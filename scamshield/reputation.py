"""Stage 3 of URL intelligence: reputation.

Sources, each optional and independent:

  Local blocklist        data/blocklist.txt: domains confirmed as scams (for example from
                         human-reviewed reports). Offline, always on.
  Google Safe Browsing   GOOGLE_SAFE_BROWSING_KEY   (free, non-commercial use)
  Google Web Risk        GOOGLE_WEB_RISK_KEY        (Google's commercial equivalent)
  URLhaus (abuse.ch)     URLHAUS_AUTH_KEY           (malware distribution links)
  PhishTank              PHISHTANK_APP_KEY          (reported phishing sites; PhishTank has not
                                                    been accepting new registrations, so a key
                                                    may not be obtainable)
  Domain age (RDAP)      no key: public registration data via rdap.org. A website
                         registered days ago is a strong warning sign.

Online sources run only when the user allows online services, receive only the
link (never the message), and are cached with expiry. Any failure means
"not checked", never "safe".

The most important rule: NOT being listed is not evidence of safety. Threat
databases are incomplete and lag behind new scam sites by hours or days, so
"not listed" is always reported as "not verified".

NOTE: request formats follow each service's public documentation. They're
tested with simulated responses, and should be checked against the live
services once keys are configured.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TTL = {"unsafe": 24 * 3600, "not listed": 6 * 3600, "age": 7 * 24 * 3600}
MAX_ENTRIES = 5000
TIMEOUT = 4
NEW_DOMAIN_DAYS = 30
BLOCKLIST = Path(__file__).resolve().parents[1] / "data" / "blocklist.txt"


class TTLCache:
    """Small thread-safe cache with per-entry expiry (Streamlit serves users on threads)."""

    def __init__(self, max_entries: int = MAX_ENTRIES, clock=time.monotonic):
        self._data: OrderedDict[str, tuple[object, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries
        self._clock = clock

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            value, expires = item
            if self._clock() >= expires:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value, ttl: float) -> None:
        with self._lock:
            self._data[key] = (value, self._clock() + ttl)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)   # drop the least recently used


_cache = TTLCache()


# --- sources -----------------------------------------------------------------------------------------
def _post_json(url: str, body: dict | None = None, form: dict | None = None, headers: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else urllib.parse.urlencode(form or {}).encode()
    h = {"Content-Type": "application/json" if body is not None else "application/x-www-form-urlencoded",
         "User-Agent": "jagratha-scam-checker"}
    h.update(headers or {})
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h), timeout=TIMEOUT) as r:
        return json.load(r)


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                               "User-Agent": "jagratha-scam-checker"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def _full(url: str) -> str:
    return url if url.lower().startswith(("http://", "https://")) else "http://" + url


def safe_browsing(url: str, key: str) -> str:
    body = {"client": {"clientId": "jagratha", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": _full(url)}]}}
    res = _post_json(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", body=body)
    return "unsafe" if res.get("matches") else "not listed"


def web_risk(url: str, key: str) -> str:
    q = urllib.parse.urlencode([("threatTypes", t) for t in ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")]
                               + [("uri", _full(url)), ("key", key)])
    res = _get_json(f"https://webrisk.googleapis.com/v1/uris:search?{q}")
    return "unsafe" if res.get("threat") else "not listed"


def urlhaus(url: str, key: str) -> str:
    res = _post_json("https://urlhaus-api.abuse.ch/v1/url/", form={"url": _full(url)}, headers={"Auth-Key": key})
    return "unsafe" if res.get("query_status") == "ok" else "not listed"


def phishtank(url: str, key: str) -> str:
    res = _post_json("https://checkurl.phishtank.com/checkurl/",
                     form={"url": _full(url), "format": "json", "app_key": key})
    r = res.get("results", {})
    return "unsafe" if r.get("in_database") and r.get("valid") else "not listed"


SOURCES = [  # (name, environment variable holding the key, function)
    ("Google Safe Browsing", "GOOGLE_SAFE_BROWSING_KEY", safe_browsing),
    ("Google Web Risk", "GOOGLE_WEB_RISK_KEY", web_risk),
    ("URLhaus", "URLHAUS_AUTH_KEY", urlhaus),
    ("PhishTank", "PHISHTANK_APP_KEY", phishtank),
]


def configured() -> list[str]:
    return [name for name, env, _ in SOURCES if os.getenv(env)]


def enabled() -> bool:
    """Is any key-based threat database configured? (Domain age needs no key.)"""
    return bool(configured())


_blocklist: set[str] | None = None


def blocklist() -> set[str]:
    global _blocklist
    if _blocklist is None:
        try:
            lines = BLOCKLIST.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        _blocklist = {ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")}
    return _blocklist


def domain_age_days(domain: str) -> int | None:
    """Days since the domain was registered, from public RDAP data. None if unknown."""
    cached = _cache.get("age:" + domain)
    if cached is not None:
        return cached if cached >= 0 else None
    try:
        res = _get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
        when = next(e["eventDate"] for e in res.get("events", []) if e.get("eventAction") == "registration")
        born = datetime.fromisoformat(when.replace("Z", "+00:00"))
        days = (datetime.now(timezone.utc) - born).days
    except Exception:
        _cache.set("age:" + domain, -1, 3600)   # don't retry a failing lookup for an hour
        return None
    _cache.set("age:" + domain, days, TTL["age"])
    return days


@dataclass
class Reputation:
    status: str                                  # unsafe | not listed | not checked
    listed_by: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    age_days: int | None = None
    oldest_check: float | None = None   # time.time() of the oldest (cached) answer used


def check(url: str, domain: str, online: bool, host: str = "") -> Reputation:
    # Blocklist entries can be a whole domain (scam-site.top) or one host (pay.scam-site.top).
    if domain in blocklist() or (host and host.lower() in blocklist()):
        return Reputation("unsafe", ["Jagratha blocklist"], ["Jagratha blocklist"])
    if not online:
        return Reputation("not checked")
    rep = Reputation("not checked", age_days=domain_age_days(domain))
    for name, env, fn in SOURCES:
        key = os.getenv(env)
        if not key:
            continue
        cache_key = f"{name}:{url}"
        cached = _cache.get(cache_key)
        if cached is None:
            try:
                result = fn(url, key)
            except Exception:
                continue   # a failed source is "not checked", never "safe"
            when = time.time()
            _cache.set(cache_key, (result, when), TTL[result])
        else:
            result, when = cached
        rep.oldest_check = when if rep.oldest_check is None else min(rep.oldest_check, when)
        rep.checked.append(name)
        if result == "unsafe":
            rep.listed_by.append(name)
    if rep.listed_by:
        rep.status = "unsafe"
    elif rep.checked:
        rep.status = "not listed"
    return rep


def lookup(url: str, online: bool = True) -> str:
    """Just the status, for one link."""
    from .links import host_of, registrable
    return check(url, registrable(host_of(url)), online).status


def freshness(checked_at: float | None) -> str:
    """'checked just now' / 'checked 3 hours ago (saved result)'."""
    if checked_at is None:
        return "not checked"
    minutes = (time.time() - checked_at) / 60
    if minutes < 2:
        return "checked just now"
    if minutes < 90:
        return f"checked {minutes:.0f} minutes ago (saved result)"
    return f"checked {minutes / 60:.0f} hours ago (saved result)"


def findings(url: str, host: str, online: bool):
    """Stage 3 findings for urlintel."""
    from .links import registrable
    from .urlintel import Finding

    rep = check(url, registrable(host), online, host)
    out = []
    if rep.status == "unsafe":
        when = "" if rep.listed_by == ["Jagratha blocklist"] else f" ({freshness(rep.oldest_check)})"
        out.append(Finding("reputation", "blocklisted_link", "danger", 0.97,
                           f"It's listed as dangerous (phishing or malware) by: {', '.join(rep.listed_by)}{when}."))
    elif rep.status == "not listed":
        out.append(Finding("reputation", "", "info", 0.0,
                           f"Not found in {len(rep.checked)} threat database{'s' if len(rep.checked) > 1 else ''} "
                           f"({', '.join(rep.checked)}), {freshness(rep.oldest_check)}. That does NOT mean it's safe: "
                           "new scam sites often aren't listed for hours or days."))
    elif online:
        out.append(Finding("reputation", "", "info", 0.0, "No threat database could be checked for this link."))
    else:
        out.append(Finding("reputation", "", "info", 0.0, "Not checked against threat databases (online checks are off)."))
    if rep.age_days is not None:
        if rep.age_days < 7:
            out.append(Finding("reputation", "new_domain", "danger", 0.85,
                               f"This website was registered only {rep.age_days} day{'s' if rep.age_days != 1 else ''} "
                               "ago. Scam sites are usually brand new; real banks and shops aren't."))
        elif rep.age_days < NEW_DOMAIN_DAYS:
            out.append(Finding("reputation", "new_domain", "warning", 0.7,
                               f"This website was registered {rep.age_days} days ago. Scam sites are usually new."))
        else:
            out.append(Finding("reputation", "", "info", 0.0,
                               f"The website has existed for about {max(1, rep.age_days // 30)} months. Older sites "
                               "can still be scams, but brand-new ones are a bigger warning sign."))
    return out

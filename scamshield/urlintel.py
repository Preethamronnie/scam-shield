"""URL intelligence, in four stages, used for links in messages AND in the
Link tab, so both always reach the same conclusion.

  1. Structure     how the address is built: the @ trick, IP addresses,
                   look-alike letters, redirect parameters, shorteners,
                   deep subdomains, heavy encoding, app downloads.
  2. Brand         does it imitate a known brand: brand names in other
                   domains, look-alike letters (ѕbі.co.in), typos, and the
                   real destination hidden inside a redirect.
  3. Reputation    known phishing/malware databases, domain age and a local
                   blocklist (reputation.py). Online, opt-in, stage 2 of the
                   pipeline.
  4. Destination   where the link really leads and what the page does
                   (destination.py). Only when the user asks.

An unknown link is never treated as safe: if nothing is found, the verdict is
"Not verified", because new scam sites often aren't in any database yet.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from . import links as L

# Look-alike letters from other alphabets that are used to imitate Latin ones.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ɡ": "g", "ӏ": "l", "ո": "n", "ν": "v", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t", "ӧ": "o", "ӓ": "a",
    "ı": "i", "ł": "l", "ø": "o", "ß": "b", "ä": "a", "ö": "o", "ü": "u", "é": "e", "è": "e", "ê": "e",
})
_REDIRECT_KEYS = {"url", "u", "q", "redirect", "redirect_uri", "redirect_url", "redir", "next", "target", "dest",
                  "destination", "continue", "goto", "link", "out", "to", "r", "return", "returnurl"}
_ENCODED = re.compile(r"%[0-9a-f]{2}", re.I)


@dataclass
class Finding:
    stage: str        # structure | brand | reputation | destination
    id: str           # red-flag ID used by the risk engine (or "" for information only)
    level: str        # danger | warning | info | good
    strength: float
    text: str


@dataclass
class UrlReport:
    url: str
    host: str
    display_host: str
    domain: str
    findings: list[Finding] = field(default_factory=list)
    redirects_to: "UrlReport | None" = None
    claims_to_be: str | None = None
    official: bool = False

    @property
    def verdict(self) -> str:
        levels = {f.level for f in self.all_findings()}
        if "danger" in levels:
            return "Dangerous"
        if "warning" in levels:
            return "Suspicious"
        if self.official and not self.redirects_to:
            return "Official website"
        return "Not verified"

    def all_findings(self) -> list[Finding]:
        return self.findings + (self.redirects_to.all_findings() if self.redirects_to else [])

    def by_stage(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.all_findings():
            out.setdefault(f.stage, []).append(f)
        return out


def skeleton(host: str) -> str:
    """The host with look-alike letters replaced by the Latin letters they imitate."""
    return L.decode_host(host).lower().translate(_CONFUSABLES)


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isascii():
            if ch.isalpha():
                out.add("Latin")
        elif "\u0400" <= ch <= "\u04ff":
            out.add("Cyrillic")
        elif "\u0370" <= ch <= "\u03ff":
            out.add("Greek")
        elif ch.isalpha():
            out.add("Other")
    return out


def _nested_url(url: str) -> str | None:
    """A full link hidden in a redirect parameter: example.com/out?url=http://evil.top."""
    try:
        query = urlsplit(url if "://" in url else "http://" + url).query
    except ValueError:
        return None
    for key, value in parse_qsl(query, keep_blank_values=False):
        value = unquote(value).strip()
        if key.lower() in _REDIRECT_KEYS and re.match(r"(?i)^(https?://|www\.)[\w-]+\.[\w.-]+", value):
            return value
    return None


def structure(url: str, host: str) -> list[Finding]:
    f: list[Finding] = []
    raw = L._SCHEME.sub("", url)
    authority = L._PATH_START.split(raw, 1)[0]
    path = raw[len(authority):]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if re.match(r"(?i)^(javascript|data|file|vbscript):", url):
        f.append(Finding("structure", "odd_link", "danger", 0.95, "It isn't a web address at all but a script or file link."))
    if "@" in authority:
        f.append(Finding("structure", "url_userinfo", "danger", 0.9,
                         f"It uses the @ trick: everything before the @ is ignored, and the real site is {host}."))
    if L._IP.match(host):
        f.append(Finding("structure", "odd_link", "danger", 0.75,
                         "It uses a number address instead of a website name. Real companies never do this."))
    decoded = L.decode_host(host)
    if decoded != host or any(ord(c) > 127 for c in host):
        mixed = any(len(_scripts(lbl)) > 1 for lbl in decoded.split("."))
        f.append(Finding("structure", "homograph", "danger" if mixed else "warning", 0.9 if mixed else 0.7,
                         f"It uses look-alike letters from another alphabet ({decoded}). The address can look "
                         "identical to a real one while leading somewhere else."))
    if re.match(r"^[^/]+:\d+", authority) and not re.search(r":(80|443)$", authority):
        f.append(Finding("structure", "odd_link", "warning", 0.6, "It uses an unusual port number in the address."))
    if L.registrable(host) in L.SHORTENERS:
        f.append(Finding("structure", "short_link", "warning", 0.6, "It's a shortened link, which hides where it really goes."))
    if tld in L.RISKY_TLDS:
        f.append(Finding("structure", "odd_link", "warning", 0.6,
                         f"It ends in .{tld}, a domain ending that's cheap and often used for scams."))
    if len(host.split(".")) >= 5:
        f.append(Finding("structure", "deep_subdomains", "warning", 0.55,
                         "It has a very long website name with many parts, often used to bury a fake brand name "
                         "at the front (like sbi.co.in.something-else.com)."))
    if len(_ENCODED.findall(url)) >= 6 or len(url) > 180:
        f.append(Finding("structure", "obfuscated_url", "warning", 0.5,
                         "The address is unusually long or heavily encoded, which can hide where it goes."))
    if path.lower().split("?")[0].endswith(".apk"):
        f.append(Finding("structure", "apk_file", "danger", 0.92,
                         "It downloads an Android app (.apk) from outside the Play Store. These can read your OTPs."))
    if url.lower().startswith("http://"):
        f.append(Finding("structure", "", "info", 0.0,
                         "It isn't encrypted (http, not https). Never type passwords or card details on it."))
    return f


def brand(url: str, host: str, mentioned: set[str]) -> tuple[list[Finding], str | None, bool]:
    f: list[Finding] = []
    official = L.is_official(host)
    raw = L._SCHEME.sub("", url)
    path = raw[len(L._PATH_START.split(raw, 1)[0]):].lower()
    claimed = None
    if official:
        f.append(Finding("brand", "", "good", 0.0, f"{L.registrable(host)} is an official website."))
        return f, None, True
    lookalike = L.brand_in_host(skeleton(host))
    if lookalike:
        claimed = L._display(lookalike)
        via = " using look-alike letters" if skeleton(host) != host.lower() else ""
        f.append(Finding("brand", "fake_brand_link", "danger", 0.95 if via else 0.9,
                         f"It pretends to be {claimed}{via}, but {L.registrable(host)} is not their website."))
    elif mentioned:
        name = sorted(mentioned)[0]
        claimed = L._display(name)
        if L.registrable(host) not in L.SHORTENERS:
            f.append(Finding("brand", "brand_mismatch", "danger", 0.8,
                             f"The message says it's from {claimed}, but the link goes to a different website "
                             f"({host})."))
    if not lookalike:
        m = L._BRAND_WORD_RX.search(path)
        sensitive = L_SENSITIVE.search(host + "/" + path)
        if m:
            f.append(Finding("brand", "brand_in_path", "warning" if sensitive else "info", 0.65 if sensitive else 0.3,
                             f"It mentions {L._display(m.group(0))} in the address, but it isn't their website."))
    words = sorted({w.lower() for w in L_SENSITIVE.findall(host + "/" + path)})
    if words:
        f.append(Finding("brand", "", "info", 0.0, f"It uses words scammers like on fake pages: {', '.join(words)}."))
    return f, claimed, False


L_SENSITIVE = re.compile(r"(login|log-in|signin|verify|verification|kyc|update|secure|account|wallet|reward|refund|"
                         r"claim|prize|bonus|unblock|suspend|otp|aadhaar|bank|password)", re.I)


def analyse(url: str, mentioned_brands: set[str] | None = None, online: bool = False, _depth: int = 0) -> UrlReport:
    """Stages 1-3 for one link. (Stage 4, the destination, runs only on request.)"""
    from . import reputation

    url = url.strip().strip("<>\"'")
    host = L.host_of(url)
    rep = UrlReport(url, host, L.decode_host(host), L.registrable(host))
    rep.findings += structure(url, host)
    found, rep.claims_to_be, rep.official = brand(url, host, mentioned_brands or set())
    rep.findings += found

    nested = _nested_url(url) if _depth == 0 else None
    if nested and L.host_of(nested) != host:
        inner = analyse(nested, mentioned_brands, online, _depth + 1)
        rep.redirects_to = inner
        for f in rep.findings:
            if f.level == "good":   # the official site is only a stepping stone here
                f.level, f.text = "info", f"{L.registrable(host)} is a real website, but this link only passes through it."
        rep.findings.append(Finding("structure", "open_redirect", "warning", 0.7,
                                    f"It goes through {L.registrable(host)} but sends you on to {inner.host}. "
                                    "Scammers hide behind well-known sites' redirect links."))
    rep.findings += reputation.findings(url, host, online and not rep.official)
    return rep


def signals_from(rep: UrlReport) -> list[tuple[str, float, str, str]]:
    """(id, strength, reason, phrase) red flags for the risk engine, strongest per ID."""
    best: dict[str, tuple] = {}
    for f in rep.all_findings():
        if f.id and (f.id not in best or f.strength > best[f.id][1]):
            best[f.id] = (f.id, f.strength, f.text, rep.host)
    if not best and not rep.official:
        best["link"] = ("link", 0.25, "It contains a link. Only open links you were expecting, and remember that "
                                      "no warning signs doesn't mean a site is safe.", rep.host)
    return list(best.values())

"""Optional online domain reputation check (Google Safe Browsing).

Off by default, so the app and its evaluation are fully offline and
reproducible. Set GOOGLE_SAFE_BROWSING_KEY to turn it on. Any network problem
returns "not checked" rather than an error: reputation is extra evidence,
never a requirement.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from collections import OrderedDict

API = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


# How long an answer stays valid. A site on the blocklist stays dangerous, so
# that's kept longest; "not listed" expires sooner because new scam sites get
# listed within hours. Failures aren't cached, so the next request retries.
TTL = {"unsafe": 24 * 3600, "not listed": 6 * 3600}
MAX_ENTRIES = 5000


class TTLCache:
    """Small thread-safe cache with per-entry expiry (Streamlit serves users on threads)."""

    def __init__(self, max_entries: int = MAX_ENTRIES, clock=time.monotonic):
        self._data: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries
        self._clock = clock

    def get(self, key: str) -> str | None:
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

    def set(self, key: str, value: str, ttl: float) -> None:
        with self._lock:
            self._data[key] = (value, self._clock() + ttl)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)   # drop the least recently used


_cache = TTLCache()


def enabled() -> bool:
    return bool(os.getenv("GOOGLE_SAFE_BROWSING_KEY"))


def lookup(url: str) -> str:
    """'unsafe', 'not listed', or 'not checked'."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return "not checked"
    cached = _cache.get(url)
    if cached is not None:
        return cached
    result = _query(url, key)
    if result in TTL:
        _cache.set(url, result, TTL[result])
    return result


def _query(url: str, key: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    body = {
        "client": {"clientId": "scam-shield", "clientVersion": "1.0"},
        "threatInfo": {"threatTypes": THREATS, "platformTypes": ["ANY_PLATFORM"],
                       "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]},
    }
    req = urllib.request.Request(API.format(key=key), data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return "unsafe" if json.load(resp).get("matches") else "not listed"
    except Exception:
        return "not checked"

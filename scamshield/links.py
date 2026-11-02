"""Checking the links in a message.

Scam links usually pretend to be a well-known company ("sbi-kyc-update.xyz",
"amaz0n-refund.in"). Real messages link to the company's own domain
("sbi.co.in") or a government domain (".gov.in"). Telling these apart cuts
false alarms on genuine messages and catches look-alike sites.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Official domains of brands that scammers commonly impersonate. Any
# subdomain of these is treated as official (e.g. retail.onlinesbi.sbi).
OFFICIAL = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfc.bank.in"],
    "icici": ["icicibank.com", "icici.bank.in"],
    "axis": ["axisbank.com", "axis.bank.in"],
    "kotak": ["kotak.com", "kotak.bank.in"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "amazon": ["amazon.in", "amazon.com", "amzn.in", "amzn.to"],
    "flipkart": ["flipkart.com", "fkrt.it"],
    "indiapost": ["indiapost.gov.in"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.co.in"],
    "bluedart": ["bluedart.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "google": ["google.com", "google.co.in", "g.co", "goo.gl"],
    "youtube": ["youtube.com", "youtu.be"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "airtel": ["airtel.in"],
    "jio": ["jio.com", "jiomart.com", "jiocinema.com", "jiosaavn.com", "jiohotstar.com"],
    "irctc": ["irctc.co.in"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "olx": ["olx.in"],
    "incometax": ["incometax.gov.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "parivahan": ["parivahan.gov.in"],
    "echallan": ["parivahan.gov.in"],
    "fastag": ["npci.org.in", "ihmcl.co.in"],
    "npci": ["npci.org.in"],
    "epfo": ["epfindia.gov.in"],
    "rbi": ["rbi.org.in"],
}
# Brand names that also appear as ordinary words are only matched in domains.
ALIASES = {"state bank": "sbi", "india post": "indiapost", "income tax": "incometax",
           "amazon": "amazon", "flipkart": "flipkart", "paytm": "paytm", "phonepe": "phonepe",
           "hdfc": "hdfc", "icici": "icici", "sbi": "sbi", "netflix": "netflix",
           "instagram": "instagram", "whatsapp": "whatsapp", "fedex": "fedex", "dhl": "dhl",
           "usps": "usps", "paypal": "paypal", "irctc": "irctc", "aadhaar": "aadhaar",
           "e-challan": "echallan", "echallan": "echallan", "fastag": "fastag", "epfo": "epfo"}

GOV_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".gov.uk", ".mil")
TWO_PART_TLDS = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "bank.in",
                 "co.uk", "org.uk", "gov.uk", "com.au", "co.jp"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "tiny.cc", "ow.ly", "s.id", "t.ly"}
RISKY_TLDS = {"xyz", "top", "click", "info", "win", "fun", "site", "link", "buzz", "icu",
              "live", "online", "shop", "store", "vip", "cc", "ws", "rest", "sbs", "cfd", "lol"}

_URL = re.compile(
    r"(?:https?://|www\.)[^\s<>\"')]+"
    r"|\b(?:[a-z0-9-]+\.)+(?:com|in|net|org|co|io|me|ly|xyz|top|click|info|win|fun|site|link|buzz|icu|live|online|shop|store|vip|cc|ws|rest|sbs|cfd|lol|to|it|gl|at|id|bank|sbi)\b(?:/[^\s<>\"')]*)?",
    re.I,
)
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
_SCHEME = re.compile(r"^https?://", re.I)
_PATH_START = re.compile(r"[/?#]")
_LABEL_SPLIT = re.compile(r"[.-]")
# Compiled once: every alias / brand name in one pattern, longest first so
# "state bank" wins over "sbi"-style shorter matches.
_ALIAS_RX = re.compile(r"\b(" + "|".join(re.escape(a) for a in sorted(ALIASES, key=len, reverse=True)) + r")\b")
_BRAND_WORD_RX = re.compile(r"\b(" + "|".join(re.escape(b) for b in sorted(OFFICIAL, key=len, reverse=True)) + r")\b")


@dataclass(frozen=True)
class LinkFlag:
    id: str
    strength: float
    reason: str
    phrase: str = ""


def host_of(url: str) -> str:
    url = _SCHEME.sub("", url.strip())
    authority = _PATH_START.split(url, 1)[0]
    # "google.com@evil.top": everything before the @ is ignored by browsers.
    authority = authority.rsplit("@", 1)[-1]
    host = authority.split(":", 1)[0].lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_official(host: str) -> bool:
    if host.endswith(GOV_SUFFIXES):
        return True
    reg = registrable(host)
    return any(reg == d or host.endswith("." + d) or host == d
               for domains in OFFICIAL.values() for d in domains)


def _within_one_edit(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


def brand_in_host(host: str) -> str | None:
    """A brand the host name is pretending to be, including look-alikes (amaz0n, flipkrt)."""
    labels = _LABEL_SPLIT.split(host.translate(_CONFUSABLE))
    joined = "".join(labels)
    for brand in OFFICIAL:
        if brand in labels:
            return brand
        # "hdfcbank-kyc", "kycsbi"... but not "taxisure" for "axis"
        if len(brand) >= 3 and any(l.startswith(brand) or l.endswith(brand) for l in labels if len(l) > len(brand)):
            return brand
        if len(brand) >= 6 and brand in joined:
            return brand
        # one-letter typos of longer names: flipkrt, netfiix, instagran
        if len(brand) >= 7 and any(_within_one_edit(l, brand) for l in labels):
            return brand
    return None


def brands_in_text(text: str) -> set[str]:
    low = text.lower()
    return {ALIASES[m.group(0)] for m in _ALIAS_RX.finditer(low)}


def find_links(text: str) -> list[str]:
    # A bare "name.apk" is a file name (handled by the APK rule), not a website.
    # Sentence punctuation right after a link isn't part of it ("…example.xyz.").
    links = [u.rstrip(".,;:!?)]'\"") for u in _URL.findall(text)]
    return [u for u in links if u and not (u.lower().endswith(".apk") and "/" not in u)]


def _display(brand: str) -> str:
    return brand.upper() if len(brand) <= 4 else brand.title()


@dataclass
class UrlInfo:
    """Everything known about one link in a message."""
    url: str
    host: str
    domain: str                 # registrable domain, e.g. sbi.co.in
    assessment: str             # official | impersonation | brand_mismatch | shortened | ip_address | unusual_domain | unknown
    claims_to_be: str | None    # brand the link or message pretends to be
    reputation: str             # from reputation.lookup: unsafe | not listed | not checked
    note: str

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def analyze_urls(text: str, online: bool = False) -> list[UrlInfo]:
    """Everything about each link that can be worked out locally; with
    online=True, also its reputation (stage 2 of the pipeline)."""
    from .reputation import lookup  # optional online check, off unless configured

    infos, seen = [], set()
    mentioned = brands_in_text(text)
    for url in find_links(text):
        host = host_of(url)
        if "." not in host or host in seen:
            continue
        seen.add(host)
        domain, tld = registrable(host), host.rsplit(".", 1)[-1]
        brand = None if is_official(host) else brand_in_host(host)
        if is_official(host):
            kind, note = "official", "An official website of the company or government."
        elif brand:
            kind, note = "impersonation", f"Pretends to be {_display(brand)}, but isn't their real website."
        elif domain in SHORTENERS:
            kind, note = "shortened", "A shortened link that hides where it really goes."
        elif _IP.match(host):
            kind, note = "ip_address", "A bare number address instead of a website name."
        elif mentioned:
            brand = sorted(mentioned)[0]
            kind, note = "brand_mismatch", f"The message claims to be from {_display(brand)}, but this isn't their website."
        elif tld in RISKY_TLDS:
            kind, note = "unusual_domain", f"An unusual website ending in .{tld}."
        else:
            kind, note = "unknown", "Not a known official site; no specific warning signs."
        infos.append(UrlInfo(url, host, domain, kind, _display(brand) if brand else None,
                             lookup(url) if online and kind != "official" else "not checked", note))
    return infos


def check_links(text: str, online: bool = False) -> list[LinkFlag]:
    """Red flags derived from the URL analysis."""
    flags: dict[str, LinkFlag] = {}
    for u in analyze_urls(text, online):
        if u.reputation == "unsafe":
            flags["blocklisted_link"] = LinkFlag(
                "blocklisted_link", 0.97, phrase=u.host,
                reason=f"The link ({u.host}) is on Google Safe Browsing's list of dangerous sites.")
        if u.assessment == "impersonation":
            flags["fake_brand_link"] = LinkFlag(
                "fake_brand_link", 0.9, phrase=u.host,
                reason=f"The link ({u.host}) pretends to be {u.claims_to_be}, but it isn't their real website.")
        elif u.assessment == "brand_mismatch":
            flags["brand_mismatch"] = LinkFlag(
                "brand_mismatch", 0.8, phrase=u.host,
                reason=f"The message says it's from {u.claims_to_be}, but the link goes to a different website ({u.host}).")
        if u.assessment == "shortened":
            flags["short_link"] = LinkFlag("short_link", 0.6, phrase=u.host,
                                           reason="It uses a shortened link, which hides where it really goes.")
        elif u.assessment == "ip_address":
            flags["odd_link"] = LinkFlag("odd_link", 0.75, phrase=u.host,
                                         reason="The link is a bare number address instead of a website name. Real companies never do this.")
        elif u.host.rsplit(".", 1)[-1] in RISKY_TLDS and u.assessment != "official":
            flags.setdefault("odd_link", LinkFlag("odd_link", 0.6, phrase=u.host,
                             reason=f"The link goes to an unusual website ending in .{u.host.rsplit('.', 1)[-1]}, not an official one."))
        elif u.assessment == "unknown":
            flags.setdefault("link", LinkFlag("link", 0.25, phrase=u.host,
                                              reason="It contains a link. Only open links you were expecting."))
    return list(flags.values())


# --- checking a single link on its own ---------------------------------------------------------
SENSITIVE_WORDS = re.compile(r"(login|log-in|signin|verify|verification|kyc|update|secure|account|wallet|"
                             r"reward|refund|claim|prize|bonus|unblock|suspend|otp|pan|aadhaar|bank)", re.I)
_PORT = re.compile(r"^[^/]+:\d+")


@dataclass
class Indicator:
    level: str      # danger | warning | info | good
    text: str


@dataclass
class LinkReport:
    url: str
    info: UrlInfo
    verdict: str                     # Dangerous | Suspicious | Official website | No warning signs found
    indicators: list[Indicator]
    redirects: list | None = None    # filled in by redirects.follow() when the user asks

    def to_dict(self) -> dict:
        return {"url": self.url, "verdict": self.verdict, **self.info.to_dict(),
                "indicators": [{"level": i.level, "text": i.text} for i in self.indicators],
                "redirects": self.redirects}


def inspect_link(url: str, online: bool = False) -> LinkReport:
    """Everything that can be said about a link without opening it."""
    url = url.strip().strip("<>\"'")
    infos = analyze_urls(url, online)
    if not infos:
        raise ValueError("That doesn't look like a web address. Paste a link such as example.com/page.")
    info = infos[0]
    raw = _SCHEME.sub("", url)
    path = raw.split("/", 1)[1] if "/" in raw else ""
    tld = info.host.rsplit(".", 1)[-1]
    ind: list[Indicator] = []

    if info.reputation == "unsafe":
        ind.append(Indicator("danger", "Google Safe Browsing lists this link as dangerous (phishing or malware)."))
    if info.assessment == "official":
        ind.append(Indicator("good", f"{info.domain} is an official website."))
    if info.assessment == "impersonation":
        ind.append(Indicator("danger", f"Pretends to be {info.claims_to_be}, but {info.domain} is not their website."))
    if "xn--" in info.host:
        ind.append(Indicator("danger", "Uses special look-alike letters in the address (for example a Cyrillic 'а' "
                                       "instead of 'a'), a trick to copy real website names."))
    if "@" in raw.split("/", 1)[0]:
        ind.append(Indicator("danger", "Contains an @ before the website name. Everything before the @ is ignored; "
                                       "the real site is the part after it."))
    if info.assessment == "ip_address":
        ind.append(Indicator("danger", "Uses a number address instead of a website name. Real companies never do this."))
    if path.lower().endswith(".apk") or url.lower().endswith(".apk"):
        ind.append(Indicator("danger", "Downloads an Android app (.apk) from outside the Play Store. "
                                       "These can read your messages and OTPs."))
    if info.assessment == "shortened":
        ind.append(Indicator("warning", "A shortened link: you can't see where it really goes."))
    if tld in RISKY_TLDS and info.assessment != "official":
        ind.append(Indicator("warning", f"Ends in .{tld}, a domain ending that's cheap and often used for scams."))
    if _PORT.match(raw):
        ind.append(Indicator("warning", "Uses an unusual port number in the address."))
    if info.assessment != "official":
        words = sorted({w.lower() for w in SENSITIVE_WORDS.findall(info.host + "/" + path)})
        if words:
            ind.append(Indicator("warning", f"Uses words scammers like in fake pages: {', '.join(words)}."))
        m = _BRAND_WORD_RX.search(path.lower())
        brand = m.group(0) if m else None
        if brand and info.assessment != "impersonation":
            ind.append(Indicator("warning", f"Mentions {_display(brand)} in the address, but isn't their website."))
        if len(info.host.split(".")) >= 5:
            ind.append(Indicator("warning", "A very long website name with many parts, often used to hide the real site."))
        if info.domain.count("-") >= 2 and "xn--" not in info.domain:
            ind.append(Indicator("info", "The website name has several hyphens, common in fake sites."))
    if url.lower().startswith("http://"):
        ind.append(Indicator("info", "Not encrypted (http, not https). Never type passwords or card details on it."))
    if info.reputation == "not checked" and info.assessment != "official":
        ind.append(Indicator("info", "Not checked against an online blocklist (online checks are off)."))
    elif info.reputation == "not listed":
        ind.append(Indicator("info", "Not on Google Safe Browsing's list of dangerous sites. New scam sites often aren't listed yet."))

    levels = {i.level for i in ind}
    if "danger" in levels:
        verdict = "Dangerous"
    elif "warning" in levels:
        verdict = "Suspicious"
    elif info.assessment == "official":
        verdict = "Official website"
    else:
        verdict = "No warning signs found"
    return LinkReport(url, info, verdict, ind)

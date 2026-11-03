"""Checking the links in a message.

Scam links usually pretend to be a well-known company ("sbi-kyc-update.xyz",
"amaz0n-refund.in"). Real messages link to the company's own domain
("sbi.co.in") or a government domain (".gov.in"). Telling these apart cuts
false alarms on genuine messages and catches look-alike sites.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

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


# Disguised links: "sbi-kyc[.]example[.]xyz", "hxxps://", "sbi-verify . top", "example(dot)com".
_FAKE_DOT = re.compile(r"\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*", re.I)
_HXXP = re.compile(r"\bhxxp(s?)(\[:\]|:)//", re.I)
_SPACED_DOT = re.compile(r"\b([a-z0-9][a-z0-9-]{1,62})\s+\.\s+(" + "|".join(sorted(
    {"com", "in", "net", "org", "co", "xyz", "top", "info", "online", "site", "link", "live", "shop", "vip", "app",
     "click", "win", "fun", "buzz", "icu"}, key=len, reverse=True)) + r")\b", re.I)


def refang(text: str) -> tuple[str, bool]:
    """Undo common link disguises so the link can be checked. Returns (text, was_disguised)."""
    out = _FAKE_DOT.sub(".", text)
    out = _HXXP.sub(lambda m: f"http{m.group(1)}://", out)
    for _ in range(4):   # "sbi . co . in" needs more than one pass
        joined = _SPACED_DOT.sub(lambda m: f"{m.group(1)}.{m.group(2)}", out)
        if joined == out:
            break
        out = joined
    return out, out != text


def find_links(text: str) -> list[str]:
    text, _ = refang(text)
    # A bare "name.apk" is a file name (handled by the APK rule), not a website.
    # Sentence punctuation right after a link isn't part of it ("…example.xyz.").
    # The domain of an email address (name@gmail.com) isn't a website link.
    links = [m.group(0).rstrip(".,;:!?)]'\"") for m in _URL.finditer(text)
             if not (m.start() > 0 and text[m.start() - 1] == "@")]
    return [u for u in links if u and not (u.lower().endswith(".apk") and "/" not in u)]


_DISPLAY = {"indiapost": "India Post", "incometax": "Income Tax Department", "echallan": "e-Challan (Parivahan)",
            "phonepe": "PhonePe", "paytm": "Paytm", "whatsapp": "WhatsApp", "youtube": "YouTube", "fastag": "FASTag",
            "bluedart": "Blue Dart", "irctc": "IRCTC", "uidai": "UIDAI", "aadhaar": "Aadhaar (UIDAI)",
            "parivahan": "Parivahan", "flipkart": "Flipkart", "amazon": "Amazon", "jio": "Jio", "olx": "OLX",
            "epfo": "EPFO", "npci": "NPCI"}


def _display(brand: str) -> str:
    return _DISPLAY.get(brand) or (brand.upper() if len(brand) <= 4 else brand.title())


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
    display_host: str = ""      # look-alike letters decoded: xn--pple-43d.com -> аpple.com

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def decode_host(host: str) -> str:
    """Show the real characters of a punycode (look-alike) name: xn--pple-43d.com -> аpple.com."""
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def _assessment(r) -> tuple[str, str]:
    """A one-word summary of the URL report, for the evidence table."""
    ids = {f.id for f in r.all_findings()}
    if "blocklisted_link" in ids:
        return "known_dangerous", "Listed as dangerous by a threat database."
    if "fake_brand_link" in ids:
        return "impersonation", f"Pretends to be {r.claims_to_be}, but isn't their real website."
    if "homograph" in ids:
        return "lookalike_letters", "Uses look-alike letters from another alphabet."
    if "url_userinfo" in ids:
        return "at_trick", f"Uses the @ trick; the real site is {r.host}."
    if "open_redirect" in ids:
        return "redirect", f"Passes through {r.domain} on its way to {r.redirects_to.host}."
    if "brand_mismatch" in ids:
        return "brand_mismatch", f"The message claims to be from {r.claims_to_be}, but this isn't their website."
    if "short_link" in ids:
        return "shortened", "A shortened link that hides where it really goes."
    if _IP.match(r.host):
        return "ip_address", "A bare number address instead of a website name."
    if r.official and not r.redirects_to:
        return "official", "An official website of the company or government."
    if r.verdict in ("Dangerous", "Suspicious"):
        return "unusual_domain", "Has warning signs (see the link check)."
    return "unknown", "Not a known official site. No warning signs found, but that doesn't make it safe."


def analyze_urls(text: str, online: bool = False) -> list[UrlInfo]:
    """Every link in the text, run through the four-stage URL intelligence (stages 1-3)."""
    from . import reputation, urlintel

    infos, seen = [], set()
    mentioned = brands_in_text(text)
    for url in find_links(text):
        host = host_of(url)
        if "." not in host or host in seen:
            continue
        seen.add(host)
        r = urlintel.analyse(url, mentioned, online)
        kind, note = _assessment(r)
        status = reputation.check(url, r.domain, online and not r.official, host).status
        infos.append(UrlInfo(url, host, r.domain, kind, r.claims_to_be, status, note, r.display_host))
    return infos


def check_links(text: str, online: bool = False) -> list[LinkFlag]:
    """Red flags from the URL intelligence for every link in the text, strongest of each kind."""
    from . import urlintel

    flags: dict[str, LinkFlag] = {}
    if refang(text)[1] and find_links(text):
        flags["disguised_link"] = LinkFlag(
            "disguised_link", 0.75, phrase="disguised link",
            reason="A link is written in a disguised way (like [.] or hxxp) so filters and scanners miss it. "
                   "Genuine companies don't hide their links.")
    mentioned = brands_in_text(text)
    seen = set()
    for url in find_links(text):
        host = host_of(url)
        if "." not in host or host in seen:
            continue
        seen.add(host)
        for sid, strength, reason, phrase in urlintel.signals_from(urlintel.analyse(url, mentioned, online)):
            if sid not in flags or strength > flags[sid].strength:
                flags[sid] = LinkFlag(sid, strength, reason, phrase)
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
    verdict: str                     # Dangerous | Suspicious | Official website | Not verified
    indicators: list[Indicator]
    redirects: list | None = None    # filled in by redirects.follow() when the user asks
    stages: dict = field(default_factory=dict)   # findings grouped by stage
    passes_to: str | None = None                 # the real destination hidden in a redirect link

    def to_dict(self) -> dict:
        return {"url": self.url, "verdict": self.verdict, **self.info.to_dict(),
                "indicators": [{"level": i.level, "text": i.text} for i in self.indicators],
                "redirects": self.redirects}


def inspect_link(url: str, online: bool = False) -> LinkReport:
    """Everything that can be said about one link without opening it (stages 1-3)."""
    from . import urlintel

    url = url.strip().strip("<>\"'")
    infos = analyze_urls(url, online)
    if not infos:
        raise ValueError("That doesn't look like a web address. Paste a link such as example.com/page.")
    r = urlintel.analyse(url, set(), online)
    order = {"danger": 0, "warning": 1, "good": 2, "info": 3}
    seen, indicators = set(), []
    for f in sorted(r.all_findings(), key=lambda f: order[f.level]):
        if f.text not in seen:
            seen.add(f.text)
            indicators.append(Indicator(f.level, f.text))
    return LinkReport(url, infos[0], r.verdict, indicators, stages={k: [x.text for x in v] for k, v in r.by_stage().items()},
                      passes_to=r.redirects_to.display_host if r.redirects_to else None)

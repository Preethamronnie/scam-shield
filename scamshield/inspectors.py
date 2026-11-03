"""File classification and static inspection.

Scams don't only arrive as text: a fake bank statement or "arrest warrant" as
a PDF, a "banking app" as an APK, a "refund" QR code, an email with a nasty
attachment. This module works out what a file really is from its bytes (never
its name), then inspects it *statically*: files are parsed as data, never
opened, executed, installed or rendered.

Everything here returns plain data (dicts and strings) and imports nothing
heavy, so PDF, APK and email inspection can run inside sandbox.run_isolated.
Findings are returned as "signals" (dicts with id, strength, reason, phrase)
that the analyzer turns into normal red flags, so files go through the same
risk categories and verdict rules as messages.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape
from urllib.parse import parse_qs, unquote, urlsplit

MAX_TEXT = 20_000


class InspectError(ValueError):
    """A problem with the file that's safe (and useful) to show the user."""

KINDS = {
    "image": "Image",
    "pdf": "PDF document",
    "apk": "Android app (APK)",
    "email": "Email file (.eml)",
    "zip": "ZIP archive",
    "audio": "Audio recording",
    "video": "Video",
    "unknown": "Unknown file type",
}
# What each kind may weigh at most (bytes). Everything else is refused.
SIZE_LIMITS = {"image": 8, "pdf": 10, "apk": 25, "email": 10}


def _sig(sid: str, strength: float, reason: str, phrase: str = "") -> dict:
    return {"id": sid, "strength": strength, "reason": reason, "phrase": phrase}


# --- 1. what is this file, really? ----------------------------------------------------------------
_EMAIL_HEADER = re.compile(rb"^(from|to|subject|date|received|return-path|message-id|mime-version|delivered-to):",
                           re.I | re.M)


def classify(data: bytes) -> str:
    head = data[:16]
    if head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff") or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.startswith(b"%PDF-") or b"%PDF-" in data[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = set(z.namelist())
            return "apk" if "AndroidManifest.xml" in names else "zip"
        except zipfile.BadZipFile:
            return "unknown"
    if head[:3] == b"ID3" or head[:4] in (b"OggS", b"fLaC") or (head[:4] == b"RIFF" and head[8:12] == b"WAVE") \
            or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2") or head[:4] == b"#!AM":
        return "audio"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        return "audio" if brand in (b"M4A ", b"M4B ") else "video"
    if head[:4] == b"\x1aE\xdf\xa3":
        return "video"
    if len(_EMAIL_HEADER.findall(data[:8192])) >= 3:
        return "email"
    return "unknown"


# --- 2. QR codes inside images -------------------------------------------------------------------------
_RECEIVE_WORDS = re.compile(r"\b(receive|refund|cashback|prize|won|win|reward|claim|get money|credited to you|accept)\b", re.I)


def parse_upi(uri: str) -> dict | None:
    """upi://pay?pa=name@bank&pn=Payee&am=100 -> its parts."""
    if not uri.lower().startswith("upi://"):
        return None
    parts = urlsplit(uri)
    q = {k: unquote(v[0]) for k, v in parse_qs(parts.query).items()}
    return {"action": parts.netloc.lower() or "pay", "payee_id": q.get("pa", ""), "payee_name": q.get("pn", ""),
            "amount": q.get("am", ""), "note": q.get("tn", "")}


def read_qr_codes(img) -> list[str]:
    """Decode QR codes and barcodes from an already-validated PIL image."""
    try:
        import zxingcpp
    except ImportError:
        return []
    try:
        return [r.text for r in zxingcpp.read_barcodes(img) if r.text][:5]
    except Exception:
        return []


def qr_findings(codes: list[str], context_text: str = "") -> tuple[list[str], list[dict], str]:
    """(facts to show, signals, text to analyse) for the QR codes in an image."""
    facts, signals, text = [], [], []
    for code in codes:
        upi = parse_upi(code)
        if upi:
            who = upi["payee_name"] or upi["payee_id"] or "someone"
            amount = f" Rs {upi['amount']}" if upi["amount"] else ""
            facts.append(f"QR code: a UPI payment request. Scanning it SENDS{amount} to {who}"
                         + (f" ({upi['payee_id']})" if upi["payee_id"] and upi["payee_name"] else "")
                         + ". A QR code can never send money to you.")
            text.append(f"UPI payment QR code to {upi['payee_id']} {upi['payee_name']} {upi['note']}".strip())
            if _RECEIVE_WORDS.search(context_text + " " + upi["note"]):
                signals.append(_sig("qr_receive_trick", 0.95,
                                    "It says you'll receive money by scanning a QR code, but this QR code is a request "
                                    "to PAY. Scanning it and entering your PIN takes money from your account.",
                                    f"QR code pays {upi['payee_id']}"))
            else:
                signals.append(_sig("qr_payment_request", 0.45,
                                    "It contains a UPI payment QR code. Only scan it if you mean to pay this person.",
                                    f"QR code pays {upi['payee_id']}"))
        elif re.match(r"(?i)^(https?://|www\.)", code):
            facts.append(f"QR code: opens the link {code}")
            text.append(code)
        else:
            facts.append(f"QR code: contains the text \"{code[:120]}\"")
            text.append(code[:500])
    return facts, signals, "\n".join(text)


_PAYMENT_PROOF = re.compile(
    r"\b(payment (was )?successful|paid successfully|transaction successful|money sent|transferred successfully|"
    r"payment completed|amount (credited|debited)|upi transaction id|utr( no| number)?)\b", re.I)


def payment_screenshot_findings(ocr_text: str) -> tuple[list[str], list[dict]]:
    """A photo that looks like a payment receipt. It can't be proven fake from
    the pixels, but the key fact is that a screenshot is never proof."""
    if not _PAYMENT_PROOF.search(ocr_text):
        return [], []
    return (["This looks like a payment confirmation screenshot. These are easy to fake in seconds; only your "
             "own bank or UPI app can confirm that money really arrived."],
            [_sig("payment_screenshot", 0.45,
                  "It's a screenshot of a payment. Scammers send fake 'payment successful' screenshots, then ask you "
                  "to refund the 'extra'. Check your own bank app, not the picture.")])


# --- 3. PDFs ---------------------------------------------------------------------------------------------
MAX_PDF_PAGES = 50


def inspect_pdf(data: bytes) -> dict:
    """Read text and links from a PDF and look for active content. Nothing in
    the PDF is executed: JavaScript and actions are only detected, never run."""
    from pypdf import PdfReader

    facts, signals = [], []
    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            pass
        if reader.is_encrypted:
            return {"kind": "pdf", "text": "", "signals": [],
                    "facts": ["This PDF is password-protected, so its contents couldn't be read. Be careful with "
                              "password-protected files from strangers: it's a trick to get past scanners."]}
    n_pages = len(reader.pages)
    facts.append(f"PDF with {n_pages} page{'s' if n_pages != 1 else ''}"
                 + (f"; only the first {MAX_PDF_PAGES} were read" if n_pages > MAX_PDF_PAGES else "") + ".")

    texts, links = [], []
    for page in reader.pages[:MAX_PDF_PAGES]:
        try:
            texts.append(page.extract_text() or "")
        except Exception:
            pass
        for annot in (page.get("/Annots") or []):
            try:
                a = annot.get_object().get("/A")
                if a is not None and a.get_object().get("/URI"):
                    links.append(str(a.get_object()["/URI"]))
            except Exception:
                continue
        if sum(len(t) for t in texts) > MAX_TEXT:
            break
    text = "\n".join(texts).strip()[:MAX_TEXT]

    # Active content: detected by looking at the raw objects, never run.
    raw = data
    if re.search(rb"/(JavaScript|JS)\b", raw):
        signals.append(_sig("pdf_javascript", 0.9, "The PDF contains hidden code (JavaScript) that runs when it's "
                            "opened. Real bank statements, bills and notices don't need code.", "PDF code"))
    if re.search(rb"/Launch\b", raw):
        signals.append(_sig("pdf_launch", 0.95, "The PDF tries to start another program or file when it's opened, "
                            "a known trick for installing malware.", "PDF launch action"))
    if re.search(rb"/EmbeddedFile\b", raw):
        signals.append(_sig("pdf_embedded_file", 0.6, "The PDF has another file hidden inside it. Don't open "
                            "files inside documents from strangers.", "File inside PDF"))
    if re.search(rb"/OpenAction\b", raw) and (links or re.search(rb"/URI\b", raw)):
        signals.append(_sig("pdf_auto_link", 0.7, "The PDF tries to open a website automatically.", "PDF auto-link"))

    if links:
        facts.append("Links inside the PDF: " + ", ".join(dict.fromkeys(links[:5])))
    if not text:
        facts.append("No text inside: it's probably a scanned image. Take a screenshot of the page and add that "
                     "instead, so the text can be read.")
    meta = reader.metadata or {}
    made_with = str(meta.get("/Producer") or meta.get("/Creator") or "").strip()
    if made_with:
        facts.append(f"Made with: {made_with[:80]}")
    return {"kind": "pdf", "text": (text + "\n" + "\n".join(links)).strip(), "signals": signals, "facts": facts}


# --- 4. APKs -----------------------------------------------------------------------------------------------
MAX_MANIFEST = 2 * 1024 * 1024
MAX_UNCOMPRESSED = 200 * 1024 * 1024

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("apk_reads_sms", 0.95, "read your SMS messages, including OTPs"),
    "android.permission.RECEIVE_SMS": ("apk_reads_sms", 0.95, "read SMS messages as they arrive, including OTPs"),
    "android.permission.SEND_SMS": ("apk_sends_sms", 0.8, "send SMS from your number"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("apk_accessibility", 0.9,
                                                      "see your screen and tap buttons for you (accessibility control)"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": ("apk_notifications", 0.85,
                                                              "read all your notifications, including OTPs"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("apk_overlay", 0.7,
                                               "draw fake screens over other apps, like your banking app"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("apk_installs_apps", 0.6, "install other apps"),
    "android.permission.READ_CALL_LOG": ("apk_calls", 0.6, "read your call history"),
    "android.permission.CALL_PHONE": ("apk_calls", 0.6, "make phone calls"),
    "android.permission.READ_CONTACTS": ("apk_contacts", 0.5, "read your contacts"),
    "android.permission.READ_PHONE_STATE": ("apk_phone_state", 0.4, "read your phone number and SIM details"),
}


def _axml_strings(manifest: bytes) -> list[str]:
    """Strings from an Android binary XML file (its string pool), without
    parsing anything else. Falls back to scanning for UTF-16 text."""
    try:
        if struct.unpack_from("<H", manifest, 0)[0] != 0x0003:
            raise ValueError("not binary XML")
        pos = struct.unpack_from("<H", manifest, 2)[0]
        ctype, hsize, csize, count, _styles, flags, start, _ = struct.unpack_from("<HHIIIIII", manifest, pos)
        if ctype != 0x0001 or count > 50_000:
            raise ValueError("no string pool")
        utf8 = bool(flags & 0x100)
        offsets = struct.unpack_from(f"<{count}I", manifest, pos + hsize)
        base = pos + start
        out = []
        for off in offsets:
            p = base + off
            if utf8:
                n = manifest[p]
                p += 2 if n & 0x80 else 1          # UTF-16 length (skipped)
                n = manifest[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | manifest[p + 1]
                    p += 1
                p += 1
                out.append(manifest[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", manifest, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", manifest, p)[0]
                    p += 2
                out.append(manifest[p:p + 2 * n].decode("utf-16-le", "replace"))
        return out
    except Exception:
        found = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", manifest)
        return [f.decode("utf-16-le", "replace") for f in found]


def inspect_apk(data: bytes) -> dict:
    """Look inside an Android app without installing or running it: which
    sensitive permissions it asks for. (An APK is a ZIP file; only its manifest
    is read, with limits that stop 'zip bombs'.)"""
    facts, signals = [], []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_UNCOMPRESSED:
            raise InspectError("This app file expands to an enormous size when unpacked (a 'zip bomb'), which "
                               "real apps never do. Don't install it.")
        info = z.getinfo("AndroidManifest.xml")
        if info.file_size > MAX_MANIFEST:
            raise InspectError("This app file is built in an unusual way (its settings file is far too large), "
                               "which is itself a warning sign. Don't install it.")
        manifest = z.read(info)
        has_code = any(n.endswith(".dex") for n in z.namelist())
    strings = _axml_strings(manifest)
    perms = sorted({s for s in strings if s.startswith("android.permission.")})
    package = next((s for s in strings if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-zA-Z0-9_]+){1,6}", s)
                    and not s.startswith(("android.", "androidx.", "com.google.android.", "http"))), "")

    signals.append(_sig("apk_file", 0.92, "This is an Android app file (APK) sent outside the Play Store. Apps "
                        "from messages and links are the most common way OTPs and bank accounts get stolen. "
                        "Don't install it.", "Android app file"))
    can_do = []
    for p in perms:
        if p in DANGEROUS_PERMISSIONS:
            sid, strength, what = DANGEROUS_PERMISSIONS[p]
            if not any(s["id"] == sid for s in signals):      # one line per kind of access
                can_do.append(what)
                signals.append(_sig(sid, strength, f"If installed, this app asks to {what}.", p.rsplit(".", 1)[-1]))
    facts.append("Android app (APK)" + (f", package name {package}" if package else "") + ". It was NOT installed "
                 "or run; only its permission list was read.")
    if can_do:
        facts.append("If installed, it could: " + "; ".join(dict.fromkeys(can_do)) + ".")
    elif perms:
        facts.append(f"It asks for {len(perms)} permissions, none of the most dangerous ones. That still doesn't "
                     "make an app from a message safe.")
    if not has_code:
        facts.append("It contains no app code, which is unusual for a real app.")
    # The package name stays out of the analysed text: "com.sbi.rewards" looks like
    # a web address to the link checker. It's shown in the facts instead.
    text = "Android app file (APK)"
    return {"kind": "apk", "text": text, "signals": signals, "facts": facts}


# --- 5. Emails ---------------------------------------------------------------------------------------------
RISKY_ATTACHMENTS = (".apk", ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".wsf", ".msi", ".jar",
                     ".html", ".htm", ".shtml", ".hta", ".iso", ".img", ".lnk", ".zip", ".rar", ".7z")
_FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "rediffmail.com",
              "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com", "yandex.com", "live.com"}
_TAGS = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.I | re.S)


def _html_to_text(html: str) -> str:
    text = re.sub(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>", r" \1 ", html, flags=re.I)  # keep link targets
    return re.sub(r"\s+", " ", unescape(_TAGS.sub(" ", text))).strip()


def inspect_email(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data[:10 * 1024 * 1024])
    facts, signals = [], []
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    subject = str(msg.get("Subject", ""))
    facts.append(f"From: {from_name + ' ' if from_name else ''}<{from_addr or 'unknown'}>")
    if subject:
        facts.append(f"Subject: {subject[:150]}")

    brandish = re.search(r"\b(bank|sbi|hdfc|icici|axis|kotak|paytm|amazon|flipkart|income tax|police|customs|"
                         r"rbi|uidai|aadhaar|fedex|dhl|india post|netflix|microsoft|support|security|kyc)\b",
                         from_name, re.I)
    if brandish and from_domain in _FREE_MAIL:
        signals.append(_sig("email_sender_spoof", 0.85, f"The sender calls themselves \"{from_name}\" but writes from "
                            f"a free {from_domain} address. Banks and government offices use their own email domains.",
                            f"{from_name} <{from_addr}>"))
    if reply_addr and from_domain and reply_addr.rsplit("@", 1)[-1].lower() != from_domain:
        signals.append(_sig("email_reply_elsewhere", 0.6, f"Replies would go to a different address ({reply_addr}) "
                            "than the one the email came from.", f"Reply-To: {reply_addr}"))
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    if re.search(r"\b(spf|dkim|dmarc)=(fail|softfail)\b", auth, re.I):
        signals.append(_sig("email_auth_fail", 0.7, "The email failed the checks that confirm who really sent it "
                            "(SPF / DKIM / DMARC). It may be forged.", "failed sender checks"))

    bodies, attachments = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        ctype = part.get_content_type()
        if name or part.get_content_disposition() == "attachment":
            attachments.append(name or ctype)
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                continue
            bodies.append(_html_to_text(content) if ctype == "text/html" else content)
    for name in attachments:
        low = name.lower()
        double = re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)\.[a-z0-9]{2,4}$", low)
        if low.endswith(RISKY_ATTACHMENTS) or double:
            signals.append(_sig("email_risky_attachment", 0.9 if low.endswith((".apk", ".exe", ".scr", ".js", ".vbs",
                                                                            ".hta", ".lnk", ".msi", ".bat", ".cmd"))
                                or double else 0.7,
                                f"It has an attachment ({name}) that can run code or open a fake login page."
                                + (" The double extension hides what it really is." if double else ""), name))
    if attachments:
        facts.append("Attachments (not opened): " + ", ".join(attachments[:10]))
    text = "\n".join([subject] + bodies).strip()[:MAX_TEXT]
    return {"kind": "email", "text": text, "signals": signals, "facts": facts}


# --- 6. Audio and video ---------------------------------------------------------------------------------------
MEDIA_FACTS = {
    "audio": ["Audio recordings can't be checked here yet. Voices can now be copied with AI from a few seconds "
              "of someone's real voice, so a recording that sounds like a family member isn't proof it's them.",
              "Call the person back on the number you already have, or ask a question only they would know. "
              "You can also type what the recording said into the message box to check it."],
    "video": ["Videos can't be checked here yet. Faces and voices in videos can be faked with AI.",
              "If a video call or recording asks for money, codes or secrecy, treat it as a scam until you've "
              "checked with the person or organisation on a number you found yourself."],
}


# --- 7. Web pages (destination analysis) --------------------------------------------------------------------
from html.parser import HTMLParser  # noqa: E402

_SENSITIVE_FIELDS = [   # (what to call it, pattern in a field's name / id / placeholder / label)
    ("OTP", r"\botp\b|one.?time|verification.?code|\bsms.?code"),
    ("card number", r"card.?(no|num)|\bccnum|cardnumber|\bpan\b(?!.?card)|debit|credit"),
    ("CVV", r"\bcvv|\bcvc|security.?code"),
    ("card expiry", r"expir|\bexp.?(month|year|date)|\bmm.?yy"),
    ("UPI PIN or MPIN", r"upi.?pin|\bmpin|m.?pin|atm.?pin|\bpin\b"),
    ("Aadhaar number", r"aadha?ar|\buid\b"),
    ("PAN number", r"\bpan.?(no|number|card)"),
    ("net banking password", r"net.?banking|internet.?banking|ib.?pass"),
]
_JS_REDIRECT = re.compile(r"(window\.|document\.|top\.)?location(\.href)?\s*=\s*['\"]([^'\"]+)|location\.(replace|assign)\(\s*['\"]([^'\"]+)", re.I)
_OBFUSCATED = re.compile(r"\beval\s*\(|\batob\s*\(|\bunescape\s*\(|String\.fromCharCode\s*\((\s*\d+\s*,){20,}|[A-Za-z0-9+/]{400,}={0,2}")


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in = "", None
        self.forms, self.inputs, self.scripts, self.script_srcs = [], [], [], []
        self.iframes, self.links, self.meta_refresh, self.text = [], [], "", []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in = "title"
        elif tag == "script":
            self._in = "script"
            if a.get("src"):
                self.script_srcs.append(a["src"])
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag in ("input", "select", "textarea"):
            self.inputs.append(" ".join(a.get(k, "") for k in ("type", "name", "id", "placeholder", "aria-label",
                                                                 "autocomplete")).lower())
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_endtag(self, tag):
        if tag in ("title", "script"):
            self._in = None

    def handle_data(self, data):
        if self._in == "title":
            self.title += data
        elif self._in == "script":
            self.scripts.append(data)
        elif len(" ".join(self.text)) < 4000:
            self.text.append(data.strip())


def inspect_html(data: bytes, page_url: str = "") -> dict:
    """Static analysis of a web page's HTML: it's parsed as data, never rendered,
    and none of its scripts are run. Looks for what phishing pages do."""
    from .links import OFFICIAL, _display, host_of, is_official, registrable

    html = data[:1024 * 1024].decode("utf-8", "replace")
    p = _PageParser()
    try:
        p.feed(html)
    except Exception:
        pass
    host = host_of(page_url) if page_url else ""
    official = bool(host) and is_official(host)
    title = " ".join(p.title.split())[:150]
    body_text = " ".join(t for t in p.text if t)[:4000]
    facts = [f"Page title: \"{title}\"" if title else "The page has no title."]
    findings = []

    def add(fid, level, strength, text):
        findings.append({"id": fid, "level": level, "strength": strength, "text": text})

    has_password = any("password" in i.split()[:1] or "type=password" in i or i.startswith("password") for i in p.inputs)
    asked = [name for name, rx in _SENSITIVE_FIELDS if any(re.search(rx, i) for i in p.inputs)]
    claimed = None
    # A page *presents itself* as a brand through its title; merely mentioning one
    # ("SBI interest rates went up") doesn't count.
    head = title.lower()
    for brand in OFFICIAL:
        if len(brand) >= 3 and re.search(rf"\b{re.escape(brand)}\b", head):
            claimed = brand
            break
    if claimed and not official:
        brand_name = _display(claimed)
        on_login = has_password or asked
        add("dest_brand_mismatch", "danger" if on_login else "warning", 0.92 if on_login else 0.6,
            f"The page presents itself as {brand_name}, but the website is {registrable(host) or 'not theirs'}"
            + (", and it asks you to log in or enter details. This is what a fake login page looks like."
               if on_login else "."))
    if asked and not official:
        add("dest_sensitive_fields", "danger", 0.9,
            f"The page asks for your {', '.join(asked)}. Never enter these on a page you reached from a message.")
    elif has_password and not official:
        # Many genuine sites ask for a password, so on its own this is a note, not a warning.
        add("dest_login_form", "info", 0.3, "The page asks for a password. Only log in on sites you opened yourself, "
                                           "never from a link in a message.")
    for action in p.forms:
        ah = host_of(action) if action.lower().startswith(("http://", "https://", "//")) else ""
        if ah and host and registrable(ah) != registrable(host):
            add("dest_form_elsewhere", "warning", 0.7,
                f"Its form sends what you type to a different website ({registrable(ah)}).")
            break
    targets = []
    if p.meta_refresh and "url=" in p.meta_refresh.lower():
        targets.append(p.meta_refresh.split("=", 1)[-1].strip(" '\""))
    for script in p.scripts:
        for m in _JS_REDIRECT.finditer(script):
            targets.append(m.group(3) or m.group(5))
    if targets:
        add("dest_auto_redirect", "warning", 0.6,
            f"The page sends you on automatically (to {targets[0][:80]}), which hides where you end up.")
    if any(_OBFUSCATED.search(s) for s in p.scripts):
        add("dest_obfuscated_code", "warning", 0.6,
            "The page contains scrambled (obfuscated) code, a common way to hide what a phishing page does.")
    apks = [h for h in p.links if h.lower().split("?")[0].endswith(".apk")]
    if apks:
        add("dest_apk_download", "danger", 0.92, "The page offers an Android app (.apk) to download outside the "
                                                 "Play Store. Don't install it.")
    if official and not findings:
        facts.append("This is an official website.")
    facts.append(f"{len(p.forms)} form(s), {len(p.inputs)} input field(s), {len(p.script_srcs) + len(p.scripts)} "
                 f"script(s). Nothing on the page was run.")
    return {"kind": "html", "text": (title + "\n" + body_text)[:MAX_TEXT], "signals": findings, "facts": facts}

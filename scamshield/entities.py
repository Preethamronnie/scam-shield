"""Extracting the concrete details scams depend on: phone numbers, payment
IDs, emails and the organisation the message claims to come from."""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- phone numbers ----------------------------------------------------------------
_PHONE = re.compile(r"(?<![\w/])(\+?\d[\d\s-]{7,15}\d|9X{6,}\d*|\d{2,5}X{3,}[\dX ]*\d)(?![\w/])", re.I)
_NON_DIGIT = re.compile(r"\D")
_SHORT_CODE = re.compile(r"\d{4,6}")          # OTPs and amounts, not phone numbers
_DATE = re.compile(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}")


@dataclass(frozen=True)
class Phone:
    number: str
    kind: str
    note: str

    def to_dict(self) -> dict:
        return {"number": self.number, "type": self.kind, "note": self.note}


def _classify(raw: str) -> tuple[str, str] | None:
    digits = _NON_DIGIT.sub("", raw)
    masked = "x" in raw.lower()
    if masked:
        return "mobile (partly hidden)", "A personal phone number, not an official helpline."
    if len(digits) < 8:
        return None
    if digits.startswith(("1800", "1860")):
        return "toll-free (India)", "Toll-free numbers can be faked too; check it on the official website."
    if digits.startswith("91") and len(digits) == 12 and digits[2] in "6789":
        return "mobile (India)", "A personal mobile number. Real banks and agencies don't contact you from these."
    if len(digits) == 10 and digits[0] in "6789":
        return "mobile (India)", "A personal mobile number. Real banks and agencies don't contact you from these."
    if digits.startswith(("09", "0871", "0870", "0844")) and len(digits) == 11:
        return "premium-rate (UK)", "Calling this number can cost a lot per minute."
    if raw.strip().startswith("+") and not digits.startswith("91"):
        return "international", "A foreign number. Be careful if it claims to be a local bank, agency or relative."
    if 8 <= len(digits) <= 13:
        return "other", ""
    return None


def find_phones(text: str) -> list[Phone]:
    out, seen = [], set()
    for m in _PHONE.finditer(text):
        raw = m.group(0).strip()
        # Skip things that are clearly amounts, dates or OTPs.
        if _SHORT_CODE.fullmatch(raw) or _DATE.search(raw):
            continue
        key = _NON_DIGIT.sub("", raw) or raw.lower()
        if key in seen:
            continue
        cls = _classify(raw)
        if cls:
            seen.add(key)
            out.append(Phone(raw, *cls))
    return out


# --- payment IDs and emails -----------------------------------------------------------
_UPI_HANDLES = ("ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "ptyes", "ptaxis",
                "pthdfc", "ptsbi", "upi", "apl", "yapl", "sbi", "icici", "hdfcbank", "axisbank", "kotak",
                "freecharge", "airtel", "jio", "waicici", "wasbi", "fam", "slc", "superyes")
_UPI = re.compile(r"\b[\w.-]{2,}@(" + "|".join(_UPI_HANDLES) + r")(?![\w-]|\.\w)", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def find_payment_ids(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(0) for m in _UPI.finditer(text)))


def find_emails(text: str) -> list[str]:
    return list(dict.fromkeys(e for e in _EMAIL.findall(text) if not _UPI.fullmatch(e)))


# --- organisations ----------------------------------------------------------------------
ORGANISATIONS = {
    "State Bank of India (SBI)": r"\bsbi\b|state bank|\byono\b",
    "HDFC Bank": r"\bhdfc\b",
    "ICICI Bank": r"\bicici\b",
    "Axis Bank": r"\baxis bank\b",
    "Kotak Mahindra Bank": r"\bkotak\b",
    "Punjab National Bank": r"\bpnb\b|punjab national",
    "Reserve Bank of India": r"\brbi\b|reserve bank",
    "Police / Cyber Crime": r"\bpolice\b|cyber ?crime|crime branch|\binspector\b",
    "CBI": r"\bcbi\b",
    "Enforcement Directorate": r"\benforcement directorate\b|\bed (officer|notice)\b",
    "Customs": r"\bcustoms\b",
    "Narcotics Control Bureau": r"\bnarcotics\b|\bncb\b",
    "TRAI / Telecom department": r"\btrai\b|\bdot\b|telecom department",
    "Income Tax Department": r"income ?tax|\bitr\b",
    "UIDAI (Aadhaar)": r"\buidai\b|\baadhaar\b",
    "EPFO": r"\bepfo\b|provident fund",
    "Transport / RTO (e-challan)": r"\brto\b|e-?challan|parivahan|traffic police",
    "Electricity board": r"electricity (board|department|office)|power (department|board)|\bbescom\b|\bmseb\b|\btneb\b",
    "Amazon": r"\bamazon\b",
    "Flipkart": r"\bflipkart\b",
    "India Post": r"india ?post|speed post",
    "FedEx": r"\bfedex\b",
    "DHL": r"\bdhl\b",
    "Blue Dart": r"blue ?dart",
    "Microsoft": r"\bmicrosoft\b",
    "Netflix": r"\bnetflix\b",
    "Instagram": r"\binstagram\b",
    "WhatsApp": r"\bwhatsapp\b",
    "Airtel": r"\bairtel\b",
    "Jio": r"\bjio\b",
    "Paytm": r"\bpaytm\b",
    "PhonePe": r"\bphonepe\b",
    "Google Pay": r"google ?pay|\bgpay\b",
    "Armed forces": r"\b(army|military|crpf|bsf|cisf|navy|air force)\b",
    "Government scheme": r"\bpm kisan\b|\byojana\b|government scheme",
}
_ORG_RX = {name: re.compile(p, re.I) for name, p in ORGANISATIONS.items()}


def find_organisations(text: str) -> list[str]:
    return [name for name, rx in _ORG_RX.items() if rx.search(text)]

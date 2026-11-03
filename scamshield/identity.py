"""Identity intelligence: does who the message claims to be match how it asks
you to get in touch or pay?

Banks, companies and government offices contact you through official
channels. When a message *claims to be* one of them but gives a personal
mobile number, a Gmail address or a personal UPI ID, or uses the brand's name
inside a payment ID or email address, that mismatch is strong evidence of
impersonation.

The check only applies when the message presents itself as coming from the
organisation ("SBI Customer Care:", "This is HDFC Bank", "Dear customer"), not
when someone merely mentions it ("my SBI card isn't working, call me").
"""
from __future__ import annotations

import re

from . import entities

_FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "rediffmail.com",
              "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com", "yandex.com", "live.com"}
# Words that turn a brand name inside an ID into a fake "department".
_BRAND_IDS = re.compile(r"\b(sbi|hdfc|icici|axis|kotak|pnb|rbi|paytm|phonepe|gpay|amazon|flipkart|uidai|aadhaar|"
                        r"incometax|itr|epfo|trai|customs|police|cbi|fedex|dhl|indiapost|bluedart|airtel|jio|"
                        r"netflix|microsoft|irctc)", re.I)
_DEPT_WORDS = re.compile(r"(kyc|support|help|care|refund|reward|verify|update|desk|official|service|claim|"
                         r"security|alert|team|dept|office|cashback|bonus)", re.I)
_CLAIM_CUES = re.compile(
    r"\b(dear (customer|user|sir|madam|valued customer|account holder|card ?holder|consumer)|"
    r"this is|we are|i am calling from|calling from|on behalf of|from the|official|our (bank|team|helpdesk)|"
    r"customer (care|support|service)|helpdesk|help desk|support team|department|officer|executive)\b", re.I)


def claims_to_be(text: str, orgs: list[str]) -> str | None:
    """The organisation the message presents itself as, if any."""
    if not orgs:
        return None
    for org in orgs:
        rx = entities._ORG_RX[org]
        m = rx.search(text)
        if not m:
            continue
        # "SBI: ..." or "HDFC Bank - ..." at the very start reads as a sender name;
        # "My SBI card isn't working" doesn't.
        starts = re.match(r"^\W{0,3}(" + rx.pattern + r")", text.strip(), re.I)
        near = text[max(0, m.start() - 40): m.end() + 40]
        before = text[max(0, m.start() - 25):m.start()]
        # "My SBI card", "I called HDFC customer care": talking about the organisation, not posing as it.
        possessive = re.search(r"\b(my|mine|your|his|her|their|called|calling|spoke to|talked to|contacted|"
                               r"visited|went to|complained to|complaint (to|with)|with)\s+(the\s+)?(\w+\s+)?$", before, re.I)
        signed = re.search(r"(^|[\n.])\s*[-–]\s*(" + rx.pattern + r")\W*$", text.strip(), re.I)   # "... -SBI"
        if starts or signed or (_CLAIM_CUES.search(near) and not possessive):
            return org
    if re.search(r"\bdear (customer|user|account holder|card ?holder|consumer)\b", text, re.I):
        return orgs[0]
    return None


def relevant(phones, emails, upi_ids) -> bool:
    return bool(phones or emails or upi_ids)


def _sig(sid, strength, reason, phrase=""):
    return {"id": sid, "strength": strength, "reason": reason, "phrase": phrase}


def detect(text: str) -> tuple[list[dict], list[str]]:
    """(signals, plain-language identity checks for the report)."""
    phones = entities.find_phones(text)
    emails = entities.find_emails(text)
    upi_ids = entities.find_payment_ids(text)
    orgs = entities.find_organisations(text)
    signals, checks = [], []

    # A brand's name inside a personal payment ID or email is impersonation whoever "sends" it.
    for ident in upi_ids + emails:
        local, _, domain = ident.partition("@")
        if _BRAND_IDS.search(local) and (_DEPT_WORDS.search(local) or domain in _FREE_MAIL or "@" in ident):
            brand = _BRAND_IDS.search(local).group(0).upper()
            kind = "payment ID" if ident in upi_ids else "email address"
            if kind == "email address" and domain not in _FREE_MAIL:
                continue   # e.g. alerts@sbi.co.in is handled by the link check
            sid = "brand_in_payment_id" if kind == "payment ID" else "brand_in_email"
            signals.append(_sig(sid, 0.85,
                                f"It uses {brand}'s name inside a personal {kind} ({ident}). Companies don't "
                                f"collect payments or documents through personal {kind}es.", ident))
            checks.append(f"{ident}: a personal {kind} made to look like {brand}.")

    org = claims_to_be(text, orgs)
    if org and org not in ("Armed forces",):
        personal = [p for p in phones if p.kind.startswith("mobile")]
        if personal:
            signals.append(_sig("official_uses_personal_number", 0.8,
                                f"It claims to be {org} but gives a personal mobile number ({personal[0].number}). "
                                "Banks, companies and government offices use official helplines, not personal "
                                "mobiles.", personal[0].number))
            checks.append(f"Claims to be {org}, but the contact number {personal[0].number} is a personal mobile.")
        free = [e for e in emails if e.rsplit("@", 1)[-1] in _FREE_MAIL]
        if free:
            signals.append(_sig("official_uses_free_email", 0.85,
                                f"It claims to be {org} but uses a free email address ({free[0]}). Official "
                                "emails come from the organisation's own domain.", free[0]))
            checks.append(f"Claims to be {org}, but the email {free[0]} is a free personal address.")
        if upi_ids and not any(s["id"] == "brand_in_payment_id" for s in signals):
            signals.append(_sig("official_asks_upi_payment", 0.8,
                                f"It claims to be {org} but asks you to pay a UPI ID ({upi_ids[0]}). Banks and "
                                "government offices never ask you to pay a UPI ID from a message.", upi_ids[0]))
            checks.append(f"Claims to be {org}, but asks for payment to the UPI ID {upi_ids[0]}.")
        foreign = [p for p in phones if p.kind == "international"]
        if foreign:
            signals.append(_sig("official_uses_foreign_number", 0.7,
                                f"It claims to be {org} but gives a foreign number ({foreign[0].number}).",
                                foreign[0].number))
            checks.append(f"Claims to be {org}, but the number {foreign[0].number} is international.")
        if not checks:
            checks.append(f"Presents itself as {org}. No mismatched contact details found, but verify through "
                          f"{org}'s official app, website or helpline.")
    return signals, checks

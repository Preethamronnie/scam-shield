"""Intent detector: what does the message want you to DO?

Scams always end in an action: share a code, pay, install something, click,
call, keep a secret. Naming the requested action plainly ("They want you to:
share your OTP; pay Rs 4,999 to refund.desk@ybl") is often the clearest
warning, especially for elderly users. Built from the red flags the other
detectors found, plus amounts, links, numbers and payment IDs in the text.
"""
from __future__ import annotations

import re

_AMOUNT = re.compile(r"(?:rs\.?|₹|inr|rupees?)\s?(\d{1,3}(?:,\d{2,3})+(?:\.\d+)?|\d+(?:\.\d+)?)(\s?(lakh|lac|crore|k)\b)?"
                     r"|(\d{1,3}(?:,\d{2,3})+|\d{3,})\s?(rupaye|rupay|rupees|रुपये|रुपए)", re.I)
_MULT = {"lakh": 100_000, "lac": 100_000, "crore": 10_000_000, "k": 1_000}


def find_amounts(text: str) -> list[float]:
    """Money amounts mentioned, largest first: 'Rs 25,000', '₹4999', '2 lakh', '5000 rupaye'."""
    out = []
    for m in _AMOUNT.finditer(text):
        raw = (m.group(1) or m.group(4) or "").replace(",", "")
        try:
            value = float(raw) * _MULT.get((m.group(3) or "").lower(), 1)
        except ValueError:
            continue
        if value > 0:
            out.append(value)
    return sorted(set(out), reverse=True)


def _rs(v: float) -> str:
    return f"Rs {v:,.0f}" if v == int(v) else f"Rs {v:,.2f}"


ACTIONS = [   # (action, rule ids that show it)
    ("Share an OTP, PIN, password or code", {"asks_secret", "sim_swap", "login_bait", "pin_to_receive",
                                             "collect_request", "qr_receive_trick"}),
    ("Pay or transfer money", {"money_request", "fee_for_prize", "sent_by_mistake", "job_task_fee", "emergency_money",
                               "pay_to_receive", "tiny_verification_payment", "official_asks_upi_payment",
                               "qr_payment_request", "brand_in_payment_id", "fake_army"}),
    ("Install an app or let them see your screen", {"apk_file", "remote_access", "apk_reads_sms", "apk_accessibility"}),
    ("Share personal or bank details", {"personal_details", "brand_in_email", "official_uses_free_email"}),
    ("Stay on a call or video call", {"digital_arrest"}),
    ("Keep it secret from your family", {"secrecy"}),
    ("Move the chat to WhatsApp or Telegram", {"move_to_chat"}),
    ("Invest in a scheme or trading app", {"fake_trading", "guaranteed_returns"}),
]


def intents(signals, text: str, urls, phones, upi_ids) -> list[dict]:
    ids = {s.id for s in signals if s.strength >= 0.5}
    out = []
    for action, rules in ACTIONS:
        hit = ids & rules
        if not hit:
            continue
        detail = ""
        if action.startswith("Pay"):
            amounts = find_amounts(text)
            to = f" to {upi_ids[0]}" if upi_ids else ""
            detail = (_rs(amounts[0]) if amounts else "") + to
        out.append({"action": action, "detail": detail.strip(), "because": sorted(hit)})
    risky_links = [u for u in urls if u.assessment != "official"]
    if risky_links and any(s.id in ("fake_brand_link", "brand_mismatch", "odd_link", "short_link",
                                    "disguised_link", "blocklisted_link") for s in signals):
        out.append({"action": "Open a link", "detail": risky_links[0].host, "because": ["link checks"]})
    if phones and ids & {"customer_care_callback", "official_uses_personal_number", "digital_arrest", "threat"}:
        out.append({"action": "Call a phone number", "detail": phones[0].number, "because": ["contact details"]})
    return out

"""Manipulation detector: HOW is the message pressuring you?

Scams work on emotions, not logic. Naming the lever ("fear: it threatens
arrest"; "urgency: act within 24 hours"; "family: it pretends to be your
child") helps people recognise the technique next time, whatever the wording.
Built from the other detectors' red flags, plus cues for scarcity and sympathy.
"""
from __future__ import annotations

import re

LEVERS = [   # (lever, plain explanation, rule ids)
    ("Fear", "It threatens something bad (arrest, a blocked account, a case) so you act without thinking.",
     {"threat", "digital_arrest", "sextortion", "fine_or_toll", "email_auth_fail"}),
    ("Urgency", "It rushes you, so you don't stop to check.", {"urgency", "repeated_pressure", "scarcity"}),
    ("Authority", "It pretends to be police, a bank, a company or a government office, so you obey.",
     {"digital_arrest", "customer_care_callback", "fake_brand_link", "brand_mismatch", "email_sender_spoof",
      "official_uses_personal_number", "official_uses_free_email", "official_asks_upi_payment",
      "brand_in_payment_id", "brand_in_email", "official_uses_foreign_number", "fake_army", "govt_scheme"}),
    ("Greed", "It offers something too good to be true: a prize, easy money, huge returns.",
     {"prize", "fee_for_prize", "guaranteed_returns", "easy_job", "job_task_fee", "fake_trading", "reward_points",
      "govt_scheme"}),
    ("Love and family", "It uses your love for family: a child in trouble, a relative in need.",
     {"new_number_family", "emergency_money"}),
    ("Isolation", "It tells you to keep it secret or stay on the line, so nobody can warn you.",
     {"secrecy", "digital_arrest", "ignores_refusal"}),
    ("Trust-building", "It builds a friendship first, so the request later feels normal.",
     {"slow_build", "wrong_number_opener"}),
    ("Sympathy and guilt", "It makes you feel sorry for them or guilty, so you help.", {"sympathy", "sent_by_mistake"}),
    ("Shame", "It uses embarrassment, so you pay quietly instead of asking for help.", {"sextortion"}),
]

_SCARCITY = re.compile(r"\b(only \d+ (seats?|slots?|spots?|left|remaining)|limited (seats|slots|offer|period)|"
                       r"last (chance|few|day)|offer (ends|valid till|expires)|first \d+ (customers|people|users)|"
                       r"while stocks last|selling fast)\b", re.I)
_SYMPATHY = re.compile(r"\b(my (mother|mom|father|dad|child|son|daughter|wife|husband)'?s? (hospital|medical|operation|"
                       r"treatment|fees)|please help me|i am (very )?poor|i have no one|god will bless you|"
                       r"i('m| am) begging)\b", re.I)


def detect(text: str) -> list[dict]:
    out = []
    m = _SCARCITY.search(text)
    if m:
        out.append({"id": "scarcity", "strength": 0.5, "phrase": m.group(0),
                    "reason": "It says the offer is limited or running out, to push you into deciding fast."})
    m = _SYMPATHY.search(text)
    if m:
        out.append({"id": "sympathy", "strength": 0.45, "phrase": m.group(0),
                    "reason": "It appeals to your sympathy. Genuine people in need can be helped after you've "
                              "checked who they are."})
    return out


def tactics(signals) -> list[dict]:
    """The pressure levers in use, with the words that show them."""
    by_id = {}
    for s in signals:
        if s.strength >= 0.45:
            by_id.setdefault(s.id, s)
    out = []
    for lever, explain, rules in LEVERS:
        hits = [by_id[r] for r in rules if r in by_id]
        if hits:
            quote = next((h.phrase for h in hits if h.phrase and len(h.phrase.split()) >= 2), "")
            out.append({"lever": lever, "explanation": explain, "evidence": quote[:100]})
    return out

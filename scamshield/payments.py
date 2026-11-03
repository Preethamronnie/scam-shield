"""Payment detector: UPI and payment tricks.

UPI scams mostly work by making a *payment* look like *receiving* money, or a
large payment look like a harmless check. This detector looks for:
  * collect requests: "approve the request to receive your cashback" (approving
    a collect request sends money);
  * tiny "verification" payments: "pay just Rs 1 to verify your account";
  * pay-to-receive: "pay a small fee to release your refund / prize / loan".
QR codes in images are handled by inspectors.qr_findings, and "sent by
mistake" refund scams by the rule engine.

Returns signal dicts like the other detectors.
"""
from __future__ import annotations

import re

_COLLECT = re.compile(
    r"\b(collect request|payment request|money request|request (of|for) (rs\.?|₹|inr)\s?[\d,]+|upi request)\b"
    r".{0,100}\b(approve|accept|confirm|enter (your )?(upi )?pin|authori[sz]e)\b"
    r"|\b(approve|accept)\b.{0,40}\b(request|collect)\b.{0,60}\b(receive|get|credit|cashback|refund|prize)\b",
    re.I | re.S)
_TINY_PAYMENT = re.compile(
    r"\b(pay|send|transfer|deposit)\b.{0,15}\b(just|only|a small|nominal|token)?\s*(rs\.?|₹|inr|re\.?)\s?(1|2|5|9|10|11|19|20|49|99)\b(?![\d,])"
    r".{0,80}\b(verify|verification|activate|activation|confirm|register|unlock|kyc|refund|validate|link)\w*",
    re.I | re.S)
_PAY_TO_RECEIVE = re.compile(
    r"\b(pay|deposit|transfer|send)\b.{0,60}\b(to (receive|release|unlock|claim|get|withdraw|process))\b"
    r".{0,60}\b(refund|prize|money|loan|amount|reward|parcel|profit|payment|cashback)\b",
    re.I | re.S)


def _sig(sid, strength, reason, phrase=""):
    return {"id": sid, "strength": strength, "reason": reason, "phrase": phrase}


def relevant(text: str) -> bool:
    """Should this detector run at all? (Used by the router.)"""
    return bool(re.search(r"(₹|\brs\.?\s?\d|\binr\b|\bupi\b|\bpay|\brefund|\bcashback|\bcollect|\brequest\b|"
                          r"\btransfer|\bdeposit|paise|rupaye|पैसे|रुपये)", text, re.I))


def detect(text: str) -> list[dict]:
    out = []
    m = _COLLECT.search(text)
    if m:
        out.append(_sig("collect_request", 0.92,
                        "It asks you to approve a payment or 'collect' request to receive money. Approving a request "
                        "and entering your PIN SENDS money; you never approve anything to receive it.",
                        m.group(0)[:90]))
    m = _TINY_PAYMENT.search(text)
    if m:
        out.append(_sig("tiny_verification_payment", 0.85,
                        "It asks for a tiny payment (like Rs 1 or Rs 10) to 'verify' or 'activate' something. "
                        "Banks and apps don't need you to pay to verify, and the payment page is often a trap.",
                        m.group(0)[:90]))
    m = _PAY_TO_RECEIVE.search(text)
    if m:
        out.append(_sig("pay_to_receive", 0.85,
                        "It asks you to pay first so that you can receive or release money. Real refunds, prizes "
                        "and loans never require you to pay to get them.", m.group(0)[:90]))
    return out

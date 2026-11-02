"""Rule-based red flags.

Each rule looks for one well-known scam tactic and explains it in words a
child or a grandparent can follow. These run with no model and no internet,
so the app still gives useful answers if the ML model or LLM is unavailable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    id: str
    weight: float  # how strongly this points to a scam, 0-1
    reason: str    # shown to the user


_URL = re.compile(r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:xyz|top|click|info|win|fun|site|link|co|ly|buzz|live|icu)\b\S*)", re.I)
_SHORTENER = re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy)/", re.I)
_RISKY_TLD = re.compile(r"\.(xyz|top|click|info|win|fun|site|link|buzz|icu|live)\b", re.I)
_BRAND_IN_DOMAIN = re.compile(r"https?://[^\s/]*(sbi|hdfc|icici|axis|paytm|amazon|flipkart|usps|indiapost|fedex|dhl|paypal|netflix|insta|whatsapp|itr|incometax)[^\s/]*[-.]", re.I)

_PATTERNS: list[tuple[str, float, str, str]] = [
    ("asks_secret", 0.95,
     r"\b(otp|one[- ]time password|verification code|upi pin|\bpin\b|cvv|password|6 digit code)\b.{0,60}\b(share|send|tell|enter|give|reply)\b"
     r"|\b(share|send|tell|give|enter)\b.{0,60}\b(otp|verification code|upi pin|cvv|password|code)\b",
     "It asks you to share a code, PIN or password. Real banks and companies never ask for these."),
    ("pin_to_receive", 0.95,
     r"\b(receive|accept|get)\b.{0,40}\b(money|payment|rs|refund)\b.{0,60}\b(pin|scan|qr)\b"
     r"|\bscan\b.{0,30}\bqr\b.{0,40}\b(receive|refund|get)\b",
     "It says you must enter a PIN or scan a QR code to receive money. You never need a PIN to receive money; this takes money out of your account."),
    ("remote_access", 0.95,
     r"\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?share|install .{0,20}app so we can)\b",
     "It asks you to install a screen-sharing app. This lets a stranger control your phone or computer."),
    ("fee_for_prize", 0.9,
     r"\b(won|winner|prize|lottery|lucky draw|selected|gift|giveaway|approved|refund)\b.{0,120}\b(fee|charge|pay|processing|registration|deposit)\b"
     r"|\b(pay|fee|charge)\b.{0,80}\b(to claim|to start|to release|to get it)\b",
     "It asks you to pay money to get a prize, job, loan or parcel. Real prizes and jobs don't ask for fees."),
    ("prize", 0.6,
     r"\b(congratulations|you have won|you('ve| have) been selected|winner|lucky draw|jackpot|free (iphone|gift|diamonds|robux))\b",
     "It says you won something you never entered. That's a classic way to hook people."),
    ("threat", 0.7,
     r"\b(blocked|suspended|disconnected|deactivated|deleted|cut|arrest|legal action|police|illegal)\b",
     "It threatens that something bad will happen (account blocked, power cut, arrest). Scammers use fear so you act without thinking."),
    ("urgency", 0.3,
     r"\b(urgent(ly)?|immediately|right now|within \d+ (hours?|minutes?)|today|tonight|expires?|last chance|limited (time|seats))\b",
     "It pushes you to act fast. Pressure to hurry is a common scam tactic."),
    ("secrecy", 0.7,
     r"\b(don'?t tell anyone|keep (this|it) secret|can'?t talk|don'?t call)\b",
     "It asks you to keep it secret or says they can't talk. Scammers do this so you can't check with family."),
    ("new_number_family", 0.75,
     r"\b(new number|lost my phone|dropped my phone|broke my phone|phone (is )?broken)\b",
     "Someone claims to be family on a new number and asks for help. Call their old number or meet them before sending anything."),
    ("money_request", 0.55,
     r"\b(send|transfer|pay)\b.{0,40}\b(money|rs\.?|₹|\$|upi|amount|advance)\b",
     "It asks you to send money."),
    ("guaranteed_returns", 0.85,
     r"\b(guaranteed|100% (safe|profit)|double your|\d{3,}% returns?|risk[- ]free)\b",
     "It promises guaranteed or huge returns. No real investment can promise that."),
    ("easy_job", 0.75,
     r"\b(earn|income|payout)\b.{0,60}\b(daily|per day|from home|liking|tasks?)\b"
     r"|\b(part[- ]time|work from home|online tasks?)\b.{0,80}\b(earn|daily|whatsapp|telegram)\b",
     "It offers easy money for simple tasks. These 'jobs' usually end with you paying them."),
    ("move_to_chat", 0.4,
     r"\b(whatsapp|telegram)\b.{0,30}\b(hr|now|group|join|me|on)\b",
     "It asks you to move the conversation to WhatsApp or Telegram, away from official channels."),
    ("personal_details", 0.7,
     r"\b(aadhaar|pan|card details|bank details|account number|date of birth|full name, address)\b.{0,40}\b(share|send|submit|update|enter)\b"
     r"|\b(share|send|submit|enter)\b.{0,40}\b(aadhaar|card details|bank details|account number)\b",
     "It asks for personal or bank details."),
    ("login_bait", 0.8,
     r"\b(log ?in|enter)\b.{0,40}\b(username and password|your (game )?account|password)\b",
     "It asks you to log in through their link. That's how accounts get stolen."),
]

_COMPILED = [(i, w, re.compile(p, re.I | re.S), r) for i, w, p, r in _PATTERNS]


def find_signals(text: str) -> list[Signal]:
    """Return every red flag found in `text`, strongest first."""
    found: list[Signal] = []
    for sid, weight, rx, reason in _COMPILED:
        if rx.search(text):
            found.append(Signal(sid, weight, reason))

    urls = _URL.findall(text)
    if urls:
        if _SHORTENER.search(text):
            found.append(Signal("short_link", 0.6, "It uses a shortened link, which hides where it really goes."))
        if _BRAND_IN_DOMAIN.search(text):
            found.append(Signal("fake_brand_link", 0.9, "The link uses a well-known company's name, but it isn't that company's real website."))
        elif _RISKY_TLD.search(text):
            found.append(Signal("odd_link", 0.6, "The link goes to an unusual website, not an official one."))
        else:
            found.append(Signal("link", 0.25, "It contains a link. Only open links you were expecting."))

    # A safety notice ("do not share your OTP") is a sign of a real message.
    if re.search(r"\b(do not|don'?t|never) share\b", text, re.I):
        found = [s for s in found if s.id != "asks_secret"]

    return sorted(found, key=lambda s: s.weight, reverse=True)


def rule_score(signals: list[Signal]) -> float:
    """Combine signals into a 0-1 score (noisy-OR, so several weak flags add up)."""
    p_safe = 1.0
    for s in signals:
        p_safe *= 1.0 - s.weight
    return 1.0 - p_safe

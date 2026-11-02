"""'I'm on a call right now' mode.

Digital-arrest, fake-police and fake-bank scams work by keeping the victim on
the phone (sometimes for hours, on video) so they can't stop, think or ask
anyone. This mode is for that moment: a few yes/no questions about what the
caller is doing, then clear instructions and a script.

Every check is something genuine police, banks, companies and government
officials do not do on a phone or video call, so any single "yes" is enough
to say: hang up.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CallCheck:
    key: str
    question: str
    why: str


CHECKS = [
    CallCheck("authority", "Says they're police, CBI, customs, a court, TRAI, RBI or another officer",
              "Officers don't investigate or arrest people over phone or video calls."),
    CallCheck("stay_on", "Tells you to stay on the call, keep the video on, or not hang up",
              "Keeping you on the line is how scammers stop you checking with anyone."),
    CallCheck("secret", "Tells you not to tell your family or anyone else",
              "Genuine officials never ask you to keep an investigation secret from your family."),
    CallCheck("money", "Asks you to pay, transfer, 'verify' or 'park' money in another account",
              "No agency asks you to move money to prove your innocence or keep it safe."),
    CallCheck("codes", "Asks for an OTP, PIN, password, or card or bank details",
              "Banks and officials never ask for these on a call."),
    CallCheck("install", "Asks you to install an app, open a link, or share your screen",
              "Apps and screen sharing let them see your OTPs and control your phone."),
    CallCheck("threat", "Threatens arrest, a case, a frozen account or a cut connection",
              "Fear is used so you obey without thinking."),
    CallCheck("relative", "Says a family member is in trouble, arrested or in hospital and needs money",
              "Call that family member yourself on their usual number."),
]
_BY_KEY = {c.key: c for c in CHECKS}

# Message rules that usually mean the scam is happening on a live call, so the
# message results can point people to this mode.
CALL_SCAM_RULES = {"digital_arrest", "emergency_money", "customer_care_callback", "remote_access",
                   "sim_swap", "asks_secret"}


@dataclass
class CallAdvice:
    is_scam: bool
    headline: str
    reasons: list[str]


def assess_call(ticked: list[str]) -> CallAdvice:
    reasons = [_BY_KEY[k].why for k in ticked if k in _BY_KEY]
    if reasons:
        return CallAdvice(True, "This is a scam. Hang up now.", reasons)
    return CallAdvice(False, "If anything on this list happens, hang up. You can always call back on an "
                             "official number you look up yourself.", [])


def suggests_live_call(signal_ids) -> bool:
    return bool(set(signal_ids) & CALL_SCAM_RULES)

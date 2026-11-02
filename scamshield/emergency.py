"""What to do if you've already been scammed (India).

Ordered by urgency: the first steps are the ones where minutes matter. Shown
on its own tab, and as a banner on every warning verdict.
"""
from __future__ import annotations

HELPLINE = "1930"
PORTAL = "https://cybercrime.gov.in"
CHAKSHU = "https://sancharsaathi.gov.in"

SITUATIONS = {
    "paid": "I sent money (UPI, bank transfer, card, gift card)",
    "otp": "I shared an OTP, PIN, password or card details",
    "app": "I installed an app or let someone see or control my screen",
    "id": "I shared Aadhaar, PAN or other ID documents",
    "threat": "Someone is threatening or blackmailing me",
}

ALWAYS_FIRST = [
    f"**Call {HELPLINE} now** (National Cyber Crime Helpline). Reporting within the first hours gives the best "
    "chance of stopping the money before it's moved on.",
    f"**Report online** at [{PORTAL.removeprefix('https://')}]({PORTAL}) if you can't get through, "
    "or as well as calling. Note down the complaint number you're given.",
]

STEPS = {
    "paid": [
        "**Call your bank or payment app** using the number on the back of your card or inside the official app "
        "(never a number from the message). Ask them to block further payments and raise a fraud complaint.",
        "In your UPI app, open the payment and use **Help / Report a problem** to raise a dispute.",
        "Keep the **transaction ID / UTR number**, the amount, date and time, and the receiver's UPI ID or account number.",
    ],
    "otp": [
        "**Call your bank now** to block your card and, if needed, freeze net banking and UPI.",
        "Change your banking, email and UPI passwords and PINs, starting with any you shared.",
        "Check your account for payments you didn't make, and tell the bank about every one.",
    ],
    "app": [
        "**Turn on airplane mode** or switch off mobile data and Wi-Fi straight away.",
        "Uninstall the app (AnyDesk, TeamViewer, or the .apk you installed).",
        "Call your bank **from a different phone** if you can, and block your cards and UPI.",
        "Change your passwords from another device, then have the phone checked or reset.",
    ],
    "id": [
        "On the official UIDAI website or mAadhaar app, **lock your Aadhaar biometrics** so they can't be misused.",
        "Watch for loans, SIM cards or accounts opened in your name, and report any you don't recognise.",
        f"Report suspected fraud calls and messages on **Chakshu** at [{CHAKSHU.removeprefix('https://')}]({CHAKSHU}).",
    ],
    "threat": [
        "**Don't pay and don't reply.** Paying almost always leads to more demands.",
        "Take screenshots of the messages, the profile and any payment requests, then block the account.",
        f"Report it at [{PORTAL.removeprefix('https://')}]({PORTAL}). It has an option for reporting crimes "
        "involving women and children, including anonymously.",
        "If you're under 18, tell a parent, teacher or another adult you trust. You haven't done anything wrong.",
    ],
}

ALWAYS_LAST = [
    "**Save the evidence:** screenshots of the chat, the sender's number or profile, links, and payment receipts. "
    "Don't delete the conversation.",
    "Tell your family. Scammers often target the same people again, sometimes pretending to be police "
    "who can 'recover' your money for a fee. That's a second scam.",
]


def steps_for(situations: list[str]) -> list[str]:
    """Steps for the chosen situations, most urgent first, without repeats."""
    steps = list(ALWAYS_FIRST)
    for key in SITUATIONS:
        if key in situations:
            steps += STEPS[key]
    return list(dict.fromkeys(steps + ALWAYS_LAST))

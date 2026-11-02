"""Rule-based red flags.

Each rule looks for one well-known scam tactic and explains it in words a
child or a grandparent can follow. These run with no model and no internet,
so the app still gives useful answers if the ML model or LLM is unavailable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .links import check_links, find_links, host_of, is_official

LINK_DEPENDENT = {"fine_or_toll", "govt_scheme", "reward_points"}


@dataclass(frozen=True)
class Signal:
    id: str
    strength: float  # how clearly the text shows this tactic, 0-1
    reason: str      # shown to the user
    phrase: str = ""   # short quote of the words that triggered it (may be shortened with …)
    context: str = ""  # the full sentence(s) around the match, for highlighting



# (id, strength, pattern, reason). Strength is how unambiguously the text
# shows the tactic, not how dangerous it is: danger comes from the rule's risk
# category (see risk.py).
_PATTERNS: list[tuple[str, float, str, str]] = [
    ("asks_secret", 0.95,
     r"\b(otp|one[- ]time password|verification code|upi pin|\bpin\b|cvv|password|6 digit code)\b.{0,60}\b(share|send|tell|enter|give|reply|forward)\b"
     r"|\b(share|send|tell|give|enter|reply with|forward)\b.{0,60}\b(otp|verification code|upi pin|cvv|password|code)\b",
     "It asks you to share a code, PIN or password. Real banks and companies never ask for these."),
    ("pin_to_receive", 0.95,
     r"\b(receive|accept|get)\b.{0,40}\b(money|payment|rs|refund)\b.{0,60}\b(pin|scan|qr)\b"
     r"|\bscan\b.{0,30}\bqr\b.{0,40}\b(receive|refund|get)\b"
     r"|\b(enter|entering|type)\b.{0,20}\b(upi )?pin\b.{0,60}\b(get|receive|cashback|refund|accept|claim)\b",
     "It says you must enter a PIN or scan a QR code to receive money. You never need a PIN to receive money; this takes money out of your account."),
    ("remote_access", 0.95,
     r"\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?share|install .{0,20}app so we can)\b",
     "It asks you to install a screen-sharing app. This lets a stranger control your phone or computer."),
    ("fee_for_prize", 0.9,
     r"\b(won|winner|prize|lottery|lucky draw|selected|gifts?|giveaway|approved|refund)\b.{0,120}\b(fee|charge|pay|processing|registration|deposit)\b"
     r"|\b(pay|fee|charge)\b.{0,80}\b(to claim|to start|to release|to get it)\b",
     "It asks you to pay money to get a prize, job, loan or parcel. Real prizes and jobs don't ask for fees."),
    ("prize", 0.6,
     r"\b(congratulations|you have won|you('ve| have) been selected|winner|lucky draw|jackpot|free (iphone|gift|diamonds|robux)"
     r"|(was|been|is) awarded|selected to (receive|win)|claim (your |the )?(prize|reward|cash))\b",
     "It says you won something you never entered. That's a classic way to hook people."),
    ("threat", 0.7,
     # Needs something of yours being blocked/cut, not just the word: real chats
     # say "hair cut" and "blocked by politicians" (found on real 2012 messages).
     r"\b(account|card|sim|number|connection|power|electricity|kyc|service|pan|aadhaar|wallet|upi|netbanking|profile|id)\b"
     r".{0,50}\b(blocked|suspended|disconnected|deactivated|deleted|cut|frozen|terminated|closed)\b"
     r"|\b(arrest(ed)?|legal action|court case|fir)\b",
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
     r"\b(aadhaar|pan|card details|bank details|account number|date of birth|full name, address)\b.{0,40}\b(share|send|submit|enter|provide)\b"
     r"|\b(share|send|submit|enter)\b.{0,40}\b(aadhaar|card details|bank details|account number)\b",
     "It asks for personal or bank details."),
    ("login_bait", 0.8,
     r"\b(log ?in|enter)\b.{0,40}\b(username and password|your (game )?account|password)\b",
     "It asks you to log in through their link. That's how accounts get stolen."),
    # --- scam types common in 2025-26 ---------------------------------------
    ("apk_file", 0.92,
     r"\.apk\b|\bapk (file|link)\b|download .{0,30}\bapp\b.{0,20}\b(from )?(this|the|below|given) link\b"
     r"|install .{0,30}\b(from|via) (this|the|below|given)( given| below)? link\b",
     "It asks you to install an app from a link or file (often an .apk). Apps from outside the Play Store or App Store can read your OTPs and empty your bank account."),
    ("digital_arrest", 0.9,
     r"\bdigital(ly)? arrest"
     r"|\b(cbi|ed|enforcement directorate|narcotics|ncb|cyber ?crime|crime branch|police|customs|rbi|trai|income tax)\b.{0,100}\b(video call|skype|warrant|money laundering|drugs?|illegal (items|parcel)|case (is |has been )?(registered|filed)|stay on (the )?call)"
     r"|\b(arrest|warrant)\b.{0,80}\b(pay|transfer|verify|deposit|security amount)\b",
     "It says police, CBI, customs or another agency is investigating you. Real officers never 'arrest' anyone on a video call or ask you to transfer money to clear your name."),
    ("emergency_money", 0.85,
     r"\b(accident|hospital|kidnapp?ed|in jail|arrested|police station|stuck abroad)\b.{0,100}\b(send|transfer|pay|money|rs|₹|upi)\b"
     r"|\b(need(s|ed)?|send|transfer)\b.{0,30}\bmoney\b.{0,60}\b(accident|hospital|jail|police station|bail|stuck abroad)\b",
     "It says someone you love is in an emergency and needs money right now. Hang up and call that person, or another family member, on a number you already have."),
    ("sextortion", 0.95,
     r"\b(video|photos?|pics?|recording|chats?)\b.{0,60}\b(of you|you sent|with you)\b.{0,100}\b(leak|share|send (it )?to|post|viral|family|friends|contacts)\b"
     r"|\bpay\b.{0,40}\bor (i|we)('ll| will) (share|post|send|leak)",
     "It threatens to share private photos or videos unless you pay. Don't pay and don't reply. Tell someone you trust and report it; paying only leads to more demands."),
    ("sent_by_mistake", 0.8,
     r"\b(sent|transferred|credited)\b.{0,50}\b(by mistake|wrongly|accidentally|wrong number)\b.{0,80}\b(return|send (it )?back|refund|transfer back)",
     "Someone says they sent you money by mistake and asks for it back. Check your bank app yourself; the 'payment' is often a fake message or a collect request."),
    ("reward_points", 0.75,
     r"\b(reward|credit card|loyalty|bonus) points?\b.{0,80}\b(expir|lapse)",
     "It says your reward points are expiring and pushes you to redeem them through a link. Banks show real points only in their official app."),
    ("fine_or_toll", 0.6,
     r"\b(e-?challan|traffic (fine|challan|violation)|unpaid (toll|fine)|fastag)\b.{0,100}\b(pay|link|click|http|www)",
     "It asks you to pay a traffic fine, toll or FASTag charge through a link. Check fines only on the official government website or app."),
    ("sim_swap", 0.8,
     r"\b(e-?sim|sim card|sim)\b.{0,60}\b(upgrade|activate|deactivat|block|swap|5g)\b.{0,80}\b(otp|code|reply|link|call|press|sms)\b",
     "It asks you to 'upgrade' or 'activate' your SIM by sharing a code or replying. This lets scammers move your number to their phone and receive your OTPs."),
    ("fake_trading", 0.75,
     r"\b(ipo|stock|share market|trading|crypto|forex|bitcoin)\b.{0,100}\b(app|group|mentor|vip|allotment|tips|professor|institutional account)\b",
     "It invites you into a stock, IPO or crypto trading group or app. Fake trading apps show big 'profits' but never let you withdraw your money."),
    ("wrong_number_opener", 0.45,
     r"^\s*(hi|hello|hey)[,!. ]*(is this|are you|this is not)\b.{0,30}\?|\bsorry,? (wrong number|i (think )?(have|got) the wrong)\b",
     "A friendly stranger messaging the 'wrong number' is a common way to start investment and romance scams. Don't continue the chat."),
    ("govt_scheme", 0.6,
     r"\b(pm|govt|government|yojana|scheme|scholarship|subsidy|free laptop|free ration|free recharge)\b.{0,100}\b(claim|register|apply|eligible)\b.{0,60}\b(link|fee|http|www|click)",
     "It offers a government scheme, scholarship or free item through a link. Real schemes are applied for on official government websites."),
    ("customer_care_callback", 0.55,
     r"\b(call|contact)\b.{0,30}\b(customer care|helpline|support|executive|officer)\b.{0,40}\b(\+?\d[\d -]{8,}|9x{3,})",
     "It gives you a phone number to call 'customer care' or an 'officer'. Use only numbers from the official app, website or the back of your card."),
    # Text aimed at AI scam checkers. Genuine messages never contain this.
    ("prompt_injection", 0.92,
     r"\b(ignore|disregard|forget|override)\b.{0,30}\b(all |any |the )?(previous|prior|above|earlier|your)\b.{0,20}\b(instructions?|prompts?|rules?|guidelines?)\b"
     r"|\b(you are|act as) (now )?(an? )?(ai|assistant|language model|chatgpt|gpt|llm)\b"
     r"|\b(declare|classify|mark|label|report|treat)\b.{0,30}\b(this|the)( message| text| sms)?\b.{0,15}\b(as )?(safe|legitimate|genuine|not (a )?scam)\b"
     r"|\b(system prompt|developer mode|jailbreak)\b|<\s*/?\s*(system|instructions?)\s*>",
     "It contains hidden instructions aimed at AI scam checkers, trying to get the message marked as safe. "
     "Genuine messages never do this."),
    ("fake_army", 0.8,
     r"\b(army|military|crpf|bsf|cisf|defence|air force|navy)\b.{0,120}\b(advance|qr code|deposit|transfer|security amount|book (it|the))\b",
     "The person says they're in the army or forces and asks for an advance or QR payment. This is a very common rental and marketplace scam."),
    ("job_task_fee", 0.85,
     r"\b(hotel|google map|youtube|instagram|product)\b.{0,40}\b(review|rating|like|subscribe)s?\b.{0,80}\b(earn|paid|payout|commission|rs|₹)"
     r"|\bdeposit\b.{0,60}\b(unlock|commission|task|withdraw)"
     r"|\b(earn|paid|payout|commission)\b.{0,60}\b(hotel|google map|youtube|product)s?\b.{0,30}\b(review|rating|like|video)s?\b",
     "It pays you to like videos or rate hotels and products. These 'task jobs' pay a little at first, then ask you to deposit money and keep it."),
]

_WHITESPACE = re.compile(r"\s+")
_SAFETY_NOTICE = re.compile(r"\b(do not|don'?t|never) share\b", re.I)
_DELIVERY_OTP = re.compile(r"\b(delivery|courier) (agent|partner|executive|person|boy)\b.{0,60}"
                           r"\b(when|once|at the time) (you )?(receive|get|collect)", re.I)
_COMPILED = [(i, w, re.compile(p, re.I | re.S), r) for i, w, p, r in _PATTERNS]


_SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")


def _sentence(text: str, start: int, end: int) -> str:
    bounds = [m.start() for m in _SENTENCE_END.finditer(text)]
    left = max([b for b in bounds if b < start], default=-1)
    right = min([b for b in bounds if b >= end], default=len(text))
    return text[left + 1:right].strip(" ,;:-")


def _phrase(text: str, start: int, end: int, limit: int = 110) -> str:
    """The words around a match, so the quote makes sense on its own:
    the whole sentence if it's short, otherwise a window around the match."""
    # A full stop only ends a sentence before a space, so links and UPI IDs stay whole.
    bounds = [m.start() for m in _SENTENCE_END.finditer(text)]
    left = max([b for b in bounds if b < start], default=-1)
    right = min([b for b in bounds if b >= end], default=len(text))
    sentence = text[left + 1:right].strip(" ,;:-")
    if len(sentence) <= limit:
        return sentence
    a = max(left + 1, start - 30)
    b = min(right, max(end, a + 40) + 30)
    window = text[a:b]
    if a > left + 1:
        window = "…" + window.split(" ", 1)[-1]
    if b < right:
        window = window.rsplit(" ", 1)[0] + "…"
    return window.strip(" ,;:-")


def find_signals(text: str, online: bool = False) -> list[Signal]:
    """Return every red flag found in `text`, strongest first."""
    text = _WHITESPACE.sub(" ", text)  # photos and pasted chats break lines mid-sentence
    found: list[Signal] = []
    for sid, strength, rx, reason in _COMPILED:
        m = rx.search(text)
        if m:
            found.append(Signal(sid, strength, reason, _phrase(text, m.start(), m.end()),
                                _sentence(text, m.start(), m.end())))

    for f in check_links(text, online):
        found.append(Signal(f.id, f.strength, f.reason, f.phrase))

    # Rules that only matter because of *where* a link goes are dropped when
    # every link is an official site (a real e-challan or scheme portal).
    hosts = [host_of(u) for u in find_links(text)]
    if hosts and all(is_official(h) for h in hosts):
        found = [s for s in found if s.id not in LINK_DEPENDENT]

    # A safety notice ("do not share your OTP") is a sign of a real message,
    # and so is a delivery OTP meant for the person handing over your parcel.
    if _SAFETY_NOTICE.search(text) or _DELIVERY_OTP.search(text):
        found = [s for s in found if s.id != "asks_secret"]

    return sorted(found, key=lambda s: s.strength, reverse=True)

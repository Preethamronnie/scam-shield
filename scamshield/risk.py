"""Weighted risk categories.

Every red-flag rule belongs to one or more *categories* of scam tactic, and
each category has a risk level. Evidence is combined across categories, not
by counting rules: five rules that all spot urgency are still one piece of
evidence (urgency), while a credential request plus a fake brand link are two
independent pieces of evidence, which is what makes a scam verdict strong.

Two different numbers come out of this, and they mean different things:

* the **risk score** (0-100) is a weighted sum of the evidence found. It is a
  ranking of how much scam evidence a message contains. It is NOT a
  probability and is never shown as one.
* the **verdict** comes from explicit decision rules over the categories (see
  `decide`), with "Insufficient information" when the evidence doesn't support
  a confident call either way.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .signals import Signal

CRITICAL, HIGH, MEDIUM = "Critical", "High", "Medium"
LEVEL_POINTS = {CRITICAL: 60, HIGH: 40, MEDIUM: 20}
LEVEL_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}


@dataclass(frozen=True)
class Category:
    key: str
    name: str
    level: str
    example: str


CATEGORIES = {c.key: c for c in [
    Category("credential_theft", "Credential theft", CRITICAL, "Share OTP / UPI PIN, install a screen-sharing app"),
    Category("financial_manipulation", "Financial manipulation", HIGH, "Pay a processing fee, guaranteed returns"),
    Category("impersonation", "Impersonation", HIGH, "Fake police officer, fake bank website"),
    Category("social_engineering", "Social engineering", HIGH, "New number pretending to be family"),
    Category("urgency", "Urgency and pressure", MEDIUM, "Act within 10 minutes, account will be blocked"),
    Category("suspicious_url", "Suspicious link", MEDIUM, "Unknown shortened link, look-alike website"),
    Category("scam_wording", "Scam-like wording", MEDIUM, "Wording the ML model has often seen in scams"),
]}

# Which categories each rule is evidence for. A fake brand link is both a
# suspicious URL and impersonation, so it counts in both.
CATEGORY_OF: dict[str, tuple[str, ...]] = {
    # credential theft: anything that hands over codes, PINs, logins or the device
    "asks_secret": ("credential_theft",),
    "pin_to_receive": ("credential_theft",),
    "remote_access": ("credential_theft",),
    "apk_file": ("credential_theft",),
    "login_bait": ("credential_theft",),
    "sim_swap": ("credential_theft",),
    "personal_details": ("credential_theft",),
    # financial manipulation: getting money out of you
    "fee_for_prize": ("financial_manipulation",),
    "money_request": ("financial_manipulation",),
    "guaranteed_returns": ("financial_manipulation",),
    "easy_job": ("financial_manipulation",),
    "job_task_fee": ("financial_manipulation",),
    "sent_by_mistake": ("financial_manipulation",),
    "fake_trading": ("financial_manipulation",),
    "prize": ("financial_manipulation",),
    "reward_points": ("financial_manipulation",),
    "fine_or_toll": ("financial_manipulation",),
    "govt_scheme": ("financial_manipulation",),
    # impersonation: pretending to be an authority or company
    "digital_arrest": ("impersonation",),
    "customer_care_callback": ("impersonation",),
    "fake_army": ("impersonation",),
    "fake_brand_link": ("impersonation", "suspicious_url"),
    "blocklisted_link": ("credential_theft", "suspicious_url"),  # known phishing/malware site
    "brand_mismatch": ("impersonation", "suspicious_url"),
    # social engineering: exploiting trust, love, fear or shame
    "new_number_family": ("social_engineering",),
    "emergency_money": ("social_engineering",),
    "secrecy": ("social_engineering",),
    "wrong_number_opener": ("social_engineering",),
    "sextortion": ("social_engineering",),
    "prompt_injection": ("social_engineering",),   # manipulating the checker itself
    "move_to_chat": ("social_engineering",),
    # files (inspectors.py): QR codes, payment screenshots, PDFs, APKs, emails
    "qr_receive_trick": ("credential_theft",),        # a "receive money" QR that actually pays
    "qr_payment_request": ("financial_manipulation",),  # weak on its own: shops use payment QRs too
    "payment_screenshot": ("financial_manipulation",),  # weak on its own: a hint, not proof
    "pdf_javascript": ("credential_theft",),
    "pdf_launch": ("credential_theft",),
    "pdf_embedded_file": ("credential_theft",),
    "pdf_auto_link": ("suspicious_url",),
    "apk_reads_sms": ("credential_theft",),
    "apk_sends_sms": ("credential_theft",),
    "apk_accessibility": ("credential_theft",),
    "apk_notifications": ("credential_theft",),
    "apk_overlay": ("credential_theft",),
    "apk_installs_apps": ("credential_theft",),
    "apk_calls": ("credential_theft",),
    "apk_contacts": ("credential_theft",),
    "apk_phone_state": ("credential_theft",),
    "email_sender_spoof": ("impersonation",),
    "email_reply_elsewhere": ("impersonation",),
    "email_auth_fail": ("impersonation",),
    "email_risky_attachment": ("credential_theft",),
    # payment detector (payments.py)
    "collect_request": ("credential_theft",),          # approving + PIN sends money, like pin_to_receive
    "tiny_verification_payment": ("financial_manipulation",),
    "pay_to_receive": ("financial_manipulation",),
    # identity intelligence (identity.py)
    "brand_in_payment_id": ("impersonation", "financial_manipulation"),
    "brand_in_email": ("impersonation",),
    "official_uses_personal_number": ("impersonation",),
    "official_uses_free_email": ("impersonation",),
    "official_asks_upi_payment": ("impersonation", "financial_manipulation"),
    "official_uses_foreign_number": ("impersonation",),
    # manipulation detector (manipulation.py)
    "scarcity": ("urgency",),
    "sympathy": ("social_engineering",),
    # conversation-level patterns (context.py)
    "slow_build": ("social_engineering",),
    "ignores_refusal": ("social_engineering",),
    "repeated_pressure": ("urgency",),
    # urgency and pressure
    "urgency": ("urgency",),
    "threat": ("urgency",),
    # links
    "disguised_link": ("suspicious_url",),
    "url_userinfo": ("suspicious_url", "impersonation"),    # the @ trick
    "homograph": ("suspicious_url", "impersonation"),       # look-alike letters
    "open_redirect": ("suspicious_url",),
    "deep_subdomains": ("suspicious_url",),
    "obfuscated_url": ("suspicious_url",),
    "brand_in_path": ("suspicious_url",),
    "new_domain": ("suspicious_url",),
    "short_link": ("suspicious_url",),
    "odd_link": ("suspicious_url",),
    "link": ("suspicious_url",),
}

PRESENT = 0.5        # evidence below this is noted but doesn't count towards a verdict
STRONG = {CRITICAL: 0.8, HIGH: 0.9}  # one category this strong is enough on its own
MIN_WORDS = 4        # fewer words than this is rarely enough to judge
WORD_RX = re.compile(r"[^\W\d_]{2,}")  # words of 2+ letters, any script

# How much each detector's findings are trusted. A threat-database hit or a
# permission read straight from an app file is near-certain; a match from the
# partial Hindi phrase list, or the uncalibrated ML model, much less so.
RELIABILITY = {"reputation": 0.98, "file": 0.95, "rule": 0.9, "url": 0.9, "payment": 0.9, "identity": 0.85,
               "context": 0.8, "lexicon": 0.75, "manipulation": 0.7, "model": 0.6}


@dataclass
class CategoryEvidence:
    category: Category
    evidence: float                     # strength of the signal this category is credited with, 0-1
    signals: list[Signal] = field(default_factory=list)
    independent: bool = True            # does it add NEW evidence, or repeat another category's?
    basis: Signal | None = None         # the signal it's credited with
    same_as: str | None = None          # if not independent: the category that already counted it

    @property
    def present(self) -> bool:
        return self.evidence >= PRESENT

    @property
    def reliability(self) -> float:
        return RELIABILITY.get(self.basis.origin if self.basis else "rule", 0.8)


@dataclass
class Chain:
    name: str
    explanation: str


@dataclass
class Assessment:
    verdict: str
    detail: str               # one line saying why this verdict
    risk_score: int           # 0-100, NOT a probability
    categories: list[CategoryEvidence]
    chains: list[Chain] = field(default_factory=list)          # known scam patterns matched
    mitigations: list[str] = field(default_factory=list)       # evidence pointing the other way
    harm: dict = field(default_factory=dict)                   # {"level", "at_stake"}


SCAM = "Likely a scam"
CAREFUL = "Be careful"
SAFE = "No obvious threat detected"
UNSURE = "Insufficient information"

SUBTITLE = {
    SCAM: "Strong evidence",
    CAREFUL: "Suspicious indicators",
    SAFE: "Low detected risk",
    UNSURE: "Cannot confidently classify",
}

# Evidence that backs up other evidence but doesn't count as a tactic itself.
# Moderately confident model output (0.75-0.9) flagged genuine bank and
# shopping alerts in testing, so it only corroborates. A very confident model
# (>= MODEL_ALONE) may raise "Be careful" on its own: on the evaluation sets
# this raised recall on real 2012 spam from 0.18 to 0.83 with no extra false
# positives (see results/metrics.md, section D).
CORROBORATING = {"scam_wording"}
MODEL_ALONE = 0.9
# A very confident model agreeing with ONE serious tactic is corroboration from a
# different method, enough for "Likely a scam" (stated as exactly that, not as two tactics).
MODEL_CONFIRMS = 0.85
OCR_UNRELIABLE = 60   # text read from a photo below this confidence (0-100) can't clear a message


# --- 1. group evidence --------------------------------------------------------------------------------------
def gather(signals: list[Signal], model_p: float | None) -> list[CategoryEvidence]:
    """Group signals by category, then credit each category with one piece of
    evidence that no earlier (more serious) category has already used.

    Within a category, repeated signs of the same tactic aren't new evidence
    (only the strongest counts). Across categories, one underlying thing (a
    single fake link, one phone number) can show several tactics, but it's
    still ONE piece of evidence: the link counts once, under its most serious
    category, and the other categories are marked as the same evidence."""
    groups: dict[str, CategoryEvidence] = {}
    for s in signals:
        for key in CATEGORY_OF.get(s.id, ()):
            ce = groups.setdefault(key, CategoryEvidence(CATEGORIES[key], 0.0))
            ce.signals.append(s)
    if model_p is not None and model_p >= 0.75:
        groups["scam_wording"] = CategoryEvidence(
            CATEGORIES["scam_wording"], 0.0,
            [Signal("model", model_p, "The wording closely resembles scam messages the model learned from.",
                    origin="model", anchor="model")])
    for ce in groups.values():
        if ce.category.key == "scam_wording":
            ce.evidence = round((model_p - 0.5) * 2, 2)
        else:
            ce.evidence = max(s.strength for s in ce.signals)
    cats = sorted(groups.values(), key=lambda c: (LEVEL_ORDER[c.category.level], -c.evidence))

    used: dict[str, str] = {}   # evidence key -> category that counted it
    for ce in cats:
        if ce.category.key in CORROBORATING:
            ce.independent, ce.basis = False, ce.signals[0]
            continue
        for s in sorted(ce.signals, key=lambda s: -s.strength):
            key = s.anchor or f"sig:{s.id}"
            if key not in used:
                used[key] = ce.category.key
                ce.basis, ce.evidence = s, s.strength
                break
        else:
            strongest = max(ce.signals, key=lambda s: s.strength)
            ce.independent, ce.basis = False, strongest
            ce.same_as = CATEGORIES[used[strongest.anchor or f"sig:{strongest.id}"]].name
    return cats


# --- 2. known scam patterns: correlated evidence that tells one story ---------------------------------------
# Each pattern is a list of requirements; a requirement is met by any of its rule IDs
# or category keys with evidence that counts. Matching a pattern doesn't add risk on
# its own; it means the pieces of evidence form a recognised attack, which makes the
# verdict more certain and explains it better.
CHAINS = [
    ("Impersonation to steal your codes", "It pretends to be an organisation and asks for codes, a PIN or an app: "
     "the classic account-takeover pattern.", [{"impersonation"}, {"credential_theft"}]),
    ("Threat-and-link phishing", "It threatens your account and points you to a look-alike or unknown link to "
     "'fix' it.", [{"threat", "urgency", "repeated_pressure"}, {"fake_brand_link", "brand_mismatch", "homograph",
                                                                "url_userinfo", "odd_link", "disguised_link"}]),
    ("Family emergency scam", "Someone claiming to be family, in sudden trouble, asking for money.",
     [{"new_number_family", "emergency_money"}, {"money_request", "emergency_money", "brand_in_payment_id"}]),
    ("Digital arrest playbook", "A fake officer, an accusation, and pressure to pay or stay on the call.",
     [{"digital_arrest"}, {"money_request", "secrecy", "threat", "official_asks_upi_payment", "emergency_money"}]),
    ("Pay-to-receive trick", "It makes paying look like receiving: approve, scan or pay first to 'get' money.",
     [{"pin_to_receive", "collect_request", "qr_receive_trick", "pay_to_receive", "sent_by_mistake",
       "tiny_verification_payment"}]),
    ("Investment grooming", "A friendly stranger builds trust, then steers you to a trading scheme.",
     [{"slow_build", "wrong_number_opener", "sympathy"}, {"fake_trading", "guaranteed_returns"}]),
    ("Task-job trap", "Easy money for simple tasks, then a deposit to 'unlock' earnings.",
     [{"easy_job", "job_task_fee"}, {"money_request", "fee_for_prize", "job_task_fee", "pay_to_receive"}]),
]


def find_chains(cats: list[CategoryEvidence]) -> list[Chain]:
    ids = {s.id for c in cats for s in c.signals if s.strength >= PRESENT}
    keys = {c.category.key for c in cats if c.present and c.independent}
    found = []
    for name, explanation, needs in CHAINS:
        if all(req & (ids | keys) for req in needs):
            # A pattern needs at least two independent pieces of evidence, unless it is a
            # single unambiguous trick (pay-to-receive).
            if len(needs) == 1 or len([c for c in cats if c.present and c.independent]) >= 2:
                found.append(Chain(name, explanation))
    return found


# --- 3. potential harm: how bad it would be if this IS a scam -----------------------------------------------
def assess_harm(cats: list[CategoryEvidence], amounts: list[float]) -> dict:
    """Severity is a separate question from likelihood: a likely scam asking for
    Rs 200 and one asking for an OTP (your whole account) need different urgency."""
    ids = {s.id for c in cats for s in c.signals if s.strength >= PRESENT}
    keys = {c.category.key for c in cats if c.present}
    top = max(amounts) if amounts else None
    money = f"Rs {top:,.0f}" if top else None
    if ids & {"apk_file", "remote_access", "apk_reads_sms", "apk_accessibility"}:
        return {"level": "Severe", "at_stake": "If you install the app or share your screen, they can read your OTPs "
                                             "and take over your bank accounts."}
    if "credential_theft" in keys:
        return {"level": "Severe", "at_stake": "If you share the code, PIN or password, they can empty your bank "
                                             "account or take over your accounts."}
    if ids & {"digital_arrest"}:
        return {"level": "Severe", "at_stake": "These scams often take people's entire savings, a little at a time."}
    if ids & {"sextortion"}:
        return {"level": "Severe", "at_stake": "Paying leads to more demands. Get help early; you've done nothing wrong."}
    if ids & {"fake_trading", "guaranteed_returns"}:
        return {"level": "Severe", "at_stake": "Investment scams take whatever you put in, and then ask for more to "
                                             "'withdraw' it."}
    if top and top >= 100_000:
        return {"level": "Severe", "at_stake": f"They're asking for {money}."}
    if "financial_manipulation" in keys or ids & {"emergency_money", "personal_details"}:
        if top and top < 10_000:
            return {"level": "Moderate", "at_stake": f"You could lose {money}, and scammers often come back for more."}
        return {"level": "Serious", "at_stake": (f"They're asking for {money}." if money else
                                                 "You could lose money.") + " Payments are very hard to get back."}
    if "impersonation" in keys:
        return {"level": "Serious", "at_stake": "A fake page or contact can trick you into giving away your login, "
                                              "card details or money."}
    if keys & {"suspicious_url", "urgency", "social_engineering"}:
        return {"level": "Moderate", "at_stake": "A suspicious link or request; it could lead to a fake page or a "
                                               "request for money later."}
    return {"level": "Low", "at_stake": ""}


# --- 4. the verdict -----------------------------------------------------------------------------------------
def risk_score(cats: list[CategoryEvidence], chains: list[Chain] | None = None) -> int:
    """Weighted INDEPENDENT evidence, scaled by how reliable each piece is. One
    piece of evidence counts once, however many categories it touches. A
    ranking of how much evidence there is, NOT a probability."""
    total = 0.0
    for c in cats:
        if c.present and c.independent:
            total += LEVEL_POINTS[c.category.level] * c.evidence * c.reliability
    # The model's opinion isn't a tactic, but it is evidence: it always adds to the amount
    # of evidence (at its lower reliability), even when it's the only thing found.
    for c in cats:
        if c.category.key in CORROBORATING:
            total += LEVEL_POINTS[MEDIUM] * c.evidence * c.reliability
    total += 10 * min(2, len(chains or []))
    return min(100, round(total))


def _too_little_text(text: str) -> bool:
    return len(WORD_RX.findall(text)) < MIN_WORDS


def decide(text: str, cats: list[CategoryEvidence], model_p: float | None,
           ocr_quality: float | None = None, chains: list[Chain] | None = None) -> tuple[str, str]:
    # Only independent evidence counts: a single fake link is one piece of evidence,
    # not "impersonation" plus "suspicious link".
    present = [c for c in cats if c.present and c.independent]
    levels = [c.category.level for c in present]
    n_serious = sum(lvl in (CRITICAL, HIGH) for lvl in levels)
    n_medium = sum(lvl == MEDIUM for lvl in levels)
    names = " + ".join(c.category.name.lower() for c in present)
    pattern = f" It matches a known scam pattern: {chains[0].name.lower()}." if chains else ""

    strong = [c for c in present if c.evidence >= STRONG.get(c.category.level, 2)]
    if strong:
        c = strong[0]
        return SCAM, f"Clear sign of {c.category.name.lower()} ({c.category.level.lower()} risk).{pattern}"
    if n_serious >= 2:
        return SCAM, f"Independent evidence from several tactics: {names}.{pattern}"
    if n_serious == 1 and n_medium >= 1:
        return SCAM, f"A serious tactic backed up by separate evidence: {names}.{pattern}"
    if chains:   # e.g. a single pay-to-receive trick
        return SCAM, f"It matches a known scam pattern: {chains[0].name.lower()}."
    if n_serious == 1 and model_p is not None and model_p >= MODEL_CONFIRMS:
        return SCAM, (f"One serious warning sign ({names}), confirmed by the ML model: the wording strongly "
                      "matches known scams.")
    if n_serious == 1:
        return CAREFUL, f"One serious warning sign ({names}) without other evidence."
    if n_medium >= 2:
        return CAREFUL, f"Several warning signs: {names}."
    if n_medium == 1:
        return CAREFUL, f"One warning sign: {names}."

    # Nothing counted. Decide whether "no threat" is justified or we just can't tell.
    if ocr_quality is not None and ocr_quality < OCR_UNRELIABLE:
        return UNSURE, "The photo was too hard to read to judge. Try a clearer screenshot or paste the text."
    from .preprocess import detect_language
    language = detect_language(text)
    if language.coverage == "none":
        return UNSURE, f"This is in {language.name}, which the checker can't read yet."
    if _too_little_text(text):
        return UNSURE, "Too little text to judge. Paste the whole message or conversation."
    weak = [c for c in cats if not c.present]
    if model_p is not None and model_p >= MODEL_ALONE:
        return CAREFUL, "No known scam tactic found, but the wording is very similar to scam messages."
    if weak and any(c.category.level != MEDIUM for c in weak):
        return UNSURE, "A faint sign of a scam tactic, not enough to judge either way."
    return SAFE, "No known scam tactics found."


def assess(text: str, signals: list[Signal], model_p: float | None, ocr_quality: float | None = None,
           mitigations: list[str] | None = None, amounts: list[float] | None = None) -> Assessment:
    cats = gather(signals, model_p)
    chains = find_chains(cats)
    verdict, detail = decide(text, cats, model_p, ocr_quality, chains)
    mitigations = list(mitigations or [])
    if mitigations and verdict in (SCAM, CAREFUL):
        detail += " Some signs point the other way (see below)."
    return Assessment(verdict, detail, risk_score(cats, chains), cats, chains, mitigations,
                      assess_harm(cats, amounts or []) if verdict != SAFE else {"level": "Low", "at_stake": ""})

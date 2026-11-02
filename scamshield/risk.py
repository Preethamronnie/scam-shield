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
    # conversation-level patterns (context.py)
    "slow_build": ("social_engineering",),
    "ignores_refusal": ("social_engineering",),
    "repeated_pressure": ("urgency",),
    # urgency and pressure
    "urgency": ("urgency",),
    "threat": ("urgency",),
    # links
    "short_link": ("suspicious_url",),
    "odd_link": ("suspicious_url",),
    "link": ("suspicious_url",),
}

PRESENT = 0.5        # evidence below this is noted but doesn't count towards a verdict
STRONG = {CRITICAL: 0.8, HIGH: 0.9}  # one category this strong is enough on its own
MIN_WORDS = 4        # fewer words than this is rarely enough to judge
WORD_RX = re.compile(r"[^\W\d_]{2,}")  # words of 2+ letters, any script


@dataclass
class CategoryEvidence:
    category: Category
    evidence: float                     # strongest signal in the category, 0-1
    signals: list[Signal] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return self.evidence >= PRESENT


@dataclass
class Assessment:
    verdict: str
    detail: str               # one line saying why this verdict
    risk_score: int           # 0-100, NOT a probability
    categories: list[CategoryEvidence]


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


def gather(signals: list[Signal], model_p: float | None) -> list[CategoryEvidence]:
    """Group signals by category. Evidence within a category is the strongest
    signal, not the sum: repeated signs of the same tactic aren't new evidence."""
    groups: dict[str, CategoryEvidence] = {}
    for s in signals:
        for key in CATEGORY_OF.get(s.id, ()):
            ce = groups.setdefault(key, CategoryEvidence(CATEGORIES[key], 0.0))
            ce.signals.append(s)
            ce.evidence = max(ce.evidence, s.strength)
    # The ML model is one more, medium-level piece of evidence, and only when
    # it is fairly sure. Its output is uncalibrated, so on its own it can reach
    # "Be careful" at most (see MODEL_ALONE in decide).
    if model_p is not None and model_p >= 0.75:
        groups["scam_wording"] = CategoryEvidence(
            CATEGORIES["scam_wording"], round((model_p - 0.5) * 2, 2),
            [Signal("model", model_p, "The wording closely resembles scam messages the model learned from.")])
    return sorted(groups.values(), key=lambda c: (LEVEL_ORDER[c.category.level], -c.evidence))


def risk_score(cats: list[CategoryEvidence]) -> int:
    return min(100, round(sum(LEVEL_POINTS[c.category.level] * c.evidence for c in cats)))


def _too_little_text(text: str) -> bool:
    words = WORD_RX.findall(text)
    return len(words) < MIN_WORDS


def _mostly_unsupported_script(text: str) -> bool:
    """The model and rules read English (and romanised Hindi). Text mostly in
    another script can't be judged reliably without the LLM."""
    letters = [ch for ch in text if ch.isalpha()]
    return bool(letters) and sum(ch.isascii() for ch in letters) / len(letters) < 0.5


# Evidence that backs up other evidence but doesn't count as a tactic itself.
# Moderately confident model output (0.75-0.9) flagged genuine bank and
# shopping alerts in testing, so it only corroborates. A very confident model
# (>= MODEL_ALONE) may raise "Be careful" on its own: on the evaluation sets
# this raised recall on real 2012 spam from 0.18 to 0.83 with no extra false
# positives (see results/metrics.md, section D).
CORROBORATING = {"scam_wording"}
MODEL_ALONE = 0.9


def decide(text: str, cats: list[CategoryEvidence], model_p: float | None) -> tuple[str, str]:
    present = [c for c in cats if c.present]
    independent = [c for c in present if c.category.key not in CORROBORATING]
    if not independent:
        present = []
    levels = [c.category.level for c in present]
    n_serious = sum(lvl in (CRITICAL, HIGH) for lvl in levels)
    n_medium = sum(lvl == MEDIUM for lvl in levels)
    names = " + ".join(c.category.name.lower() for c in present)

    strong = [c for c in present if c.evidence >= STRONG.get(c.category.level, 2)]
    if strong:
        c = strong[0]
        return SCAM, f"Clear sign of {c.category.name.lower()} ({c.category.level.lower()} risk)."
    if n_serious >= 2:
        return SCAM, f"Independent evidence from several tactics: {names}."
    if n_serious == 1 and n_medium >= 1:
        return SCAM, f"A serious tactic backed up by other evidence: {names}."
    if n_serious == 1:
        return CAREFUL, f"One serious warning sign ({names}) without other evidence."
    if n_medium >= 2:
        return CAREFUL, f"Several warning signs: {names}."
    if n_medium == 1:
        return CAREFUL, f"One warning sign: {names}."

    # Nothing present. Decide whether "no threat" is justified or we just can't tell.
    if _mostly_unsupported_script(text):
        return UNSURE, "Most of this text is in a script the checker can't read reliably yet."
    if _too_little_text(text):
        return UNSURE, "Too little text to judge. Paste the whole message or conversation."
    weak = [c for c in cats if not c.present]
    if model_p is not None and model_p >= MODEL_ALONE:
        return CAREFUL, "No known scam tactic found, but the wording is very similar to scam messages."
    if weak and any(c.category.level != MEDIUM for c in weak):
        return UNSURE, "A faint sign of a scam tactic, not enough to judge either way."
    return SAFE, "No known scam tactics found."


def assess(text: str, signals: list[Signal], model_p: float | None) -> Assessment:
    cats = gather(signals, model_p)
    verdict, detail = decide(text, cats, model_p)
    return Assessment(verdict, detail, risk_score(cats), cats)

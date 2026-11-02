"""Combines the ML model and the rules into one plain-language verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import model as ml
from .signals import Signal, find_signals, rule_score

SCAM, CAREFUL, SAFE = "Likely a scam", "Be careful", "Looks safe"

ADVICE = {
    SCAM: [
        "Don't click any links, call back, or reply.",
        "Never share OTPs, PINs, passwords or card details.",
        "Don't send money. If it claims to be your bank or family, contact them using a number you already know.",
        "Block the sender and report it (in India: cybercrime.gov.in or call 1930).",
    ],
    CAREFUL: [
        "Don't act in a hurry. Real organisations give you time.",
        "Check with the company using their official app, website, or a number you already have.",
        "Ask a family member or friend before doing anything it asks.",
    ],
    SAFE: [
        "Nothing suspicious stands out, but stay alert.",
        "If it later asks for money, codes or personal details, check again.",
    ],
}


@dataclass
class Result:
    verdict: str
    score: float              # 0-1, higher = more likely a scam
    model_score: float | None
    rule_score: float
    signals: list[Signal] = field(default_factory=list)
    suspicious_words: list[str] = field(default_factory=list)

    @property
    def advice(self) -> list[str]:
        return ADVICE[self.verdict]


def combine(model_p: float | None, rules_p: float, signals: list[Signal]) -> float:
    if model_p is None:
        score = rules_p
    else:
        score = 0.5 * model_p + 0.5 * rules_p
    # One very strong red flag (asking for an OTP, PIN, remote access, fee
    # for a prize) is enough on its own, whatever the model thinks.
    if any(s.weight >= 0.9 for s in signals):
        score = max(score, 0.8)
    # Several independent red flags together are strong evidence too, even
    # when the message is worded like normal chat ("Hi Mum, new number...").
    elif rules_p >= 0.85:
        score = max(score, 0.7)
    return score


def verdict_for(score: float) -> str:
    if score >= 0.65:
        return SCAM
    if score >= 0.35:
        return CAREFUL
    return SAFE


def analyze(text: str) -> Result:
    text = (text or "").strip()
    if not text:
        raise ValueError("Paste a message to check.")
    signals = find_signals(text)
    r = rule_score(signals)
    pipe = ml.load()
    m = float(pipe.predict_proba([text])[0, 1]) if pipe is not None else None
    words = ml.top_words(pipe, text) if pipe is not None else []
    score = combine(m, r, signals)
    return Result(verdict_for(score), score, m, r, signals, words)

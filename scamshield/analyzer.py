"""Runs the full pipeline:

  message / photo text / conversation
    -> preprocessing (normalise, detect language, split conversation)
    -> ML classifier + rule engine + URL intelligence + context engine
    -> risk aggregation + confidence assessment
    -> structured evidence report (verdict, evidence, recommended actions)
    -> optional LLM explanation of that report (explain.py)

No step after the risk aggregation can change the verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import entities, evidence, model as ml, reputation
from .context import analyze_conversation
from .links import analyze_urls
from .preprocess import normalize, detect_language, parse_conversation
from .risk import CAREFUL, SAFE, SCAM, SUBTITLE, UNSURE, WORD_RX, CategoryEvidence, assess
from .signals import Signal, find_signals

__all__ = ["analyze", "Result", "SCAM", "CAREFUL", "SAFE", "UNSURE"]

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
        "Nothing suspicious stands out, but no checker catches everything.",
        "If it later asks for money, codes or personal details, check again.",
    ],
    UNSURE: [
        "Paste the whole message or conversation, including any links, and check again.",
        "Until you're sure, don't send money, share codes or click links from this sender.",
        "If it's from someone you know, confirm by calling a number you already have.",
    ],
}


@dataclass
class Result:
    verdict: str
    detail: str
    risk_score: int                    # 0-100 weighted evidence. NOT a probability.
    categories: list[CategoryEvidence]
    model_score: float | None          # raw, uncalibrated model output
    signals: list[Signal] = field(default_factory=list)
    suspicious_words: list[str] = field(default_factory=list)
    report: evidence.Report | None = None
    text: str = ""                     # the normalised text that was analysed

    @property
    def subtitle(self) -> str:
        return SUBTITLE[self.verdict]

    @property
    def advice(self) -> list[str]:
        return self.report.recommended_actions if self.report else ADVICE[self.verdict]


_AUTO = object()


def analyze(text: str, source: str = "text", model_p=_AUTO, online: bool = False) -> Result:
    """`source` is "text" or "photo" (text read by OCR). Conversations are detected automatically.
    `model_p` overrides the ML model's output (None = rules only); used by the evaluation
    so each message can be scored by a cross-validated model."""
    text = normalize(text)
    if not text:
        raise ValueError("Paste a message to check.")
    language = detect_language(text)

    # Rule engine + context engine.
    turns = parse_conversation(text)
    conversation = None
    if turns:
        conv = analyze_conversation(turns, online)
        signals = sorted(conv.signals, key=lambda s: s.strength, reverse=True)
        their_text = "\n".join(t.text for t in turns if t.speaker != conv.user)
        conversation = conv.to_dict()
        source = "conversation from photo" if source == "photo" else "conversation"
    else:
        signals = find_signals(text, online)
        their_text = text

    # ML classifier.
    pipe = ml.load() if model_p is _AUTO else None
    if model_p is _AUTO:
        model_p = float(pipe.predict_proba([their_text])[0, 1]) if pipe is not None else None
    words = ml.top_words(pipe, their_text) if pipe is not None else []

    # Risk aggregation.
    a = assess(their_text, signals, model_p)

    # Structured evidence.
    urls = analyze_urls(their_text, online)
    phones = entities.find_phones(their_text)
    orgs = entities.find_organisations(their_text)
    n_words = len(WORD_RX.findall(their_text))
    confidence, conf_reasons = evidence.assess_confidence(a.verdict, a.categories, language, n_words, source, model_p)
    report = evidence.Report(
        verdict=a.verdict, detail=a.detail, risk_score=a.risk_score,
        confidence=confidence, confidence_reasons=conf_reasons,
        scam_types=evidence.scam_types(signals) if a.verdict in (SCAM, CAREFUL) else [],
        categories=a.categories,
        suspicious_phrases=evidence.suspicious_phrases(a.categories),
        urls=urls, phone_numbers=phones,
        payment_ids=entities.find_payment_ids(their_text), emails=entities.find_emails(their_text),
        claimed_organisations=orgs,
        impersonated_organisation=evidence.impersonated(a.verdict, a.categories, urls, orgs),
        missing_information=evidence.missing_information(
            a.verdict, source, n_words, language, urls, phones, orgs, their_text, online and reputation.enabled()),
        recommended_actions=evidence.recommended_actions(a.verdict, ADVICE[a.verdict], a.categories, signals),
        language=language, source=source, conversation=conversation,
        model_output=model_p, model_words=words,
    )
    return Result(a.verdict, a.detail, a.risk_score, a.categories, model_p, signals, words, report, text)


# --- two-stage pipeline -----------------------------------------------------------------------------
def escalation_reasons(r: Result) -> list[str]:
    """Why stage 1 isn't enough on its own. Empty = stage 1 is conclusive."""
    reasons = []
    if r.verdict in (UNSURE, CAREFUL):
        reasons.append(f"local verdict was '{r.verdict}'")
    elif r.report and r.report.confidence == "Low":
        reasons.append("local confidence was low")
    unchecked = [u for u in (r.report.urls if r.report else []) if u.assessment != "official"]
    if unchecked and not (r.verdict == SCAM and r.report.confidence == "High"):
        reasons.append(f"{len(unchecked)} link(s) not yet checked against a blocklist")
    return reasons


def check(text: str, source: str = "text", allow_online: bool = False) -> Result:
    """The app's entry point. Stage 1 (rules, ML model, URL and context
    analysis) runs locally in milliseconds and decides most messages.
    Stage 2 (online link reputation) runs only when stage 1 is uncertain or
    has unchecked links, and only if the user allowed online services. The
    LLM is never part of this: it's called separately, on request."""
    import time

    from .safety import limit_text

    text, truncated = limit_text(text)
    t0 = time.perf_counter()
    result = analyze(text, source)
    stages = [{"stage": "local analysis", "ms": round((time.perf_counter() - t0) * 1000, 1)}]
    reasons = escalation_reasons(result)
    if reasons and allow_online and reputation.enabled():
        t1 = time.perf_counter()
        result = analyze(text, source, online=True)
        stages.append({"stage": "online link reputation", "ms": round((time.perf_counter() - t1) * 1000, 1)})
    result.report.analysis = {
        "stages": stages,
        "escalation_needed_because": reasons,
        "online_services_allowed": allow_online,
        "input_truncated": truncated,
    }
    return result

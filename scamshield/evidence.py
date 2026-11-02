"""The structured evidence report: everything the detection layers found.

This is the single source of truth for the verdict's explanation. The app
displays it, the user can download it, and the optional LLM may only turn it
into plain language. Because the LLM explains these detection results rather
than analysing the message itself, it has far less room to make things up.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .entities import Phone
from .links import UrlInfo
from .preprocess import Language
from .risk import CAREFUL, LEVEL_POINTS, SAFE, SCAM, SUBTITLE, UNSURE, CategoryEvidence

# Named scam types, from the rule that detected them. Order = display priority.
SCAM_TYPES = {
    "sextortion": "Sextortion",
    "prompt_injection": "Attempt to trick AI scam checkers",
    "digital_arrest": "Digital arrest scam",
    "blocklisted_link": "Known phishing or malware link",
    "remote_access": "Remote-access (screen-sharing) scam",
    "apk_file": "Malicious app (APK) scam",
    "pin_to_receive": "UPI 'enter PIN to receive money' scam",
    "asks_secret": "OTP / PIN theft",
    "sim_swap": "SIM swap scam",
    "login_bait": "Account phishing",
    "slow_build": "Slow-build (pig-butchering) scam",
    "new_number_family": "Family emergency scam ('new number')",
    "emergency_money": "Family emergency scam",
    "fake_army": "Fake army officer (rental / marketplace) scam",
    "fake_trading": "Investment / trading scam",
    "guaranteed_returns": "Investment / trading scam",
    "job_task_fee": "Task / job scam",
    "easy_job": "Task / job scam",
    "sent_by_mistake": "'Sent by mistake' refund scam",
    "fee_for_prize": "Advance-fee scam",
    "prize": "Prize / lottery scam",
    "reward_points": "Reward points scam",
    "fine_or_toll": "Fake fine or toll",
    "govt_scheme": "Fake government scheme",
    "customer_care_callback": "Fake customer care",
    "fake_brand_link": "Phishing link",
    "brand_mismatch": "Phishing link",
    "personal_details": "Identity theft attempt",
    "wrong_number_opener": "'Wrong number' opener",
}

# Specific actions, on top of the general advice for the verdict.
ACTIONS = {
    "credential_theft": "If you already shared an OTP, PIN or password, call your bank's official number now "
                        "to block your account or card, then report it at cybercrime.gov.in or 1930.",
    "apk_file": "If you installed an app from this message, turn off mobile data, uninstall the app and "
                "contact your bank from a different phone if you can.",
    "remote_access": "If you installed a screen-sharing app (AnyDesk, TeamViewer), uninstall it and change "
                     "your banking passwords from another device.",
    "digital_arrest": "Police, CBI, customs and other agencies never arrest anyone on a video call or ask for "
                      "money to clear your name. Hang up and call 1930.",
    "sextortion": "Don't pay and don't reply. Save screenshots, report the account and report at "
                  "cybercrime.gov.in. If you're under 18, tell a parent or teacher you trust.",
    "financial_manipulation": "If you already paid, report it at 1930 straight away: acting within hours "
                              "gives the best chance of freezing the money.",
    "social_engineering": "Call the person on a number you already have, or ask a question only they "
                          "would know, before you do anything.",
    "suspicious_url": "Don't open the link. If you already did, don't enter any details there.",
}


@dataclass
class Report:
    verdict: str
    detail: str
    risk_score: int
    confidence: str
    confidence_reasons: list[str]
    scam_types: list[str]
    categories: list[CategoryEvidence]
    suspicious_phrases: list[dict]
    urls: list[UrlInfo]
    phone_numbers: list[Phone]
    payment_ids: list[str]
    emails: list[str]
    claimed_organisations: list[str]
    impersonated_organisation: str | None
    missing_information: list[str]
    recommended_actions: list[str]
    language: Language
    source: str                        # text | photo | conversation | conversation from photo
    conversation: dict | None = None
    model_output: float | None = None  # uncalibrated; for transparency only
    model_words: list[str] = field(default_factory=list)
    analysis: dict = field(default_factory=dict)   # stages run, timings, why escalated

    @property
    def subtitle(self) -> str:
        return SUBTITLE[self.verdict]

    def to_dict(self) -> dict:
        """JSON-ready evidence. This (not the raw message) is what the LLM sees."""
        return {
            "verdict": self.verdict,
            "verdict_meaning": self.subtitle,
            "why_this_verdict": self.detail,
            "risk_score": {"value": self.risk_score, "out_of": 100,
                           "meaning": "Weighted amount of scam evidence found. Not a probability."},
            "confidence": {"level": self.confidence, "reasons": self.confidence_reasons},
            "detected_scam_types": self.scam_types,
            "evidence_by_category": [
                {"category": c.category.name, "risk_level": c.category.level,
                 "evidence_strength": round(c.evidence, 2),
                 "risk_points": round(LEVEL_POINTS[c.category.level] * c.evidence),
                 "counts_towards_verdict": c.present,
                 "findings": list(dict.fromkeys(s.reason for s in c.signals))}
                for c in self.categories],
            "suspicious_phrases": self.suspicious_phrases,
            "links": [u.to_dict() for u in self.urls],
            "phone_numbers": [p.to_dict() for p in self.phone_numbers],
            "payment_ids": self.payment_ids,
            "emails": self.emails,
            "claims_to_be_from": self.claimed_organisations,
            "impersonated_organisation": self.impersonated_organisation,
            "missing_information": self.missing_information,
            "recommended_actions": self.recommended_actions,
            "language": self.language.to_dict(),
            "input_type": self.source,
            "conversation": self.conversation,
            "analysis": self.analysis,
        }


# --- builders ---------------------------------------------------------------------------
def scam_types(signals) -> list[str]:
    """Named scam types, the one with the strongest evidence first."""
    order = list(SCAM_TYPES)
    found = sorted((s for s in signals if s.id in SCAM_TYPES),
                   key=lambda s: (-s.strength, order.index(s.id)))
    return list(dict.fromkeys(SCAM_TYPES[s.id] for s in found))


def suspicious_phrases(categories: list[CategoryEvidence]) -> list[dict]:
    out, seen = [], set()
    for c in categories:
        for s in c.signals:
            if s.phrase and s.phrase.lower() not in seen and s.id != "model":
                seen.add(s.phrase.lower())
                out.append({"phrase": s.phrase, "tactic": c.category.name, "why": s.reason})
    return out[:8]


def impersonated(verdict: str, categories: list[CategoryEvidence], urls: list[UrlInfo],
                 orgs: list[str]) -> str | None:
    if verdict not in (SCAM, CAREFUL):
        return None
    for u in urls:
        if u.assessment in ("impersonation", "brand_mismatch") and u.claims_to_be:
            match = next((o for o in orgs if u.claims_to_be.lower() in o.lower()), None)
            return match or u.claims_to_be
    keys = {c.category.key for c in categories if c.present}
    if keys & {"impersonation", "credential_theft", "financial_manipulation"} and orgs:
        return orgs[0]
    return None


def assess_confidence(verdict: str, categories: list[CategoryEvidence], language: Language,
                      words: int, source: str, model_p: float | None) -> tuple[str, list[str]]:
    """How sure the system is about its verdict. Separate from the risk score:
    a message can have a modest risk score and still be confidently judged."""
    present = [c for c in categories if c.present and c.category.key != "scam_wording"]
    independent = len(present)
    reasons: list[str] = []
    if verdict == UNSURE:
        level = "Low"
        reasons.append("The evidence doesn't support a confident call either way.")
    elif verdict == SCAM:
        if independent >= 2:
            level = "High"
            reasons.append(f"{independent} independent kinds of evidence point the same way.")
        else:
            level = "Medium"
            reasons.append("Based on one clear warning sign rather than several.")
    elif verdict == CAREFUL:
        level = "Medium" if independent else "Low"
        reasons.append("Some warning signs, but not enough for a firm conclusion." if independent
                       else "Based only on the message's wording, not on a known scam tactic.")
    else:  # SAFE
        if words >= 12 and (model_p is None or model_p < 0.3):
            level = "High"
            reasons.append("Enough text, no scam tactics found, and the wording isn't scam-like.")
        else:
            level = "Medium"
            reasons.append("No scam tactics found, but the message is short or the wording is somewhat ambiguous.")
    if model_p is not None and verdict == SCAM and model_p < 0.3:
        reasons.append("The ML model disagrees: the wording itself looks ordinary.")
        level = {"High": "Medium", "Medium": "Low"}.get(level, level)
    if model_p is not None and verdict == SAFE and model_p >= 0.75:
        reasons.append("The ML model finds the wording somewhat scam-like.")
        level = "Medium" if level == "High" else level
    if "photo" in source:
        reasons.append("The text was read from a photo, so some words may have been misread.")
        level = {"High": "Medium", "Medium": "Low"}.get(level, level)
    if language.name.startswith("Hinglish"):
        reasons.append("The message is partly in romanised Hindi, which the detector understands less well.")
        level = {"High": "Medium"}.get(level, level)
    return level, reasons


def missing_information(verdict: str, source: str, words: int, language: Language, urls: list[UrlInfo],
                        phones: list[Phone], orgs: list[str], text: str, reputation_on: bool) -> list[str]:
    out: list[str] = []
    if not language.supported:
        out.append(f"Most of the text is in {language.name}. Without the AI explanation turned on, only English "
                   "and romanised Hindi are analysed, so the message couldn't be checked properly.")
    if words < 6:
        out.append("The message is very short. The full message, or what was said before and after, would help.")
    if not source.startswith("conversation") and verdict in (UNSURE, CAREFUL):
        out.append("Only one message was checked. The rest of the conversation would show what they ask for next.")
    if any(u.assessment == "shortened" for u in urls):
        out.append("Where the shortened link really leads. Don't open it to find out.")
    if urls and not reputation_on and any(u.assessment != "official" for u in urls):
        out.append("The links weren't checked against an online blocklist (online checks are off or not set up).")
    if orgs and not phones and not urls and verdict in (UNSURE, CAREFUL):
        out.append(f"How to verify the sender. Contact {orgs[0]} through their official app, website or helpline.")
    if "photo" in source:
        out.append("The text was read from a photo. Check the 'Text found' panel matches the real message.")
    if "call" in text.lower() and verdict != SAFE and not phones:
        out.append("If this was a phone call, the number that called you would help.")
    return out


def recommended_actions(verdict: str, advice: list[str], categories: list[CategoryEvidence], signals) -> list[str]:
    ids = {s.id for s in signals}
    keys = {c.category.key for c in categories if c.present}
    specific = [ACTIONS[k] for k in ("digital_arrest", "sextortion", "apk_file", "remote_access") if k in ids]
    if verdict in (SCAM, CAREFUL):
        specific += [ACTIONS[k] for k in ("credential_theft", "financial_manipulation", "social_engineering",
                                          "suspicious_url") if k in keys]
    return list(dict.fromkeys(advice + specific))[:7]


def template_explanation(r: Report) -> str:
    """A plain-English summary built only from the evidence. Used when no LLM is
    configured, and as the fallback if the LLM's answer fails the grounding check."""
    parts = []
    if r.verdict == SCAM:
        kind = f" ({r.scam_types[0].lower()})" if r.scam_types else ""
        who = f", pretending to be {r.impersonated_organisation}" if r.impersonated_organisation else ""
        parts.append(f"This looks like a scam{kind}{who}.")
    elif r.verdict == CAREFUL:
        parts.append("This message has warning signs, so treat it with care.")
    elif r.verdict == SAFE:
        parts.append("We didn't find any known scam tactics in this message.")
    else:
        parts.append("We can't tell for sure whether this is a scam.")
    reasons = [f for c in r.categories if c.present and c.category.key != "scam_wording"
               for f in dict.fromkeys(s.reason for s in c.signals)]
    if reasons:
        parts.append(" ".join(reasons[:3]))
    elif r.verdict == UNSURE and r.missing_information:
        parts.append("What would help: " + r.missing_information[0][0].lower() + r.missing_information[0][1:])
    if r.recommended_actions:
        parts.append("What to do: " + r.recommended_actions[0])
    return " ".join(parts)

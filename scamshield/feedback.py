"""User feedback on verdicts, collected for human review.

Users can report:
  * correct            - correctly identified (scam or not)
  * wrong_explanation  - right that it's a scam, but the wrong type or reasons
  * false_alarm        - a legitimate message was flagged
  * missed_scam        - a scam wasn't detected

Safeguards against poisoning (attackers flooding the system with fake reports
to teach it that their scams are safe):
  * Feedback is NEVER used for training automatically. It goes into a pending
    queue; a reviewer approves or rejects each item (scripts/review_feedback.py),
    and only approved items are written to data/reviewed_examples.csv, which
    training reads. Retraining must then pass the evaluation before deploying.
  * By default only anonymised metadata is stored (the report type plus the
    verdict and rule names). The message text is stored only if the user ticks
    a box to share it, and even then personal details are masked first.
  * Each session can send a limited number of reports, duplicates are ignored,
    and reports that would *weaken* detection (e.g. "false alarm" on a message
    the system was very sure about) are marked for extra scrutiny.

Storage is a local JSON-lines file (SCAMSHIELD_FEEDBACK_DIR, default
data/feedback). On Streamlit Cloud this disk is temporary; a real deployment
should use a database.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .privacy import Masker

KINDS = {
    "correct": "✅ Correct",
    "wrong_explanation": "🤔 Right that it's a scam, but the explanation is wrong",
    "false_alarm": "🙅 This is a genuine message, it shouldn't be flagged",
    "missed_scam": "🚨 This is a scam and it wasn't caught",
}
MAX_PER_SESSION = 10


def feedback_dir() -> Path:
    return Path(os.getenv("SCAMSHIELD_FEEDBACK_DIR", Path(__file__).resolve().parents[1] / "data" / "feedback"))


def build_record(kind: str, result, share_text: bool, comment: str = "") -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown feedback kind: {kind}")
    rep = result.report
    record = {
        "received": int(time.time()),
        "kind": kind,
        "verdict": result.verdict,
        "confidence": rep.confidence,
        "rules": sorted({s.id for s in result.signals}),
        "scam_types": rep.scam_types,
        "input_type": rep.source,
        "language": rep.language.name,
        # Reports that ask the system to be *less* suspicious of something it was
        # sure about are exactly what a poisoning attack would look like.
        "needs_extra_scrutiny": kind == "false_alarm" and result.verdict == "Likely a scam"
                                and rep.confidence == "High",
        "status": "pending",
    }
    if share_text:
        masker = Masker()
        record["text_masked"] = masker.mask(result.text)[:5000]
        record["comment_masked"] = masker.mask(comment)[:500] if comment else ""
    # Hash of the text (not stored as text) to drop duplicate reports.
    record["dedupe_key"] = hashlib.sha256(f"{kind}|{result.text}".encode()).hexdigest()[:16]
    return record


def submit(record: dict, session_count: int) -> str:
    """Store a report in the pending queue. Returns a message for the user."""
    if session_count >= MAX_PER_SESSION:
        return "Thanks! You've sent the maximum number of reports for this visit."
    folder = feedback_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "pending.jsonl"
    if path.exists():
        with path.open(encoding="utf-8") as f:
            if any(json.loads(line).get("dedupe_key") == record["dedupe_key"] for line in f if line.strip()):
                return "Thanks! This report was already received."
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return "Thank you! A person will review this before it's used to improve the checker."

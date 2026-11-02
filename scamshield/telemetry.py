"""Anonymised detection metadata.

Useful for spotting problems (which rules fire most, how often stage 2 runs,
how long checks take) without recording anything about the message itself.

Logged:     verdict, confidence, risk score, rule and category names, scam
            types, language, input type, size bucket, counts of links and
            phone numbers, stage timings, model version, whether online
            services or the LLM were used.
Never:      message text, quoted phrases, links, domains, phone numbers,
            payment IDs, names, organisations, images or OCR text.

Written as one JSON line per check to the standard log (shown in Streamlit
Cloud's logs). Set SCAMSHIELD_LOG=off to disable.
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("scamshield.telemetry")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False


def _bucket(n: int) -> str:
    for limit in (100, 500, 2000, 10000):
        if n <= limit:
            return f"<={limit}"
    return ">10000"


def _model_version() -> str | None:
    from .model import CARD_PATH
    try:
        return json.loads(CARD_PATH.read_text(encoding="utf-8"))["sha256"][:12]
    except Exception:
        return None


def check_event(result, n_chars: int, llm_used: bool = False) -> dict:
    """The metadata for one check. Separate from logging so it can be tested."""
    r = result.report
    return {
        "event": "check",
        "verdict": result.verdict,
        "confidence": r.confidence,
        "risk_score": result.risk_score,
        "categories": sorted(c.category.key for c in result.categories if c.present),
        "rules": sorted({s.id for s in result.signals}),
        "scam_types": r.scam_types,
        "language": r.language.name,
        "input_type": r.source,
        "chars": _bucket(n_chars),
        "n_links": len(r.urls),
        "n_phone_numbers": len(r.phone_numbers),
        "stages": [s["stage"] for s in r.analysis.get("stages", [])],
        "ms": {s["stage"]: s["ms"] for s in r.analysis.get("stages", [])},
        "online_allowed": r.analysis.get("online_services_allowed", False),
        "llm_used": llm_used,
        "model": _model_version(),
    }


def emit(event: dict) -> None:
    if os.getenv("SCAMSHIELD_LOG", "on").lower() in ("off", "0", "false", "no"):
        return
    log.info(json.dumps(event, ensure_ascii=False))

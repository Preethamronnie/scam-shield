"""Evaluates the model, the rules and the full system.

Reports, for every system: precision, recall, false positive rate (FPR),
false negative rate (FNR), F1, PR-AUC and, for the ML model, calibration
(Brier score, expected calibration error and a reliability table).

Both error types are tracked separately on purpose:
  * a missed scam (false negative) can cost someone their savings;
  * a genuine OTP or bank alert flagged as a scam (false positive) teaches
    people to ignore the warnings.
The priority is fewer false negatives without excessive false positives, so
the report highlights dangerous misses (scam -> "No obvious threat detected")
and trust-damaging false alarms (genuine alert -> "Likely a scam").

Test sets are small, so rates come with 95% Wilson confidence intervals.

Experiments
  A. ML model on its own.
  B. Full system on modern messages (model scored by 5-fold cross-validation).
  C. Full system on 2012 SMS held-out messages: a larger set of *real*
     legitimate messages for measuring false positives.

Writes results/metrics.md.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.model_selection import StratifiedKFold, train_test_split

from scamshield import analyze, model as ml
from scamshield.data import load_modern, load_sms
from scamshield.preprocess import parse_conversation, user_speaker
from scamshield.risk import CAREFUL, SAFE, SCAM, UNSURE
from scripts.train import MODERN_WEIGHT

SEED = 42
VERDICTS = [SCAM, CAREFUL, UNSURE, SAFE]
# Genuine messages whose false alarms hurt trust most: OTPs, bank and
# payment alerts, official links, bills.
TRUST_CRITICAL = {"otp", "bank", "official_link", "challan", "telecom", "utility", "govt", "delivery"}


# --- metric helpers -----------------------------------------------------------
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion k/n (works for k=0 and k=n)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - r) / d), min(1.0, (c + r) / d))


def rate(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k / n:.2f} ({lo:.2f}-{hi:.2f})"


def confusion(y, flagged) -> dict:
    y, f = np.asarray(y).astype(bool), np.asarray(flagged).astype(bool)
    return {"tp": int((y & f).sum()), "fp": int((~y & f).sum()),
            "fn": int((y & ~f).sum()), "tn": int((~y & ~f).sum())}


def metric_row(y, flagged) -> list[str]:
    c = confusion(y, flagged)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return [rate(tp, tp + fp), rate(tp, tp + fn), rate(fp, fp + tn), rate(fn, fn + tp), f"{f1:.2f}",
            f"{tp}/{fp}/{fn}/{tn}"]


METRIC_HEAD = "Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN"


def ece(y, p, bins: int = 10) -> float:
    """Expected calibration error: average gap between predicted probability and observed frequency."""
    y, p = np.asarray(y), np.asarray(p)
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
        m = (p >= lo) & ((p < hi) if i < bins - 1 else (p <= hi))
        if m.any():
            total += m.mean() * abs(p[m].mean() - y[m].mean())
    return total


def reliability(y, p, bins: int = 5) -> list[str]:
    y, p = np.asarray(y), np.asarray(p)
    edges = np.linspace(0, 1, bins + 1)
    rows = ["| Predicted probability | Messages | Mean predicted | Observed scam rate |", "|---|---|---|---|"]
    for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
        m = (p >= lo) & ((p < hi) if i < bins - 1 else (p <= hi))
        if m.any():
            rows.append(f"| {lo:.1f}-{hi:.1f} | {m.sum()} | {p[m].mean():.2f} | {y[m].mean():.2f} |")
    return rows


# --- report sections ------------------------------------------------------------
def system_section(title: str, texts, y, model_p, groups=None, note: str = "") -> list[str]:
    y = np.asarray(y)
    # The full pipeline (preprocessing, rules, URL checks, context engine, risk aggregation).
    res = [analyze(t, model_p=float(p)) for t, p in zip(texts, model_p)]
    rules = [analyze(t, model_p=None) for t in texts]
    out = [f"## {title}", ""]
    if note:
        out += [note, ""]

    out += ["**Verdicts**", "", "| System | True label | " + " | ".join(VERDICTS) + " |",
            "|---|---|" + "---|" * len(VERDICTS)]
    for name, rs in (("Rules only", rules), ("Full system", res)):
        v = np.array([r.verdict for r in rs])
        for label, m in (("Scam", y == 1), ("Legitimate", y == 0)):
            out.append(f"| {name} | {label} ({m.sum()}) | " + " | ".join(str(int((v[m] == x).sum())) for x in VERDICTS) + " |")

    out += ["", "**Metrics** (95% confidence intervals in brackets). Two operating points: *strict* counts only "
            "\"Likely a scam\" as flagged, *cautious* also counts \"Be careful\". \"Insufficient information\" "
            "counts as not flagged, so an undecided scam is a false negative.", "",
            f"| System | Flagged when | {METRIC_HEAD} | PR-AUC |", "|---|---|---|---|---|---|---|---|---|"]
    for name, rs in (("Rules only", rules), ("Full system", res)):
        v = np.array([r.verdict for r in rs])
        ap = average_precision_score(y, [r.risk_score for r in rs])
        for op, flagged in (("strict", v == SCAM), ("cautious", np.isin(v, [SCAM, CAREFUL]))):
            out.append(f"| {name} | {op} | " + " | ".join(metric_row(y, flagged)) + f" | {ap:.3f} |")
    out += ["", f"PR-AUC uses the risk score as a ranking. A random ranking would score {y.mean():.3f} "
            "(the share of scams in this set).", ""]

    v = np.array([r.verdict for r in res])
    dangerous = (y == 1) & (v == SAFE)
    out += ["**The two errors that matter most** (full system)", "",
            f"- Dangerous misses, scams labelled \"No obvious threat detected\": "
            f"{dangerous.sum()} of {(y == 1).sum()} scams, rate {rate(int(dangerous.sum()), int((y == 1).sum()))}",
            f"- Scams left as \"Insufficient information\": {int(((y == 1) & (v == UNSURE)).sum())}"]
    if groups is not None:
        tc = (y == 0) & np.isin(np.asarray(groups), list(TRUST_CRITICAL))
        hard = tc & (v == SCAM)
        soft = tc & (v == CAREFUL)
        out += [f"- Trust-damaging false alarms, genuine OTP / bank / payment / official-link messages labelled "
                f"\"Likely a scam\": {hard.sum()} of {tc.sum()}, rate {rate(int(hard.sum()), int(tc.sum()))}",
                f"- The same messages labelled \"Be careful\": {soft.sum()} of {tc.sum()}"]
    else:
        fa = (y == 0) & (v == SCAM)
        out += [f"- Legitimate messages labelled \"Likely a scam\": {fa.sum()} of {(y == 0).sum()}, "
                f"rate {rate(int(fa.sum()), int((y == 0).sum()))}"]

    errs = [(t, lab, r) for t, lab, r in zip(texts, y, res)
            if (lab == 1 and r.verdict in (SAFE, UNSURE)) or (lab == 0 and r.verdict in (SCAM, CAREFUL))]
    if errs:
        out += ["", "Errors and undecided scams (full system):", ""]
        for t, lab, r in errs[:40]:
            kind = "MISSED" if lab == 1 else "FALSE ALARM"
            out.append(f"- {kind} ({r.verdict}, risk {r.risk_score}): {t[:160]}")
        if len(errs) > 40:
            out.append(f"- … and {len(errs) - 40} more")

    scores = np.array([r.risk_score for r in res])
    out += ["", "**Risk score thresholds** (full system): what would happen if a single cut-off were used "
            "instead of the verdict rules.", "", f"| Flag when risk score >= | {METRIC_HEAD} |", "|---|---|---|---|---|---|---|"]
    for th in (10, 20, 30, 40, 50, 60, 70):
        out.append(f"| {th} | " + " | ".join(metric_row(y, scores >= th)) + " |")
    return out + [""]


def alternative_section(modern, p_cv, te, p_te_full) -> list[str]:
    """Checks a design choice: should a very confident ML model be allowed to
    raise "Be careful" on its own? It would catch more scams (fewer false
    negatives) at the cost of more false alarms; this measures both."""
    out = ["## D. Design check: letting the ML model warn on its own", "",
           "With no known tactic, should very scam-like wording (model output >= 0.9) be enough for "
           "\"Be careful\", or only \"Insufficient information\"? Both counted at the cautious operating point. "
           "The app uses \"Be careful\" because it cuts false negatives without adding false positives here.", "",
           f"| Test set | Design | {METRIC_HEAD} |", "|---|---|---|---|---|---|---|---|"]
    for name, texts, y, ps in (("Modern", modern["text"], modern["y"], p_cv), ("2012 SMS", te["text"], te["y"], p_te_full)):
        alone, not_alone = [], []
        for t, p in zip(texts, ps):
            r = analyze(t, model_p=float(p))
            flagged = r.verdict in (SCAM, CAREFUL)
            alone.append(flagged)
            # Without the rule, a model-only warning would have been "Insufficient information".
            not_alone.append(flagged and not r.detail.startswith("No known scam tactic found, but"))
        out.append(f"| {name} | model only corroborates | " + " | ".join(metric_row(y, not_alone)) + " |")
        out.append(f"| {name} | model may warn alone (used) | " + " | ".join(metric_row(y, alone)) + " |")
    return out + [""]


def conversation_section() -> list[str]:
    """E. Does reading the whole conversation help? Compares judging only the
    other person's last message with judging the full chat."""
    convs = json.loads(Path("data/conversations.json").read_text(encoding="utf-8"))
    y = np.array([c["label"] == "scam" for c in convs], dtype=int)
    last, full = [], []
    for c in convs:
        turns = parse_conversation(c["text"])
        me = user_speaker(turns)
        last.append(analyze([t for t in turns if t.speaker != me][-1].text))
        full.append(analyze(c["text"]))
    out = ["## E. Conversations: last message only vs whole conversation", "",
           f"{len(convs)} hand-written chats ({y.sum()} scams, {(1 - y).sum()} genuine look-alikes such as an old "
           "schoolfriend's 'is this Rahul?' or a parent asking for money). Uses the final trained model; "
           "no conversation was used for training.", "",
           f"| Judged on | Flagged when | {METRIC_HEAD} |", "|---|---|---|---|---|---|---|---|"]
    for name, rs in (("Last message only", last), ("Whole conversation", full)):
        v = np.array([r.verdict for r in rs])
        out.append(f"| {name} | cautious | " + " | ".join(metric_row(y, np.isin(v, [SCAM, CAREFUL]))) + " |")
    out += ["", "Dangerous misses (scam labelled \"No obvious threat detected\"):", ""]
    for name, rs in (("Last message only", last), ("Whole conversation", full)):
        missed = [c["id"] for c, r, lab in zip(convs, rs, y) if lab == 1 and r.verdict == SAFE]
        out.append(f"- {name}: {len(missed)}" + (f" ({', '.join(missed)})" if missed else ""))
    out += ["", "| Chat | Label | Last message only | Whole conversation |", "|---|---|---|---|"]
    for c, a, b in zip(convs, last, full):
        out.append(f"| {c['id']} | {c['label']} | {a.verdict} | {b.verdict} |")
    return out + [""]


def main():
    sms, modern = load_sms(), load_modern()
    out = ["# Jagratha evaluation", ""]

    tr, te = train_test_split(sms, test_size=0.2, stratify=sms["y"], random_state=SEED)
    sms_only = ml.train(tr["text"], tr["y"])
    p_sms_te = sms_only.predict_proba(te["text"])[:, 1]
    p_sms_mod = sms_only.predict_proba(modern["text"])[:, 1]

    # Modern messages: each scored by a model that never saw it.
    p_cv = np.zeros(len(modern))
    for tr_idx, te_idx in StratifiedKFold(5, shuffle=True, random_state=SEED).split(modern["text"], modern["y"]):
        df = pd.concat([sms, modern.iloc[tr_idx]], ignore_index=True)
        w = np.where(df["source"] == "modern", MODERN_WEIGHT, 1.0)
        p_cv[te_idx] = ml.train(df["text"], df["y"], sample_weight=w).predict_proba(modern.iloc[te_idx]["text"])[:, 1]

    # 2012 held-out messages: model trained on the SMS training split + all modern data.
    df = pd.concat([tr, modern], ignore_index=True)
    w = np.where(df["source"] == "modern", MODERN_WEIGHT, 1.0)
    p_te_full = ml.train(df["text"], df["y"], sample_weight=w).predict_proba(te["text"])[:, 1]

    out += ["## A. ML model on its own (threshold 0.5)", "",
            f"| Model | Tested on | {METRIC_HEAD} | PR-AUC | Brier | ECE |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, test, y, p in [
        ("Trained on 2012 SMS", "2012 SMS (held out)", te["y"], p_sms_te),
        ("Trained on 2012 SMS", "Modern messages", modern["y"], p_sms_mod),
        ("Trained on SMS + modern (5-fold CV)", "Modern messages", modern["y"], p_cv),
    ]:
        out.append(f"| {name} | {test} | " + " | ".join(metric_row(y, p >= 0.5))
                   + f" | {average_precision_score(y, p):.3f} | {brier_score_loss(y, p):.3f} | {ece(y, p):.3f} |")
    out += ["", "Calibration: Brier score and expected calibration error (ECE), lower is better. Reliability on "
            "modern messages (5-fold CV): if the model were calibrated, the last two columns would match.", ""]
    out += reliability(modern["y"], p_cv)
    out += ["", "The model's output is used only as corroborating evidence and is never shown to users as a "
            "probability; the risk score shown in the app is not calibrated either.", ""]

    out += system_section("B. Full system on modern messages", modern["text"].tolist(), modern["y"], p_cv,
                          groups=modern["category"].tolist())
    out += system_section(
        "C. Full system on 2012 SMS held-out messages", te["text"].tolist(), te["y"], p_te_full,
        note=(f"{len(te)} real messages ({int(te['y'].sum())} spam, {int((1 - te['y']).sum())} legitimate). "
              "The spam is mostly 2012 UK marketing and premium-rate spam rather than modern scams, so recall "
              "here mainly shows what the system *doesn't* try to catch. The false positive rate on the "
              "legitimate messages is the useful number: it's measured on real messages nobody wrote for this project."))

    out += alternative_section(modern, p_cv, te, p_te_full)
    out += conversation_section()

    report = "\n".join(out)
    Path("results").mkdir(exist_ok=True)
    Path("results/metrics.md").write_text(report + "\n", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()

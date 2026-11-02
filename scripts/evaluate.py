"""Evaluates the model, the rules and the combined system.

Experiments
  1. Model trained on the 2012 SMS data only, tested on held-out SMS data.
  2. The same model tested on modern scams  -> measures dataset shift.
  3. Model trained on SMS + modern data (5-fold CV over modern examples).
  4. Rules only, and the full system (model + rules), on modern data.

Writes results/metrics.md.
"""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, train_test_split

from scamshield import model as ml
from scamshield.analyzer import combine
from scamshield.data import load_modern, load_sms
from scamshield.signals import find_signals, rule_score
from scripts.train import MODERN_WEIGHT

THRESHOLD = 0.5
SEED = 42


def scores(y, p):
    pred = (np.asarray(p) >= THRESHOLD).astype(int)
    return {"precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0)}


def main():
    sms, modern = load_sms(), load_modern()
    rows = []

    tr, te = train_test_split(sms, test_size=0.2, stratify=sms["y"], random_state=SEED)
    sms_only = ml.train(tr["text"], tr["y"])
    rows.append(("Model trained on 2012 SMS", "2012 SMS (held out)", scores(te["y"], sms_only.predict_proba(te["text"])[:, 1])))
    rows.append(("Model trained on 2012 SMS", "Modern scams", scores(modern["y"], sms_only.predict_proba(modern["text"])[:, 1])))

    # Cross-validate over the modern set so every modern message is scored by a
    # model that never saw it.
    p_model = np.zeros(len(modern))
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    for train_idx, test_idx in skf.split(modern["text"], modern["y"]):
        df = pd.concat([sms, modern.iloc[train_idx]], ignore_index=True)
        w = np.where(df["source"] == "modern", MODERN_WEIGHT, 1.0)
        pipe = ml.train(df["text"], df["y"], sample_weight=w)
        p_model[test_idx] = pipe.predict_proba(modern.iloc[test_idx]["text"])[:, 1]
    rows.append(("Model trained on SMS + modern (5-fold CV)", "Modern scams", scores(modern["y"], p_model)))

    sigs = [find_signals(t) for t in modern["text"]]
    p_rules = [rule_score(s) for s in sigs]
    rows.append(("Rules only", "Modern scams", scores(modern["y"], p_rules)))
    p_full = [combine(m, r, s) for m, r, s in zip(p_model, p_rules, sigs)]
    rows.append(("Full system (model + rules)", "Modern scams", scores(modern["y"], p_full)))

    lines = ["| System | Tested on | Precision | Recall | F1 |", "|---|---|---|---|---|"]
    for name, test, s in rows:
        lines.append(f"| {name} | {test} | {s['precision']:.2f} | {s['recall']:.2f} | {s['f1']:.2f} |")

    missed = modern[(modern["y"] == 1) & (np.asarray(p_full) < THRESHOLD)]
    false_alarms = modern[(modern["y"] == 0) & (np.asarray(p_full) >= THRESHOLD)]
    lines += ["", f"Full system: {len(missed)} scams missed, {len(false_alarms)} false alarms "
              f"(out of {int(modern['y'].sum())} scams and {int((1 - modern['y']).sum())} safe messages)."]
    for label, df in (("Missed", missed), ("False alarm", false_alarms)):
        for t in df["text"]:
            lines.append(f"- {label}: {t}")

    report = "\n".join(lines)
    out = Path("results/metrics.md")
    out.parent.mkdir(exist_ok=True)
    out.write_text(report + "\n", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()

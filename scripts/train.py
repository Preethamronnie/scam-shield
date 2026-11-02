"""Trains the final model on all data and saves it to models/scam_model.joblib.

Modern examples are up-weighted because there are few of them and they are
the scams people actually receive today.
"""
import numpy as np
import pandas as pd

from scamshield import model as ml
from scamshield.data import load_modern, load_reviewed, load_sms

MODERN_WEIGHT = 5.0

if __name__ == "__main__":
    sms, modern, reviewed = load_sms(), load_modern(), load_reviewed()
    df = pd.concat([sms, modern, reviewed], ignore_index=True)
    w = np.where(df["source"].isin(["modern", "reviewed"]), MODERN_WEIGHT, 1.0)
    pipe = ml.train(df["text"], df["y"].astype(int), sample_weight=w)
    ml.save(pipe, training={"sms_spam_collection": len(sms), "modern_hand_written": len(modern),
                            "reviewed_feedback": len(reviewed),
                            "modern_weight": MODERN_WEIGHT})
    print(f"trained on {len(df)} messages ({len(modern)} modern) -> {ml.MODEL_PATH}")

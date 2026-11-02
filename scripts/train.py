"""Trains the final model on all data and saves it to models/scam_model.joblib.

Modern examples are up-weighted because there are few of them and they are
the scams people actually receive today.
"""
import numpy as np
import pandas as pd

from scamshield import model as ml
from scamshield.data import load_modern, load_sms

MODERN_WEIGHT = 5.0

if __name__ == "__main__":
    sms, modern = load_sms(), load_modern()
    df = pd.concat([sms, modern], ignore_index=True)
    w = np.where(df["source"] == "modern", MODERN_WEIGHT, 1.0)
    pipe = ml.train(df["text"], df["y"], sample_weight=w)
    ml.save(pipe)
    print(f"trained on {len(df)} messages ({len(modern)} modern) -> {ml.MODEL_PATH}")

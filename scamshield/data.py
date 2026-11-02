"""Loading the training data."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SMS_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"


def load_sms() -> pd.DataFrame:
    """UCI SMS Spam Collection (5,572 messages). 'spam' is mapped to scam=1."""
    path = DATA / "sms.tsv"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing. Run: python -m scripts.download_data")
    df = pd.read_csv(path, sep="\t", header=None, names=["label", "text"])
    return pd.DataFrame({"text": df["text"], "y": (df["label"] == "spam").astype(int), "source": "sms"})


def load_modern() -> pd.DataFrame:
    """Hand-written modern scams and look-alike safe messages."""
    path = DATA / "modern_scams.csv"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing. Run: python -m scripts.build_modern_set")
    df = pd.read_csv(path)
    return pd.DataFrame({"text": df["text"], "y": (df["label"] == "scam").astype(int),
                         "source": "modern", "category": df["category"]})


def load_reviewed() -> pd.DataFrame:
    """Human-reviewed feedback examples (scripts/review_feedback.py). Never raw feedback."""
    path = DATA / "reviewed_examples.csv"
    if not path.exists():
        return pd.DataFrame({"text": pd.Series(dtype=str), "y": pd.Series(dtype=int), "source": pd.Series(dtype=str)})
    df = pd.read_csv(path)
    return pd.DataFrame({"text": df["text"], "y": (df["label"] == "scam").astype(int), "source": "reviewed"})

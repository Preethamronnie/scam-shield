"""The ML classifier: TF-IDF features + logistic regression.

Small, fast, explainable, and it runs on any laptop. Word n-grams catch
phrases ("update your kyc"); character n-grams catch misspellings and
obfuscation ("fr33", "k.y.c").
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "scam_model.joblib"


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = LogisticRegression(C=8.0, class_weight="balanced", max_iter=2000)
    return Pipeline([("features", features), ("clf", clf)])


def train(texts, labels, sample_weight=None) -> Pipeline:
    pipe = build_pipeline()
    pipe.fit(list(texts), np.asarray(labels), clf__sample_weight=sample_weight)
    return pipe


def save(pipe: Pipeline, path: Path = MODEL_PATH) -> None:
    path.parent.mkdir(exist_ok=True)
    joblib.dump(pipe, path)


_cached: Pipeline | None = None


def load(path: Path = MODEL_PATH) -> Pipeline | None:
    """Load the trained model, or None if it hasn't been trained yet."""
    global _cached
    if _cached is None and path.exists():
        _cached = joblib.load(path)
    return _cached


def top_words(pipe: Pipeline, text: str, k: int = 5) -> list[str]:
    """Words in `text` that pushed the score most towards 'scam'."""
    words = pipe.named_steps["features"].transformer_list[0][1]
    coef = pipe.named_steps["clf"].coef_[0][: len(words.vocabulary_)]
    vec = words.transform([text]).toarray()[0]
    contrib = vec * coef
    names = words.get_feature_names_out()
    idx = [i for i in np.argsort(contrib)[::-1] if contrib[i] > 0][:k]
    return [names[i] for i in idx]

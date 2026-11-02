"""The ML classifier: text normalisation + TF-IDF features + logistic regression.

Small, fast, explainable, and it runs on any laptop. Word n-grams catch
phrases ("update your kyc"); character n-grams catch misspellings and
obfuscation ("fr33", "k.y.c").

Deployment:
  * The saved artifact is the *complete* pipeline, including the same text
    normalisation the app applies, so training and serving can't drift apart.
  * A model card (models/model_card.json) records the scikit-learn version,
    training data and a SHA-256 of the model file. joblib files can run code
    when loaded, so the file is only loaded if its hash matches the card.
  * The model is loaded once per process and reused for every request.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import date
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer

from .preprocess import normalize

MODEL_DIR = Path(__file__).resolve().parents[1] / "models"
MODEL_PATH = MODEL_DIR / "scam_model.joblib"
CARD_PATH = MODEL_DIR / "model_card.json"
log = logging.getLogger("scamshield")


def normalize_batch(texts):
    """Pipeline step: the same normalisation the app applies before analysis."""
    return [normalize(t) for t in texts]


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = LogisticRegression(C=8.0, class_weight="balanced", max_iter=2000)
    return Pipeline([("normalize", FunctionTransformer(normalize_batch)), ("features", features), ("clf", clf)])


def train(texts, labels, sample_weight=None) -> Pipeline:
    pipe = build_pipeline()
    pipe.fit(list(texts), np.asarray(labels), clf__sample_weight=sample_weight)
    return pipe


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save(pipe: Pipeline, path: Path = MODEL_PATH, training: dict | None = None) -> None:
    path.parent.mkdir(exist_ok=True)
    joblib.dump(pipe, path)
    card = {
        "model": "TF-IDF (word 1-2 grams + char 3-5 grams) + logistic regression",
        "pipeline_steps": [name for name, _ in pipe.steps],
        "scikit_learn_version": sklearn.__version__,
        "created": date.today().isoformat(),
        "sha256": _sha256(path),
        "training_data": training or {},
        "intended_use": "One piece of corroborating evidence inside Jagratha. Output is uncalibrated; "
                        "never show it to users as a probability.",
    }
    CARD_PATH.write_text(json.dumps(card, indent=2), encoding="utf-8")
    load.cache_clear()


@lru_cache(maxsize=1)
def load(path: Path = MODEL_PATH) -> Pipeline | None:
    """Load the trained model once per process, after checking it's the file
    the model card describes. Returns None (rules-only mode) if anything is off."""
    if not path.exists():
        return None
    if CARD_PATH.exists():
        card = json.loads(CARD_PATH.read_text(encoding="utf-8"))
        if card.get("sha256") != _sha256(path):
            log.error("model file doesn't match its model card; refusing to load it")
            return None
        if card.get("scikit_learn_version") != sklearn.__version__:
            log.warning("model trained with scikit-learn %s, running %s",
                        card.get("scikit_learn_version"), sklearn.__version__)
    pipe = joblib.load(path)
    _explainer(pipe)  # build the word-explanation tables now, not on the first request
    return pipe


@lru_cache(maxsize=4)
def _explainer(pipe: Pipeline):
    """Vocabulary and weights of the word features, built once per model.
    (Rebuilding these on every request was 88% of the analysis time.)"""
    words = pipe.named_steps["features"].transformer_list[0][1]
    names = words.get_feature_names_out()
    coef = pipe.named_steps["clf"].coef_[0][: len(names)]
    return words, names, coef


def top_words(pipe: Pipeline, text: str, k: int = 5) -> list[str]:
    """Words in `text` that pushed the score most towards 'scam'."""
    words, names, coef = _explainer(pipe)
    vec = words.transform([normalize(text)])
    idx, vals = vec.indices, vec.data          # only the words present in this message
    contrib = vals * coef[idx]
    order = np.argsort(contrib)[::-1]
    return [names[idx[i]] for i in order[:k] if contrib[i] > 0]

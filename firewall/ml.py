"""Layer 3 - Statistical classifier (offline, CPU, free).

TF-IDF (word 1-2 grams + char 3-5 grams) + Logistic Regression, trained on the
"train" pool of the synthetic corpus plus light augmentation. It generalises to
paraphrases the regex layer misses. A transformer (e.g. a DeBERTa prompt-injection
classifier) can be dropped in behind the same `predict_proba` interface.
"""
from __future__ import annotations

import os
import random

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from . import corpus

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "clf.joblib")

BENIGN_WRAPPERS = [
    "{x}",
    "Hi team,\n{x}\nThanks,\nPriya",
    "Product description: Stainless steel bottle, 1L. {x} Ships in 2 days.",
    "{x}\n\nRegards, Support",
    "Meeting notes - {x}",
]


def _augment(rows, rng):
    out = []
    for text, label, _ in rows:
        out.append((text, label))
        out.append((rng.choice(BENIGN_WRAPPERS).format(x=text), label))
        if label:
            out.append((text.lower(), label))
    return out


FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "feedback.jsonl")


def load_feedback():
    """Analyst corrections from the dashboard (trainability / human-in-the-loop)."""
    import json
    rows = []
    if os.path.exists(FEEDBACK_PATH):
        with open(FEEDBACK_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    rows.append((r["text"], int(r["label"]), None))
                except (ValueError, KeyError):
                    continue
    return rows


def build():
    rng = random.Random(1)
    rows = corpus.samples("train", seed=11, encoded_per_attack=4)
    fb = load_feedback()
    data = _augment(rows, rng) + [(t, l) for t, l, _ in fb for _ in range(3)]  # feedback up-weighted
    X, y = zip(*data)
    feats = FeatureUnion([
        ("w", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)),
        ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
    ])
    pipe = Pipeline([("f", feats), ("lr", LogisticRegression(C=2.0, max_iter=2000))])
    pipe.fit(X, y)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    return pipe


class Classifier:
    def __init__(self):
        self.pipe = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else build()

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        # Score sentence windows and take the max so one injected line in a long doc still stands out
        chunks = [c for c in _windows(text) if c.strip()] or [text]
        probs = self.pipe.predict_proba(chunks)[:, 1]
        n_words = len(text.split())
        damp = 1.0 if n_words >= 6 else 0.5 + 0.1 * n_words  # very short strings carry little evidence
        return float(max(probs)) * damp


def _windows(text: str, size: int = 2):
    import re
    sents = [s for s in re.split(r"(?<=[.!?\n])\s+", text) if s.strip()]
    if len(sents) <= size:
        return [text]
    return [" ".join(sents[i:i + size]) for i in range(0, len(sents) - size + 1)][:200]

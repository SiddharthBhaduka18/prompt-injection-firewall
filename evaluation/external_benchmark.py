"""Independent check on any public prompt-injection dataset (CSV or JSONL with text,label).

Examples (download on your own machine, then run):
  * deepset/prompt-injections (Hugging Face)   -> columns text,label
  * a HackAPrompt / Lakera Gandalf export       -> map the prompt column to text, label=1
  * your own benign traffic sample              -> label=0
Usage: python -m evaluation.external_benchmark data.csv [--text-col text] [--label-col label]
"""
import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from firewall import Firewall  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("path")
ap.add_argument("--text-col", default="text")
ap.add_argument("--label-col", default="label")
ap.add_argument("--source", default="user_message")
a = ap.parse_args()
df = pd.read_json(a.path, lines=True) if a.path.endswith(".jsonl") else pd.read_csv(a.path)
fw = Firewall(config={"use_llm": False}, log=False)
pred = [fw.scan(str(t), a.source).action != "ALLOW" for t in df[a.text_col]]
y = df[a.label_col].astype(int).tolist()
tp = sum(p and l for p, l in zip(pred, y)); fp = sum(p and not l for p, l in zip(pred, y))
fn = sum((not p) and l for p, l in zip(pred, y)); tn = sum((not p) and not l for p, l in zip(pred, y))
prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
print(json.dumps({"n": len(y), "precision": prec, "recall": rec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0,
                  "fpr": fp / (fp + tn) if fp + tn else 0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}, indent=1))

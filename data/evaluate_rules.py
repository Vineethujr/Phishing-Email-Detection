"""Baseline: run the rule-based engine over the synthetic dataset and report honest results.
Usage (project root):  python data/evaluate_rules.py   [--threshold 41]"""
import argparse, os, sys
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pandas as pd
from backend.services.risk_engine import analyze_email

ap = argparse.ArgumentParser(); ap.add_argument("--threshold", type=int, default=41,
    help="score >= threshold counts as 'flagged as phishing' (41 = SUSPICIOUS or above)")
a = ap.parse_args()
df = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_email_dataset.csv"), keep_default_na=False)
res = [analyze_email(r.sender, r.subject, r.body, r.attachment_name) for r in df.itertuples()]
df["score"] = [x["risk_score"] for x in res]; df["cls"] = [x["classification"] for x in res]
df["flag"] = df["score"] >= a.threshold; y = df["label"] == "PHISHING"
tp = int((df.flag & y).sum()); fp = int((df.flag & ~y).sum()); fn = int((~df.flag & y).sum()); tn = int((~df.flag & ~y).sum())
p = tp / (tp + fp) if tp + fp else 0; r_ = tp / (tp + fn) if tp + fn else 0; f1 = 2 * p * r_ / (p + r_) if p + r_ else 0
print(f"Rows: {len(df)}  threshold: score >= {a.threshold}")
print(f"TP={tp} FP={fp} FN={fn} TN={tn}\nAccuracy={(tp+tn)/len(df):.3f} Precision={p:.3f} Recall={r_:.3f} F1={f1:.3f}")
print("\nClassification by true label:"); print(pd.crosstab(df.label, df.cls))
print("\nMean score by category:"); print(df.groupby("category")["score"].agg(["mean", "min", "max"]).round(1).to_string())
print("\nMissed phishing (false negatives) by category:", dict(Counter(df[~df.flag & y].category)))
print("Flagged legitimate (false positives) by category:", dict(Counter(df[df.flag & ~y].category)))

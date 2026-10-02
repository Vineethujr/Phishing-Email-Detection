"""Train and compare Logistic Regression, Naive Bayes and Random Forest.

Run from project root:   python ml/train_model.py

Protocol (so results are honest):
  1. Stratified split 70% train / 15% validation / 15% test (seed 42).
  2. Fit on TRAIN. Pick the best model by VALIDATION F1. Never tune on TEST.
  3. Report TEST metrics for every model, plus the rule engine and hybrid for comparison.
  4. Stress test: leave-one-phishing-category-out (does it generalise to unseen lure types?).
All numbers are written to docs/ml_results.md by this script - none are typed by hand.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler

from backend.services.risk_engine import analyze_email
from backend.utils.preprocessing import preprocess_dataframe
from ml.evaluation import compute_metrics, plot_confusion_matrix, plot_model_comparison
from ml.hybrid import combine_scores
from ml.ml_features import NUMERIC_COLUMNS, dataframe_to_features

SEED = 42


def build_pipeline(model) -> Pipeline:
    pre = ColumnTransformer([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True), "text"),
        ("num", MinMaxScaler(), NUMERIC_COLUMNS),   # non-negative, so Naive Bayes can use it too
    ])
    return Pipeline([("features", pre), ("model", model)])


def candidate_models():
    return {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED),
        "Naive Bayes": MultinomialNB(alpha=0.5),
        "Random Forest": RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=SEED, n_jobs=1),
    }


def load_data(path: str) -> pd.DataFrame:
    return preprocess_dataframe(pd.read_csv(path, keep_default_na=False))


def split_data(df: pd.DataFrame):
    train, temp = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=SEED)
    val, test = train_test_split(temp, test_size=0.50, stratify=temp["label"], random_state=SEED)
    return train, val, test


CAVEATS = """
## Read this before quoting these numbers

- The dataset is **synthetic and template-generated**. After de-duplication many rows are near-identical
  variants of the same template, so train/validation/test contain look-alikes of each other. Near-perfect
  scores here mostly show that the pipeline works, **not** that it would catch real phishing.
- The test set is small, so one email changes precision/recall noticeably.
- Some learned signals (for example body length or URL count) reflect how the generator writes emails
  (generator artifacts), not real phishing behaviour.
- The stress test above (unseen lure type) is the more informative check. Any category with low recall
  is a lure the model would likely miss in the real world without more diverse training data.
- The hybrid blend weights (0.4 rules / 0.6 ML) are an assumption, not tuned.
- Metrics are computed by the script; re-running it regenerates this file.
"""


def fmt(m):  # one markdown row of metrics
    return f"{m['accuracy']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(ROOT, "data", "phishing_email_dataset.csv"))
    ap.add_argument("--models-dir", default=os.path.join(ROOT, "models"))
    ap.add_argument("--docs-dir", default=os.path.join(ROOT, "docs"))
    a = ap.parse_args()
    os.makedirs(a.models_dir, exist_ok=True)
    os.makedirs(a.docs_dir, exist_ok=True)

    df = load_data(a.data)
    train, val, test = split_data(df)
    print(f"Rows: total={len(df)} train={len(train)} val={len(val)} test={len(test)}")
    X = {n: dataframe_to_features(d) for n, d in (("train", train), ("val", val), ("test", test))}
    y = {n: (d["label"] == "PHISHING").astype(int).values for n, d in (("train", train), ("val", val), ("test", test))}

    val_res, test_res, fitted = {}, {}, {}
    for name, model in candidate_models().items():
        pipe = build_pipeline(model).fit(X["train"], y["train"])
        fitted[name] = pipe
        val_res[name] = compute_metrics(y["val"], pipe.predict(X["val"]))
        test_res[name] = compute_metrics(y["test"], pipe.predict(X["test"]))
        print(f"{name:20s} val F1={val_res[name]['f1']:.3f}  test F1={test_res[name]['f1']:.3f}")

    best = max(val_res, key=lambda n: (val_res[n]["f1"], val_res[n]["recall"]))
    print("Selected by validation F1:", best)

    # 5-fold CV on train+val (stability check)
    Xtv = pd.concat([X["train"], X["val"]]); ytv = np.concatenate([y["train"], y["val"]])
    cv = {}
    for name, model in candidate_models().items():
        s = cross_val_score(build_pipeline(model), Xtv, ytv, cv=StratifiedKFold(5, shuffle=True, random_state=SEED), scoring="f1")
        cv[name] = (s.mean(), s.std())

    # Rule engine + hybrid on the SAME test rows
    rule_scores = np.array([analyze_email(r.sender, r.subject, r.body, r.attachment_name)["risk_score"] for r in test.itertuples()])
    ml_prob = fitted[best].predict_proba(X["test"])[:, 1]
    detectors = dict(test_res)
    detectors["Rules only (score>=21)"] = compute_metrics(y["test"], (rule_scores >= 21).astype(int))
    detectors["Rules only (score>=41)"] = compute_metrics(y["test"], (rule_scores >= 41).astype(int))
    hyb = np.array([combine_scores(rs, p)["combined_score"] for rs, p in zip(rule_scores, ml_prob)])
    detectors["Hybrid (score>=41)"] = compute_metrics(y["test"], (hyb >= 41).astype(int))

    # Stress test: hold out each phishing category entirely
    stress = {}
    phish_cats = sorted(df[df["label"] == "PHISHING"]["category"].unique())
    for cat in phish_cats:
        held = df["category"] == cat
        Xa, Xb = dataframe_to_features(df[~held]), dataframe_to_features(df[held])
        pipe = build_pipeline(candidate_models()[best]).fit(Xa, (df[~held]["label"] == "PHISHING").astype(int))
        stress[cat] = float(pipe.predict(Xb).mean())      # recall on the unseen category
    stress_rules = {}
    for cat in phish_cats:
        sub = df[df["category"] == cat]
        s = np.array([analyze_email(r.sender, r.subject, r.body, r.attachment_name)["risk_score"] for r in sub.itertuples()])
        stress_rules[cat] = float((s >= 21).mean())

    # Save final model (fit on train only, as evaluated) + plots
    joblib.dump({"pipeline": fitted[best], "model_name": best, "numeric_columns": NUMERIC_COLUMNS,
                 "trained_on_rows": len(train)}, os.path.join(a.models_dir, "phishing_model.joblib"))
    plot_confusion_matrix(test_res[best], f"Confusion matrix - {best} (test set)", os.path.join(a.docs_dir, "confusion_matrix.png"))
    plot_model_comparison({k: v for k, v in detectors.items()}, os.path.join(a.docs_dir, "model_comparison.png"))

    # Top features (interpretability) if the model exposes them
    top = ""
    if best == "Logistic Regression":
        names = fitted[best].named_steps["features"].get_feature_names_out()
        coef = fitted[best].named_steps["model"].coef_[0]
        idx = np.argsort(coef)
        top = ("\n## Strongest learned signals (Logistic Regression coefficients)\n\n"
               "Toward PHISHING: " + ", ".join(f"`{names[i].split('__')[1]}`" for i in idx[::-1][:12]) +
               "\n\nToward LEGITIMATE: " + ", ".join(f"`{names[i].split('__')[1]}`" for i in idx[:12]) + "\n")

    hdr = "| Detector | Accuracy | Precision | Recall | F1 | TP | FP | FN | TN |\n|---|---|---|---|---|---|---|---|---|\n"
    md = [f"# ML Results (generated by `ml/train_model.py`, seed {SEED})", "",
          f"Rows: {len(df)} (train {len(train)} / validation {len(val)} / test {len(test)}). Positive class = PHISHING.",
          f"Selected model (best validation F1): **{best}**", "",
          "## Validation set (used to choose the model)", "", hdr +
          "\n".join(f"| {n} | {fmt(m)} |" for n, m in val_res.items()), "",
          "## Test set (final, untouched during selection)", "", hdr +
          "\n".join(f"| {n} | {fmt(m)} |" for n, m in detectors.items()), "",
          "## 5-fold cross-validation F1 (train+validation)", "",
          "| Model | Mean F1 | Std |\n|---|---|---|\n" + "\n".join(f"| {n} | {m:.3f} | {s:.3f} |" for n, (m, s) in cv.items()), "",
          f"## Stress test: recall on a phishing category the model never saw ({best})", "",
          "| Held-out category | ML recall | Rules recall (score>=21) |\n|---|---|---|\n" +
          "\n".join(f"| {c} | {stress[c]:.2f} | {stress_rules[c]:.2f} |" for c in phish_cats), "", top, CAVEATS]
    with open(os.path.join(a.docs_dir, "ml_results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    with open(os.path.join(a.docs_dir, "ml_results.json"), "w") as f:
        json.dump({"best": best, "validation": val_res, "test": detectors, "stress_ml": stress, "stress_rules": stress_rules}, f, indent=2)
    print("Saved model, docs/ml_results.md, confusion_matrix.png, model_comparison.png")


if __name__ == "__main__":
    main()

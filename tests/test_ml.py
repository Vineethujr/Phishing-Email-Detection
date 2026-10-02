"""Phase 2 tests: ML pipeline, evaluation helpers, hybrid scoring (T24 series)."""
import os

import pandas as pd
import pytest

from ml.evaluation import compute_metrics
from ml.hybrid import combine_scores
from ml.ml_features import NUMERIC_COLUMNS, dataframe_to_features, email_to_frame
from ml.predict import hybrid_assessment, load_model, predict_probability
from ml.train_model import build_pipeline, candidate_models, load_data, split_data
from run_demo import LEGIT, PHISH

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_email_dataset.csv")


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Train a fresh Logistic Regression on the train split only (no dependence on saved files)."""
    df = load_data(DATA)
    train, val, test = split_data(df)
    pipe = build_pipeline(candidate_models()["Logistic Regression"]).fit(
        dataframe_to_features(train), (train["label"] == "PHISHING").astype(int))
    import joblib
    path = str(tmp_path_factory.mktemp("m") / "m.joblib")
    joblib.dump({"pipeline": pipe, "model_name": "Logistic Regression"}, path)
    return path, (train, val, test)


def test_t24a_split_is_stratified_and_disjoint(actual):
    """Train/validation/test split
    Input: dataset split 70/15/15 with seed 42
    Expected: no shared email_id between splits; both classes present in each split"""
    _, (tr, va, te) = None, split_data(load_data(DATA))
    ids = [set(x["email_id"]) for x in (tr, va, te)]
    actual(f"sizes={len(tr)}/{len(va)}/{len(te)}")
    assert not (ids[0] & ids[1] or ids[0] & ids[2] or ids[1] & ids[2])
    assert all(x["label"].nunique() == 2 for x in (tr, va, te))


def test_t24b_feature_frame(actual):
    """Feature frame for the model
    Input: one phishing email
    Expected: 1 row, 'text' plus all numeric columns, no missing values"""
    f = email_to_frame(PHISH["sender"], PHISH["subject"], PHISH["body"])
    actual(f"shape={f.shape}")
    assert f.shape == (1, 1 + len(NUMERIC_COLUMNS)) and not f.isna().any().any()


def test_t24c_prediction_direction(trained, actual):
    """ML prediction on the two demo emails
    Input: demo phishing vs demo legitimate email (model trained in-test)
    Expected: probability in [0,1]; phishing probability > legitimate probability"""
    path, _ = trained
    p = predict_probability(PHISH["sender"], PHISH["subject"], PHISH["body"], model_path=path)
    l = predict_probability(LEGIT["sender"], LEGIT["subject"], LEGIT["body"], model_path=path)
    actual(f"phish={p:.3f} legit={l:.3f}")
    assert 0 <= l <= 1 and 0 <= p <= 1 and p > l


def test_t24d_metrics_correct(actual):
    """Metric computation on a known example
    Input: y_true=[1,1,1,0,0,0], y_pred=[1,1,0,0,0,1]
    Expected: TP=2 FP=1 FN=1 TN=2; precision=recall=2/3"""
    m = compute_metrics([1, 1, 1, 0, 0, 0], [1, 1, 0, 0, 0, 1])
    actual({k: m[k] for k in ("tp", "fp", "fn", "tn")})
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 2)
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)


def test_t24e_accuracy_can_mislead(actual):
    """Accuracy alone can mislead
    Input: 95 legitimate + 5 phishing, a model that always says 'legitimate'
    Expected: accuracy 0.95 but recall 0.0"""
    m = compute_metrics([0] * 95 + [1] * 5, [0] * 100)
    actual(f"accuracy={m['accuracy']} recall={m['recall']}")
    assert m["accuracy"] == 0.95 and m["recall"] == 0.0


def test_t24f_hybrid_blend(actual):
    """Hybrid score blending
    Input: rule=70, ML probability=0.80; and ML unavailable
    Expected: 0.4*70 + 0.6*80 = 76; without ML the rule score is used"""
    a, b = combine_scores(70, 0.8), combine_scores(70, None)
    actual(f"hybrid={a['combined_score']} fallback={b['combined_score']} ({b['mode']})")
    assert a["combined_score"] == 76 and b["combined_score"] == 70 and b["mode"] == "rules_only"


def test_t24g_hybrid_without_model(tmp_path, actual):
    """App works when no model file exists
    Input: hybrid_assessment with a missing model path
    Expected: rules-only mode, classification still produced"""
    r = hybrid_assessment(PHISH["sender"], PHISH["subject"], PHISH["body"], model_path=str(tmp_path / "none.joblib"))
    actual(f"mode={r['mode']} {r['combined_score']} {r['classification']}")
    assert r["mode"] == "rules_only" and r["classification"].startswith("HIGH")


def test_t24h_hybrid_with_model(trained, actual):
    """Hybrid with a trained model
    Input: demo phishing email
    Expected: hybrid mode, ML probability present, HIGH RISK"""
    path, _ = trained
    r = hybrid_assessment(PHISH["sender"], PHISH["subject"], PHISH["body"], model_path=path)
    actual(f"mode={r['mode']} rule={r['rule_score']} ml={r['ml_probability']:.2f} combined={r['combined_score']}")
    assert r["mode"] == "hybrid" and r["classification"].startswith("HIGH")


def test_t24i_missing_model_returns_none(tmp_path, actual):
    """Loading a missing model
    Input: nonexistent path
    Expected: None (no crash)"""
    actual(load_model(str(tmp_path / "x.joblib")))
    assert load_model(str(tmp_path / "x.joblib")) is None

"""Load the trained model and score emails (optional: the app works without it)."""
import os
from typing import Dict, Optional

import joblib

from backend.services.risk_engine import analyze_email, classify
from ml.hybrid import combine_scores
from ml.ml_features import email_to_frame

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "phishing_model.joblib")
_CACHE: Dict[str, Dict] = {}


def load_model(path: str = DEFAULT_MODEL_PATH) -> Optional[Dict]:
    """Return the saved bundle, or None if no model has been trained yet."""
    if path not in _CACHE:
        if not os.path.exists(path):
            return None
        _CACHE[path] = joblib.load(path)   # only load model files you created yourself (joblib uses pickle)
    return _CACHE[path]


def predict_probability(sender: str, subject: str, body: str, attachment_name: str = "", model_path: str = DEFAULT_MODEL_PATH) -> Optional[float]:
    bundle = load_model(model_path)
    if bundle is None:
        return None
    return float(bundle["pipeline"].predict_proba(email_to_frame(sender, subject, body, attachment_name))[0, 1])


def hybrid_assessment(sender: str, subject: str, body: str, attachment_name: str = "", model_path: str = DEFAULT_MODEL_PATH) -> Dict:
    """Rule analysis + optional ML probability + blended score and classification."""
    rules = analyze_email(sender, subject, body, attachment_name)
    prob = predict_probability(sender, subject, body, attachment_name, model_path)
    blend = combine_scores(rules["risk_score"], prob)
    return {**blend, "classification": classify(blend["combined_score"]), "rule_result": rules,
            "note": "ML probability is an estimate from a model trained on synthetic data, not certainty."}

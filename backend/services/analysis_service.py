"""One place that turns raw email fields into the final API result (rules + optional ML)."""
from typing import Dict, Optional

from backend.services.risk_engine import DISCLAIMER, analyze_email, classify, get_recommendations

try:  # ML is optional: the app must still run without scikit-learn or a trained model
    from ml.hybrid import combine_scores
    from ml.predict import predict_probability
except ImportError:  # pragma: no cover
    combine_scores = predict_probability = None


def assess_email(sender: str, subject: str, body: str, attachment_name: str = "", display_name: Optional[str] = None,
                 use_ml: bool = True, model_path: Optional[str] = None) -> Dict:
    rules = analyze_email(sender, subject, body, attachment_name, display_name)
    prob = None
    if use_ml and predict_probability is not None:
        kwargs = {"model_path": model_path} if model_path else {}
        try:
            prob = predict_probability(sender, subject, body, attachment_name, **kwargs)
        except Exception:  # a broken model file must never break the analyzer
            prob = None

    result = dict(rules)
    result["rule_score"] = rules["risk_score"]
    if prob is None:
        result.update(ml_probability=None, mode="rules_only")
    else:
        blend = combine_scores(rules["risk_score"], prob)
        result.update(risk_score=blend["combined_score"], ml_probability=round(prob, 4), mode="hybrid")
        result["classification"] = classify(result["risk_score"])
        if prob >= 0.5:
            result["indicators"] = rules["indicators"] + [{
                "indicator_type": "ml", "severity": "medium", "points": 0,
                "description": f"ML model estimates {prob:.0%} probability of phishing (estimate, not certainty)"}]
        result["recommendations"] = get_recommendations(result["classification"], result["indicators"])
    result["disclaimer"] = DISCLAIMER
    return result

"""Hybrid detection = interpretable rules + machine-learning probability.

combined_score = RULE_WEIGHT * rule_score + ML_WEIGHT * (ml_probability * 100)

Why combine? Rules give clear explanations and catch known patterns; ML can pick up
wording patterns the rules do not list. The weights are a project assumption.
The ML output is a probability estimate from a model trained on SYNTHETIC data - it is not certainty.
"""
from typing import Dict, Optional

RULE_WEIGHT, ML_WEIGHT = 0.4, 0.6


def combine_scores(rule_score: float, ml_probability: Optional[float]) -> Dict:
    """Weighted blend. If no ML model is available, fall back to the rule score alone."""
    if ml_probability is None:
        return {"combined_score": int(round(rule_score)), "rule_score": rule_score, "ml_probability": None, "mode": "rules_only"}
    combined = RULE_WEIGHT * rule_score + ML_WEIGHT * ml_probability * 100
    return {"combined_score": int(round(min(100, max(0, combined)))), "rule_score": rule_score,
            "ml_probability": float(ml_probability), "mode": "hybrid"}

"""Turns emails into a DataFrame the sklearn pipeline understands.

Two kinds of input to the model:
  * text      : subject + body + a token for the attachment extension (TF-IDF)
  * numeric   : the structured phishing indicators from extract_email_features()
Keeping both lets the model use wording AND explainable security signals.
"""
from typing import Dict, List

import pandas as pd

from backend.services.feature_extractor import features_from_results, run_analyzers
from backend.utils.preprocessing import extract_attachment_extension

NUMERIC_COLUMNS = [
    "urgent_keyword_count", "credential_keyword_count", "financial_keyword_count", "threat_keyword_count",
    "reward_keyword_count", "url_count", "suspicious_url_count", "has_ip_url", "has_shortened_url_pattern",
    "has_non_https_url", "sender_domain_length", "subdomain_count", "suspicious_attachment", "generic_greeting",
    "contains_password_request", "contains_personal_info_request", "exclamation_count", "uppercase_ratio",
    "body_length", "subject_length",
]


def _row(sender: str, subject: str, body: str, attachment_name: str) -> Dict:
    r = run_analyzers(sender, subject, body, attachment_name)
    ext = extract_attachment_extension(attachment_name)
    row = {"text": f"{r['subject']} {r['body']} attachment_ext_{ext.strip('.') or 'none'}"}
    row.update(features_from_results(r))
    return row


def email_to_frame(sender: str, subject: str, body: str, attachment_name: str = "") -> pd.DataFrame:
    """One email -> one-row DataFrame (used at prediction time)."""
    return pd.DataFrame([_row(sender, subject, body, attachment_name)])[["text"] + NUMERIC_COLUMNS]


def dataframe_to_features(df: pd.DataFrame) -> pd.DataFrame:
    """Dataset DataFrame (columns: sender, subject, body, attachment_name) -> model input."""
    rows: List[Dict] = [_row(r.sender, r.subject, r.body, r.attachment_name) for r in df.itertuples()]
    return pd.DataFrame(rows)[["text"] + NUMERIC_COLUMNS]

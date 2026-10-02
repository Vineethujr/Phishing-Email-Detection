"""Preprocessing helpers.

Design rule: NEVER destroy evidence. Aggressive cleaning (lower-casing
everything, deleting punctuation, stripping URLs, removing digits) throws away
exactly the signals we need: ALL-CAPS shouting, '!!!', raw IPs in URLs,
'paypa1'-style digit swaps, '.exe' extensions. So `clean_text_light` only
normalises whitespace/control characters and leaves the rest intact.
"""
import html
import re
from typing import List, Optional, Tuple

import pandas as pd

from backend.utils.constants import MAX_BODY_CHARS, MAX_URLS

URL_REGEX = re.compile(r"""(?i)\b(?:https?://|ftp://|www\.)[^\s<>"'\)\]]+""")
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)$")
ANCHOR_REGEX = re.compile(r"""<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)
TAG_REGEX = re.compile(r"<[^>]+>")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def parse_sender(sender: Optional[str]) -> Tuple[str, str]:
    """'ExampleBank Support <a@b.com>' -> ('ExampleBank Support', 'a@b.com')."""
    sender = (sender or "").strip()
    m = re.match(r'^\s*"?([^"<]*?)"?\s*<([^<>]+)>\s*$', sender)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", sender


def extract_sender_domain(sender: Optional[str]) -> str:
    """Return the lower-cased domain of a sender, or '' if the address is invalid."""
    _, addr = parse_sender(sender)
    m = EMAIL_REGEX.match(addr)
    return m.group(1).lower() if m else ""


def extract_urls(text: Optional[str]) -> List[str]:
    """Find URLs in text (order preserved, duplicates removed, capped)."""
    seen, urls = set(), []
    for raw in URL_REGEX.findall(text or ""):
        url = raw.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= MAX_URLS:
            break
    return urls


def extract_html_links(text: Optional[str]) -> List[Tuple[str, str]]:
    """Return (visible_text, href) pairs from <a> tags. Used for link-mismatch checks."""
    pairs = []
    for href, inner in ANCHOR_REGEX.findall(text or ""):
        pairs.append((TAG_REGEX.sub("", inner).strip(), html.unescape(href).strip()))
    return pairs[:MAX_URLS]


def strip_html(text: Optional[str]) -> str:
    """Convert an HTML body to plain text (regex based; output is never rendered as HTML)."""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text or "")
    return html.unescape(TAG_REGEX.sub(" ", text))


def extract_attachment_extension(filename: Optional[str]) -> str:
    """'Invoice.PDF.exe' -> '.exe' (lower-case, last extension only)."""
    name = (filename or "").strip().lower()
    return "." + name.rsplit(".", 1)[1] if "." in name.strip(".") else ""


def clean_text_light(text: Optional[str], max_chars: int = MAX_BODY_CHARS) -> str:
    """Light cleaning: unescape entities, drop control chars, collapse whitespace, cap length."""
    text = html.unescape(text or "")
    text = CONTROL_CHARS.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:max_chars]


def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean a raw dataset: fill missing values, dedupe, add derived columns."""
    df = df.copy()
    for col in ["sender", "subject", "body", "urls", "attachment_name", "label"]:
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str)
    df["label"] = df["label"].str.strip().str.upper()
    df = df[df["label"].isin(["LEGITIMATE", "PHISHING"])]
    df["subject"] = df["subject"].map(clean_text_light)
    df["body"] = df["body"].map(clean_text_light)
    df = df.drop_duplicates(subset=["sender", "subject", "body"]).reset_index(drop=True)
    df["sender_domain"] = df["sender"].map(extract_sender_domain)
    df["url_list"] = df.apply(lambda r: r["urls"].split() if r["urls"].strip() else extract_urls(r["body"]), axis=1)
    df["attachment_ext"] = df["attachment_name"].map(extract_attachment_extension)
    return df

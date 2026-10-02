"""Safe .eml / .txt parsing using only the standard library.

We read headers and the text body. Attachment PAYLOADS are never decoded or
saved - only their filenames are collected for static analysis.
"""
import email
from email import policy
from typing import Dict

from backend.utils.constants import MAX_EML_BYTES
from backend.utils.preprocessing import clean_text_light


def parse_eml(data: bytes) -> Dict:
    if len(data) > MAX_EML_BYTES:
        raise ValueError(f"File too large (limit {MAX_EML_BYTES} bytes)")
    msg = email.message_from_bytes(data, policy=policy.default)
    part = msg.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else ""
    names = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    return {"sender": str(msg.get("From", "")), "subject": str(msg.get("Subject", "")),
            "body": body if isinstance(body, str) else "", "attachment_name": names[0] if names else "",
            "attachment_names": names}

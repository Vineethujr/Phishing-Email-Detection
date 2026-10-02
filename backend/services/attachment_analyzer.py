"""Static attachment FILENAME analysis. Attachments are never opened or executed."""
from typing import Dict, List

from backend.utils.constants import (ARCHIVE_EXTENSIONS, DOCUMENT_EXTENSIONS, EXECUTABLE_EXTENSIONS,
                                     HTML_EXTENSIONS, MACRO_EXTENSIONS, SCRIPT_EXTENSIONS)
from backend.utils.preprocessing import extract_attachment_extension


def analyze_attachment(filename: str) -> Dict:
    """Return {'attachment_risk_score', 'findings', 'extension', 'explanation'} for a filename."""
    name = (filename or "").strip()
    if not name:
        return {"attachment_risk_score": 0, "findings": [], "extension": "", "explanation": "No attachment supplied."}

    lower = name.lower()
    ext = extract_attachment_extension(lower)
    parts = lower.strip(".").split(".")
    findings: List[Dict] = []

    def add(desc, sev, pts):
        findings.append({"description": desc, "severity": sev, "points": pts})

    risky = ext in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS
    if ext in EXECUTABLE_EXTENSIONS:
        add(f"Executable file type ({ext}) can run programs on the computer", "high", 70)
    elif ext in SCRIPT_EXTENSIONS:
        add(f"Script file type ({ext}) can run commands on the computer", "high", 70)
    elif ext in MACRO_EXTENSIONS:
        add(f"Macro-enabled Office file ({ext}) can contain automatic code", "medium", 35)
    elif ext in ARCHIVE_EXTENSIONS:
        add(f"Archive/disk-image type ({ext}) can hide other files inside", "medium", 30)
    elif ext in HTML_EXTENSIONS:
        add(f"HTML attachment ({ext}) can contain scripts or fake forms", "medium", 30)

    if len(parts) >= 3 and f".{parts[-2]}" in DOCUMENT_EXTENSIONS and (risky or ext in ARCHIVE_EXTENSIONS | MACRO_EXTENSIONS | HTML_EXTENSIONS):
        add(f"Double extension (.{parts[-2]}{ext}) disguises the real file type", "high", 25)

    score = min(100, sum(f["points"] for f in findings))
    explanation = ("; ".join(f["description"] for f in findings) if findings
                   else f"Extension '{ext or 'none'}' is not in the risky list. This is a filename check only - it does not scan file contents.")
    return {"attachment_risk_score": score, "findings": findings, "extension": ext, "explanation": explanation}

"""Streamlit interface for the phishing-awareness dashboard."""
import os
import tempfile
from typing import Dict, Optional

import pandas as pd
import streamlit as st

from backend.config import Settings
from backend.database import CLASS_CODES, Database
from backend.services.analysis_service import assess_email
from backend.services.url_analyzer import analyze_url
from backend.utils.constants import MAX_BODY_CHARS, MAX_EML_BYTES
from backend.utils.eml_parser import parse_eml
from backend.utils.preprocessing import extract_sender_domain


TIPS = [
    ("Check the sender address", "Look at the real address, not just the display name. A friendly name can hide an unrelated domain."),
    ("Read the domain spelling", "Watch for swapped characters (examp1e), extra words or hyphens, and long chains of subdomains."),
    ("Question unexpected urgency", "“Act now” and “within 24 hours” are designed to stop you thinking. Real problems can be checked calmly."),
    ("Inspect links before clicking", "Hover to preview the destination. Raw IP addresses, shorteners and odd hostnames deserve suspicion. HTTPS does not mean safe."),
    ("Never send credentials by email", "Organisations do not ask for passwords or one-time codes through email links. Go to the official site yourself."),
    ("Be careful with attachments", "Unexpected files are risky, especially .exe, .js, .zip or double extensions like invoice.pdf.exe."),
    ("Notice generic greetings", "“Dear Customer” from a company that knows your name is a mild warning sign, not proof by itself."),
    ("Verify unusual payment requests", "New bank details, gift cards or rush payments should be confirmed by phone using a number you already trust."),
    ("Recognise threatening language", "Threats of suspension, fines or legal action are pressure tactics. Slow down and verify."),
    ("Use context", "Were you expecting this? Does it match how this sender normally writes? Context often beats any single indicator."),
]

CHECKS = [
    "Do I recognise the sender, and does the real address match who they claim to be?",
    "Was I expecting this message?",
    "Is it pushing me to act urgently or scaring me?",
    "Does the link destination match what it says (hover to check)?",
    "Is it asking for a password, code or personal details?",
    "Is there an unexpected attachment or unusual file type?",
    "Is the greeting generic or the writing oddly off?",
    "Does it ask for money, gift cards or new bank details?",
    "Can I verify by opening the official site/app myself, not via this email?",
    "If still unsure, have I asked IT/security before clicking?",
]


@st.cache_resource
def get_database() -> Database:
    settings = Settings(
        db_path=os.getenv(
            "DATABASE_PATH",
            os.path.join(tempfile.gettempdir(), "phishing-awareness-history.db"),
        )
    )
    return Database(settings.db_path)


def analyze_and_store(
    sender: str,
    subject: str,
    body: str,
    attachment_name: str = "",
    display_name: Optional[str] = None,
    use_ml: bool = True,
    save_history: bool = False,
) -> Dict:
    if not (sender.strip() or subject.strip() or body.strip()):
        raise ValueError("Provide at least one of sender, subject, or body.")
    if len(sender) > 320 or len(subject) > 500 or len(body) > MAX_BODY_CHARS:
        raise ValueError("Input exceeds the allowed length.")
    if len(attachment_name) > 255 or "/" in attachment_name or "\\" in attachment_name:
        raise ValueError("Attachment must be a filename of 255 characters or fewer.")
    if display_name and len(display_name) > 200:
        raise ValueError("Display name must be 200 characters or fewer.")

    settings = Settings()
    result = assess_email(
        sender.strip(), subject.strip(), body, attachment_name.strip(),
        display_name.strip() if display_name else None, use_ml, settings.model_path,
    )
    if save_history:
        result["analysis_id"] = get_database().save_analysis(
            result, extract_sender_domain(sender), subject
        )
    return result


def show_result(result: Dict) -> None:
    st.subheader("Analysis result")
    score_col, class_col, mode_col = st.columns(3)
    score_col.metric("Risk score", f"{result['risk_score']}/100")
    class_col.metric("Classification", result["classification"])
    mode_col.metric("Analysis mode", result.get("mode", "rules_only").replace("_", " "))
    st.progress(result["risk_score"] / 100)
    if result.get("analysis_id"):
        st.caption(f"Saved to shared history as analysis #{result['analysis_id']}.")

    if result.get("ml_probability") is not None:
        st.caption(f"ML probability estimate: {result['ml_probability']:.0%} (not certainty)")

    with st.expander("Why this result?", expanded=True):
        indicators = result.get("indicators", [])
        if indicators:
            st.dataframe(
                pd.DataFrame(indicators)[["severity", "indicator_type", "points", "description"]],
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.write("No strong warning indicators were found.")

    with st.expander("URL analysis"):
        urls = result.get("url_analyses", [])
        if not urls:
            st.write("No URLs found.")
        for url in urls:
            st.code(url["url_safe"], language=None)
            st.write(f"Risk score: {url['risk_score']}/100")
            for finding in url["findings"]:
                st.text(f"- {finding['severity']}: {finding['description']}")

    with st.expander("Recommended actions"):
        for recommendation in result.get("recommendations", []):
            st.text(f"• {recommendation}")
    st.caption(result.get("disclaimer", "Automated risk estimate; verify through a trusted channel."))


def history_page(db: Database) -> None:
    st.subheader("Shared analysis history")
    st.warning(
        "History is shared with every visitor to this app. Only save synthetic or "
        "authorized examples; sender domains and subjects may be visible to others."
    )
    filter_col, search_col, sort_col = st.columns([1, 2, 1])
    selected_class = filter_col.selectbox(
        "Classification", ["All", "LOW", "MODERATE", "SUSPICIOUS", "HIGH"]
    )
    query = search_col.text_input("Search saved subject or sender domain")
    sort = sort_col.selectbox(
        "Sort by", ["Newest", "Oldest", "Highest risk", "Lowest risk"]
    )
    sort_key = {
        "Newest": "newest",
        "Oldest": "oldest",
        "Highest risk": "risk_desc",
        "Lowest risk": "risk_asc",
    }[sort]
    classification = CLASS_CODES.get(selected_class) if selected_class != "All" else None
    records, total = db.list_analyses(
        classification=classification, q=query or None, sort=sort_key, limit=100
    )
    st.caption(f"{total} saved record(s); showing up to 100.")
    if records:
        st.dataframe(
            pd.DataFrame(records)[
                ["analysis_id", "created_at", "sender_domain", "subject", "risk_score", "classification", "mode"]
            ],
            hide_index=True,
            use_container_width=True,
        )
        selected_id = st.selectbox(
            "Inspect saved analysis",
            [row["analysis_id"] for row in records],
        )
        detail = db.get_analysis(selected_id)
        if detail:
            st.write(f"**Classification:** {detail['classification']} · **Score:** {detail['risk_score']}/100")
            if detail["indicators"]:
                st.dataframe(
                    pd.DataFrame(detail["indicators"])[
                        ["severity", "indicator_type", "description"]
                    ],
                    hide_index=True,
                    use_container_width=True,
                )
    else:
        st.info("No matching analyses have been saved.")


def dashboard_page(db: Database) -> None:
    st.subheader("Dashboard")
    stats = db.stats()
    cards = st.columns(5)
    for col, label, value in zip(
        cards,
        ["Emails analyzed", "Likely phishing", "Suspicious", "Low risk", "Average score"],
        [
            stats["total"],
            stats["likely_phishing"],
            stats["suspicious"],
            stats["low_risk"],
            stats["average_risk_score"],
        ],
    ):
        col.metric(label, value)

    if not stats["total"]:
        st.info("No shared-history records yet. You can analyze examples without saving them.")
        return

    chart_col, dist_col = st.columns(2)
    chart_col.write("Analyses by classification")
    class_data = pd.DataFrame({"Analyses": stats["by_classification"]})
    chart_col.bar_chart(class_data)
    dist_col.write("Risk score distribution")
    dist_data = pd.DataFrame(stats["score_distribution"]).set_index("bucket")
    dist_col.bar_chart(dist_data)

    trend = pd.DataFrame(stats["trend"]).set_index("date")
    st.write("Recent analysis trend")
    st.line_chart(trend[["total", "flagged"]])

    indicators = db.indicator_stats()
    if indicators["top_indicators"]:
        st.write("Most common indicators")
        st.bar_chart(pd.DataFrame(indicators["top_indicators"]).set_index("indicator_type"))
    if indicators["top_keywords"]:
        st.write("Common matched phrases")
        st.dataframe(
            pd.DataFrame(indicators["top_keywords"]),
            hide_index=True,
            use_container_width=True,
        )


def main() -> None:
    st.set_page_config(page_title="Phishing Detection & Awareness", page_icon="🛡️", layout="wide")
    st.title("Phishing Detection & Awareness")
    st.caption("Defensive email-security dashboard · static analysis · synthetic or authorized content only")
    st.info(
        "Do not enter confidential or personal email content. Analysis runs in memory; "
        "saving history is optional and shares sender-domain/subject metadata with app visitors."
    )

    db = get_database()
    dashboard_tab, analyze_tab, history_tab, learn_tab = st.tabs(
        ["Dashboard", "Analyze", "History", "Awareness"]
    )

    with analyze_tab:
        paste_tab, upload_tab, url_tab = st.tabs(
            ["Paste email", "Upload .eml/.txt", "Check a URL"]
        )
        with paste_tab:
            with st.form("paste_email_form"):
                sender = st.text_input("Sender address", max_chars=320)
                display_name = st.text_input("Sender display name", max_chars=200)
                subject = st.text_input("Subject", max_chars=500)
                body = st.text_area("Email body", max_chars=MAX_BODY_CHARS, height=180)
                attachment_name = st.text_input("Attachment filename (optional)", max_chars=255)
                use_ml = st.checkbox("Use the optional ML model when available", value=True)
                save_history = st.checkbox(
                    "Save sender-domain and subject metadata to shared history (optional)",
                    value=False,
                )
                submitted = st.form_submit_button("Analyze email", type="primary")
            if submitted:
                try:
                    result = analyze_and_store(
                        sender, subject, body, attachment_name, display_name or None,
                        use_ml, save_history,
                    )
                    show_result(result)
                except ValueError as exc:
                    st.error(str(exc))

        with upload_tab:
            st.caption("Only text and attachment filenames are inspected. Attachments are never opened or saved.")
            with st.form("upload_email_form"):
                uploaded = st.file_uploader("Choose a .eml or .txt file", type=["eml", "txt"])
                upload_use_ml = st.checkbox("Use the optional ML model when available", value=True, key="upload_ml")
                upload_save = st.checkbox(
                    "Save sender-domain and subject metadata to shared history (optional)",
                    value=False,
                    key="upload_history",
                )
                upload_submitted = st.form_submit_button("Analyze uploaded email", type="primary")
            if upload_submitted:
                if uploaded is None:
                    st.error("Select an .eml or .txt file first.")
                elif uploaded.size > MAX_EML_BYTES:
                    st.error(f"File exceeds the {MAX_EML_BYTES:,}-byte upload limit.")
                else:
                    try:
                        uploaded_bytes = uploaded.getvalue()
                        parsed = parse_eml(uploaded_bytes)
                        if not parsed["sender"] and not parsed["subject"]:
                            parsed["body"] = uploaded_bytes.decode("utf-8", errors="replace")[:MAX_BODY_CHARS]
                        result = analyze_and_store(
                            parsed["sender"], parsed["subject"], parsed["body"],
                            parsed["attachment_name"], use_ml=upload_use_ml,
                            save_history=upload_save,
                        )
                        show_result(result)
                    except (ValueError, TypeError) as exc:
                        st.error(f"Could not analyze this file: {exc}")

        with url_tab:
            st.caption("URLs are analyzed as text only and are never visited.")
            with st.form("url_form"):
                url = st.text_input("URL", max_chars=2048)
                url_submitted = st.form_submit_button("Analyze URL", type="primary")
            if url_submitted:
                if not url.strip():
                    st.error("Enter a URL to analyze.")
                else:
                    result = analyze_url(url)
                    st.metric("URL risk", f"{result['risk_score']}/100 · {result['risk_level']}")
                    st.code(result["url_safe"], language=None)
                    for finding in result["findings"]:
                        st.text(f"- {finding['severity']}: {finding['description']}")
                    st.caption("Static analysis only; HTTPS does not prove that a site is trustworthy.")

    with dashboard_tab:
        dashboard_page(db)

    with history_tab:
        history_page(db)

    with learn_tab:
        st.subheader("Spot suspicious messages")
        for index, (title, description) in enumerate(TIPS, start=1):
            with st.expander(f"{index}. {title}"):
                st.write(description)
        st.subheader("Before you click")
        completed = 0
        for item in CHECKS:
            completed += st.checkbox(item, key=f"awareness_check_{item}")
        st.progress(completed / len(CHECKS))
        st.caption(f"{completed} of {len(CHECKS)} checks completed.")
        if completed == len(CHECKS):
            st.success("All checks done. If anything still feels wrong, report it instead of clicking.")
        st.subheader("If you already clicked")
        st.write(
            "Disconnect if you suspect malware, report the message to your security team, "
            "and change exposed credentials from the official site or app. Contact your "
            "organisation's IT/security team for incident-specific guidance."
        )


if __name__ == "__main__":
    main()

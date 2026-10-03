import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from backend.database import Database
from streamlit_app import analyze_and_store, get_database


def test_streamlit_app_renders_without_errors():
    app_path = Path(__file__).resolve().parents[1] / "streamlit_app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()

    assert not app.exception


def test_streamlit_analysis_rejects_empty_input():
    with pytest.raises(ValueError, match="at least one"):
        analyze_and_store("", "", "", use_ml=False)


def test_streamlit_history_is_opt_in_and_metadata_only(monkeypatch, tmp_path):
    database_path = tmp_path / "streamlit.db"
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    get_database.clear()
    try:
        result = analyze_and_store(
            "security@example.invalid",
            "Synthetic subject",
            "Unique private body marker",
            use_ml=False,
            save_history=True,
        )
        assert result["analysis_id"] > 0
        assert Database(str(database_path)).get_analysis(result["analysis_id"])

        with sqlite3.connect(database_path) as connection:
            database_dump = "\n".join(connection.iterdump())
        assert "Unique private body marker" not in database_dump
        assert "Synthetic subject" in database_dump
    finally:
        get_database.clear()

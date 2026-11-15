from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import pytest
import numpy as np

from backend.database import SQLiteStore
from backend.parsers import parse_line, parse_records, safe_text
from backend.pipeline import run_pipeline
from src.ingestion import load_log_file

SAMPLE_AUTH_LOG = Path(__file__).resolve().parents[1] / "data" / "logs" / "linux_auth_sample.log"


def _burst_frame(count: int = 7, ip: str = "192.168.1.20", user: str = "admin") -> pd.DataFrame:
    rows = []
    for i in range(count):
        rows.append(
            {
                "timestamp": pd.Timestamp("2026-05-01 10:00:00") + pd.Timedelta(seconds=i * 2),
                "raw_line": f"2026-05-01 10:00:{i:02d} host sshd: Failed password for {user} from {ip} port 58421 ssh2",
                "message": f"Failed password for {user} from {ip}",
                "source_file": "auth.log",
                "source": "auth.log",
                "line_number": i + 1,
            }
        )
    return pd.DataFrame(rows)


def _count(connection: sqlite3.Connection, query: str) -> int:
    return connection.execute(query).fetchone()[0]


def test_full_pipeline_auth_log_consistency(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "integration.db"))
    raw = load_log_file(str(SAMPLE_AUTH_LOG))
    bundle = run_pipeline(raw, contamination=0.12, run_id="integration-run-1", store=store)

    scored = bundle.scored_frame
    assert not scored.empty
    required_columns = {
        "raw_line",
        "message",
        "anomaly_score",
        "prediction",
        "severity",
        "severity_rank",
        "alert_required",
        "alert_message",
        "explanation",
        "risk_score",
        "statistical_score",
        "rule_match_count",
        "rule_weight",
        "context_score",
        "failed_login_count",
        "login_attempt_count",
        "failed_login_ratio",
        "login_burst_score",
    }
    assert required_columns.issubset(scored.columns)

    with sqlite3.connect(str(tmp_path / "integration.db")) as connection:
        assert _count(connection, "SELECT COUNT(*) FROM analysis_runs WHERE run_id = 'integration-run-1'") == 1
        assert _count(connection, "SELECT COUNT(*) FROM events") == len(scored)
        assert _count(connection, "SELECT COUNT(*) FROM alerts") == int(scored["alert_required"].sum())


def test_bruteforce_window_triggers_rule_and_high_severity() -> None:
    bundle = run_pipeline(_burst_frame(7), contamination=0.12, persist=False)
    scored = bundle.scored_frame
    assert scored["failed_login_count"].max() >= 7
    assert scored["failed_login_ratio"].max() == 1.0
    assert (scored["rule_match_count"] >= 1).any()
    assert (scored["severity"] == "High").any()


def test_severity_is_consistent_with_risk_score() -> None:
    raw = load_log_file(str(SAMPLE_AUTH_LOG))
    bundle = run_pipeline(raw, contamination=0.12, persist=False)
    scored = bundle.scored_frame
    for _, row in scored.iterrows():
        if row["risk_score"] >= 75:
            assert row["severity"] == "Critical"
            assert row["alert_required"]
        elif row["risk_score"] >= 50:
            assert row["severity"] == "High"
        elif row["risk_score"] >= 25:
            assert row["severity"] == "Medium"
        else:
            assert row["severity"] == "Low"
        assert row["alert_required"] == (row["severity"] in ["Medium", "High", "Critical"])
        assert row["severity_rank"] == {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[row["severity"]]


def test_duplicate_rerun_does_not_duplicate_alerts_or_events(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "rerun.db"))
    raw = load_log_file(str(SAMPLE_AUTH_LOG))
    run_pipeline(raw, contamination=0.12, store=store, run_id="a")
    first_alert_ids = [a["alert_id"] for a in store.list_alerts()]
    run_pipeline(raw, contamination=0.12, store=store, run_id="b")
    second_alert_ids = [a["alert_id"] for a in store.list_alerts()]

    with sqlite3.connect(str(tmp_path / "rerun.db")) as connection:
        event_count = _count(connection, "SELECT COUNT(*) FROM events")
        run_count = _count(connection, "SELECT COUNT(*) FROM analysis_runs")
    assert run_count == 2
    assert sorted(first_alert_ids) == sorted(second_alert_ids)
    assert event_count == len(raw)


def test_csv_export_contains_unified_fields() -> None:
    from backend.reporting import export_csv_bytes

    raw = load_log_file(str(SAMPLE_AUTH_LOG))
    bundle = run_pipeline(raw, contamination=0.12, persist=False)
    text = export_csv_bytes(bundle.scored_frame).decode("utf-8")
    header = text.splitlines()[0]
    for field in ["risk_score", "severity", "alert_required", "explanation", "failed_login_count", "login_burst_score"]:
        assert field in header


def test_pipeline_handles_numeric_and_missing_log_values() -> None:
    raw = pd.DataFrame(
        {
            "message": [1.0, float("nan"), "INFO user login succeeded"],
            "source_file": ["uploaded.csv"] * 3,
        }
    )

    bundle = run_pipeline(raw, contamination=0.12, persist=False)

    assert len(bundle.scored_frame) == 3
    assert bundle.scored_frame["raw_line"].tolist() == ["1.0", "", "INFO user login succeeded"]


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, ""),
        (np.nan, ""),
        (pd.NA, ""),
        (pd.NaT, ""),
        (123, "123"),
        (123.45, "123.45"),
        (True, "True"),
        (" some log message ", "some log message"),
        ("", ""),
    ],
)
def test_safe_text_normalizes_parser_inputs(value, expected) -> None:
    assert safe_text(value) == expected
    assert parse_line(value)["parse_status"] in {"empty", "unparsed"}


def test_pipeline_handles_mixed_text_types_and_source_values() -> None:
    frame = pd.DataFrame(
        {
            "message": [np.nan, 123.45, "Failed login", None, pd.NA],
            "source_file": [np.nan, "server.log", 123, None, "auth.log"],
            "line_number": [1, 2, 3, 4, 5],
        }
    )

    parsed = parse_records(frame)
    bundle = run_pipeline(frame, contamination=0.12, persist=False)

    assert len(parsed) == len(frame)
    assert len(bundle.scored_frame) == len(frame)
    assert bundle.malformed_count >= 1
    assert bundle.scored_frame["raw_line"].notna().all()
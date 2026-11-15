from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing

from backend.database import SQLiteStore

EXPECTED_TABLES = {
    "alerts",
    "events",
    "analysis_runs",
    "alert_history",
    "rules",
    "model_metadata",
    "monitoring_sources",
    "audit_logs",
    "application_settings",
}


def _table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row[0] for row in rows}


def _index_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    return {row[0] for row in rows}


def test_schema_tables_and_indexes_exist(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "test.db"))
    store.initialize()
    with closing(sqlite3.connect(str(tmp_path / "test.db"))) as connection:
        assert EXPECTED_TABLES.issubset(_table_names(connection))
        indexes = _index_names(connection)
        for expected in [
            "idx_alerts_timestamp",
            "idx_alerts_severity",
            "idx_alerts_source",
            "idx_alerts_status",
            "idx_events_timestamp",
            "idx_events_source_ip",
            "idx_events_username",
        ]:
            assert expected in indexes


def test_sqlite_store_creates_tables_and_writes_alerts() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db_path = os.path.join(directory, "test_monitor.db")
        store = SQLiteStore(db_path)
        store.initialize()

        store.insert_alert(
            alert_id="alert-1",
            timestamp="2026-01-01T00:00:00",
            source="auth.log",
            event="Auth failure",
            detectors=["isolation_forest"],
            risk_score=82.0,
            severity="Critical",
            explanation="High anomaly score",
            status="NEW",
            notes="Initial review",
        )

        with closing(sqlite3.connect(db_path)) as connection:
            row = connection.execute("SELECT alert_id, severity, status FROM alerts WHERE alert_id = ?", ("alert-1",)).fetchone()

        assert row is not None
        assert row[1] == "Critical"
        assert row[2] == "NEW"


def test_alert_dedupe_preserves_status(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "test.db"))
    store.initialize()
    store.upsert_alert_if_changed("alert-x", "t1", "src", "event", ["if"], 90.0, "Critical", "expl", event_key="k1")
    store.update_alert_status("alert-x", "INVESTIGATING", user="analyst", notes="looking")
    store.upsert_alert_if_changed("alert-x", "t1", "src", "event", ["if", "ocsvm"], 95.0, "Critical", "expl2", event_key="k1")
    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["status"] == "INVESTIGATING"
    assert alerts[0]["risk_score"] == 95.0


def test_alert_batch_handles_more_ids_than_sqlite_variable_limit(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "large-batch.db"))
    store.initialize()
    records = [
        {
            "alert_id": f"alert-{index}",
            "timestamp": "2026-01-01T00:00:00",
            "source": "upload.log",
            "event": f"event-{index}",
            "detectors": ["isolation_forest"],
            "risk_score": 80.0,
            "severity": "Critical",
            "explanation": "large upload",
            "status": "NEW",
        }
        for index in range(1200)
    ]

    assert store.upsert_alerts_batch(records) == len(records)
    assert len(store.list_alerts()) == len(records)


def test_event_insert_dedupes_by_event_key(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "test.db"))
    store.initialize()
    first = {"event_key": "abc", "timestamp": "t", "source": "s", "severity": "Low", "risk_score": 1.0, "anomaly_score": 0.1, "prediction": 1, "message": "m", "raw_log": "r"}
    second = dict(first)
    store.insert_event(**{**first, "source_file": "", "source_host": "", "source_ip": "", "username": "", "event_type": "", "analysis_run": "run1"})
    store.insert_event(**{**second, "source_file": "", "source_host": "", "source_ip": "", "username": "", "event_type": "", "analysis_run": "run2"})
    with closing(sqlite3.connect(str(tmp_path / "test.db"))) as connection:
        count = connection.execute("SELECT COUNT(*) FROM events WHERE event_key = 'abc'").fetchone()[0]
    assert count == 1


def test_alert_history_and_audit(tmp_path) -> None:
    store = SQLiteStore(str(tmp_path / "test.db"))
    store.initialize()
    store.insert_alert("alert-x", "t1", "src", "event", ["if"], 50.0, "High", "e", "NEW", "")
    store.update_alert_status("alert-x", "RESOLVED", user="soc1", notes="mitigated")
    store.log_audit("ALERT_RESOLVED", "alert-x resolved")
    history = store.list_history("alert-x")
    assert any(entry["action"] == "RESOLVED" for entry in history)
    with closing(sqlite3.connect(str(tmp_path / "test.db"))) as connection:
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'ALERT_RESOLVED'").fetchone()[0]
    assert audit_count == 1
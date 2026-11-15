from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing

from backend.database import SQLiteStore


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

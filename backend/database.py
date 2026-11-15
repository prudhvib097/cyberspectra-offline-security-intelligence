from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Iterable

import pandas as pd


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Evidence columns added after the first schema version (additive migration).
EVENT_EXTRA_COLUMNS = [
    ("statistical_score", "REAL"),
    ("rule_match_count", "INTEGER"),
    ("rule_weight", "REAL"),
    ("context_score", "REAL"),
    ("failed_login_count", "INTEGER"),
    ("destination_ip", "TEXT"),
    ("action", "TEXT"),
    ("protocol", "TEXT"),
    ("port", "TEXT"),
    ("explanation", "TEXT"),
    ("algorithm", "TEXT"),
    ("event_rate_per_min", "REAL"),
    ("login_burst_score", "REAL"),
    ("off_hours", "INTEGER"),
    ("unique_source_ips_window", "INTEGER"),
    ("alert_keyword_count", "INTEGER"),
]
EVENT_FILTER_COLUMNS = {"severity", "source", "source_file", "event_type", "analysis_run"}


@contextmanager
def _conn(db_path: str) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


class SQLiteStore:
    """SQLite persistence for events, alerts, runs, history and settings.

    Every timestamp is stored as an ISO-8601 UTC string. The alerts table
    keyed by alert_id is kept for backward compatibility with the original
    project; the event/alert signature keys provide duplicate prevention.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or os.environ.get("CYBERSPECTRA_DB") or os.path.join(os.getcwd(), "data", "monitoring.db")
        parent = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(parent, exist_ok=True)

    def initialize(self) -> None:
        with _conn(self.db_path) as connection:
            had_notifications = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_state'"
            ).fetchone() is not None
        self._create_tables()
        self._migrate()
        self._create_indexes()
        if not had_notifications:
            # First run with notification tracking: alerts that already exist
            # were never "new", so they must not trigger a popup. They stay
            # unacknowledged and still count on the bell.
            with _conn(self.db_path) as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO notification_state (alert_id, notified_at) SELECT alert_id, ? FROM alerts",
                    (_utcnow(),),
                )

    def _migrate(self) -> None:
        """Add columns introduced in later schema versions to pre-existing tables."""
        with _conn(self.db_path) as connection:
            current = {row[1] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()}
            for column, definition in [
                ("event_key", "TEXT"),
                ("updated_at", "TEXT"),
                ("created_at", "TEXT"),
            ]:
                if column not in current:
                    connection.execute(f"ALTER TABLE alerts ADD COLUMN {column} {definition}")
            event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()}
            for column, definition in EVENT_EXTRA_COLUMNS:
                if column not in event_columns:
                    connection.execute(f"ALTER TABLE events ADD COLUMN {column} {definition}")

    def _column_names(self, table: str) -> set[str]:
        with _conn(self.db_path) as connection:
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        return {row[1] for row in rows}

    def _create_tables(self) -> None:
        with _conn(self.db_path) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detectors TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    event_key TEXT,
                    updated_at TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT UNIQUE,
                    timestamp TEXT,
                    source TEXT,
                    source_file TEXT,
                    source_host TEXT,
                    source_ip TEXT,
                    username TEXT,
                    event_type TEXT,
                    severity TEXT,
                    risk_score REAL,
                    anomaly_score REAL,
                    prediction INTEGER,
                    message TEXT,
                    raw_log TEXT,
                    analysis_run TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    timestamp_start TEXT NOT NULL,
                    timestamp_end TEXT,
                    sources TEXT,
                    total_records INTEGER,
                    anomalies INTEGER,
                    algorithm TEXT,
                    contamination REAL,
                    status TEXT
                );

                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    notes TEXT,
                    user TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    enabled INTEGER NOT NULL,
                    condition TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    severity TEXT NOT NULL,
                    weight REAL NOT NULL,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS model_metadata (
                    model_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT,
                    trained_at TEXT,
                    algorithm TEXT NOT NULL,
                    parameters TEXT,
                    features TEXT,
                    dataset TEXT,
                    validation TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS monitoring_sources (
                    source_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    path_or_channel TEXT,
                    config TEXT,
                    last_checkpoint TEXT,
                    last_event_time TEXT,
                    status TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS application_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                -- Notification state is tracked apart from the alert itself, so
                -- acknowledging a notification never alters or deletes an alert.
                CREATE TABLE IF NOT EXISTS notification_state (
                    alert_id TEXT PRIMARY KEY,
                    notified_at TEXT,
                    acknowledged_at TEXT
                );
                """
            )

    def _create_indexes(self) -> None:
        with _conn(self.db_path) as connection:
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_score);

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
                CREATE INDEX IF NOT EXISTS idx_events_run ON events(analysis_run);
                CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk_score);
                CREATE INDEX IF NOT EXISTS idx_events_host ON events(source_host);
                CREATE INDEX IF NOT EXISTS idx_events_key ON events(event_key);

                CREATE INDEX IF NOT EXISTS idx_history_alert ON alert_history(alert_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
                """
            )

    def insert_alert(self, alert_id: str, timestamp: str, source: str, event: str, detectors: list[str], risk_score: float, severity: str, explanation: str, status: str, notes: str, event_key: str | None = None) -> None:
        now = _utcnow()
        with _conn(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, source, event, detectors, risk_score, severity, explanation, status, notes, event_key, updated_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    str(timestamp),
                    str(source),
                    str(event),
                    ",".join(detectors),
                    float(risk_score),
                    str(severity),
                    str(explanation),
                    str(status),
                    str(notes),
                    event_key,
                    now,
                    now,
                ),
            )

    def upsert_alert_if_changed(self, alert_id: str, timestamp: str, source: str, event: str, detectors: list[str], risk_score: float, severity: str, explanation: str, event_key: str | None = None, status: str = "NEW") -> None:
        """Deduplicated alert write: refreshes severity/explanation on re-analysis
        but keeps the analyst's lifecycle status (NEW/ACKNOWLEDGED/...)."""
        now = _utcnow()
        with _conn(self.db_path) as connection:
            existing = connection.execute("SELECT status, notes, created_at FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            final_status = existing[0] if existing else status
            notes = existing[1] if existing else ""
            created_at = existing[2] if existing and existing[2] else now
            connection.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, source, event, detectors, risk_score, severity, explanation, status, notes, event_key, updated_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    str(timestamp),
                    str(source),
                    str(event),
                    ",".join(detectors),
                    float(risk_score),
                    str(severity),
                    str(explanation),
                    final_status,
                    notes,
                    event_key,
                    now,
                    created_at,
                ),
            )

    def upsert_alerts_batch(self, records: Iterable[dict[str, Any]]) -> int:
        """Upsert alerts in one transaction while preserving existing statuses."""
        rows = list(records)
        if not rows:
            return 0
        now = _utcnow()
        with _conn(self.db_path) as connection:
            alert_ids = [str(record["alert_id"]) for record in rows]
            existing_rows = []
            # SQLite limits the number of bound variables in one statement.
            # Keep the lookup below that limit for large dashboard uploads.
            variable_limit = connection.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
            chunk_size = max(1, min(variable_limit, 500))
            for start in range(0, len(alert_ids), chunk_size):
                alert_id_chunk = alert_ids[start : start + chunk_size]
                placeholders = ",".join("?" for _ in alert_id_chunk)
                existing_rows.extend(
                    connection.execute(
                        f"SELECT alert_id, status, notes, created_at FROM alerts WHERE alert_id IN ({placeholders})",
                        alert_id_chunk,
                    ).fetchall()
                )
            existing = {row[0]: row[1:] for row in existing_rows}
            values = []
            for record in rows:
                alert_id = str(record["alert_id"])
                prior = existing.get(alert_id)
                status = str(prior[0] if prior else record.get("status", "NEW"))
                notes = str(prior[1] if prior and prior[1] is not None else "")
                created_at = str(prior[2] if prior and prior[2] else now)
                values.append(
                    (
                        alert_id,
                        str(record.get("timestamp", "")),
                        str(record.get("source", "")),
                        str(record.get("event", "")),
                        ",".join(str(detector) for detector in record.get("detectors", [])),
                        float(record.get("risk_score", 0.0) or 0.0),
                        str(record.get("severity", "Low")),
                        str(record.get("explanation", "")),
                        status,
                        notes,
                        record.get("event_key"),
                        now,
                        created_at,
                    )
                )
            connection.executemany(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, source, event, detectors, risk_score, severity,
                    explanation, status, notes, event_key, updated_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        return len(values)

    def record_analysis_run(self, run_id: str, timestamp_start: str, status: str = "completed", timestamp_end: str | None = None, sources: str = "", total_records: int = 0, anomalies: int = 0, algorithm: str = "", contamination: float = 0.0) -> None:
        with _conn(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO analysis_runs (
                    run_id, timestamp_start, timestamp_end, sources, total_records, anomalies, algorithm, contamination, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, timestamp_start, timestamp_end, sources, int(total_records), int(anomalies), algorithm, float(contamination), status),
            )

    def insert_event(self, event_key: str, timestamp: str, source: str, source_file: str, source_host: str, source_ip: str, username: str, event_type: str, severity: str, risk_score: float, anomaly_score: float, prediction: int, message: str, raw_log: str, analysis_run: str) -> None:
        with _conn(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_key, timestamp, source, source_file, source_host, source_ip, username,
                    event_type, severity, risk_score, anomaly_score, prediction, message, raw_log, analysis_run, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_key,
                    str(timestamp),
                    str(source),
                    str(source_file),
                    str(source_host),
                    str(source_ip),
                    str(username),
                    str(event_type),
                    str(severity),
                    float(risk_score),
                    float(anomaly_score),
                    int(prediction),
                    str(message),
                    str(raw_log),
                    analysis_run,
                    _utcnow(),
                ),
            )

    def insert_events_batch(self, records: Iterable[dict[str, Any]]) -> int:
        """Insert events in one transaction with executemany (duplicates ignored)."""
        now = _utcnow()
        columns = [
            "event_key", "timestamp", "source", "source_file", "source_host", "source_ip", "username",
            "event_type", "severity", "risk_score", "anomaly_score", "prediction", "message", "raw_log",
            "analysis_run", "statistical_score", "rule_match_count", "rule_weight", "context_score",
            "failed_login_count", "destination_ip", "action", "protocol", "port", "explanation", "algorithm",
            "event_rate_per_min", "login_burst_score", "off_hours", "unique_source_ips_window", "alert_keyword_count",
        ]
        rows = [tuple(record.get(column) for column in columns) + (now,) for record in records]
        if not rows:
            return 0
        sql = f"INSERT OR IGNORE INTO events ({', '.join(columns)}, created_at) VALUES ({', '.join('?' for _ in range(len(columns) + 1))})"
        with _conn(self.db_path) as connection:
            before = connection.total_changes
            connection.executemany(sql, rows)
            return connection.total_changes - before

    EVENT_INSERT_COLUMNS = [
        "event_key", "timestamp", "source", "source_file", "source_host", "source_ip", "username",
        "event_type", "severity", "risk_score", "anomaly_score", "prediction", "message", "raw_log",
        "analysis_run", "statistical_score", "rule_match_count", "rule_weight", "context_score",
        "failed_login_count", "destination_ip", "action", "protocol", "port", "explanation", "algorithm",
        "event_rate_per_min", "login_burst_score", "off_hours", "unique_source_ips_window", "alert_keyword_count",
    ]

    def insert_events_frame(self, frame: pd.DataFrame) -> int:
        """Bulk-insert a frame whose columns are ``EVENT_INSERT_COLUMNS`` (duplicates ignored).

        Uses plain tuples instead of per-row dicts, which is several times
        faster than ``insert_events_batch`` on 100K+ rows.
        """
        if frame.empty:
            return 0
        columns = self.EVENT_INSERT_COLUMNS
        now = _utcnow()
        rows = [row + (now,) for row in frame[columns].itertuples(index=False, name=None)]
        sql = f"INSERT OR IGNORE INTO events ({', '.join(columns)}, created_at) VALUES ({', '.join('?' for _ in range(len(columns) + 1))})"
        with _conn(self.db_path) as connection:
            before = connection.total_changes
            connection.executemany(sql, rows)
            return connection.total_changes - before

    # ------------------------------------------------------------------
    # Event explorer (database-side filtering + pagination)
    # ------------------------------------------------------------------
    def query_events(
        self,
        *,
        search: str = "",
        severities: Iterable[str] | None = None,
        sources: Iterable[str] | None = None,
        event_types: Iterable[str] | None = None,
        run_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        sort_by: str = "timestamp",
        descending: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[pd.DataFrame, int]:
        """Return one page of events plus the total number of matches."""
        where, params = self._event_where(search, severities, sources, event_types, run_id, date_from, date_to)
        sort_column = sort_by if sort_by in {"timestamp", "risk_score", "severity", "source", "event_type", "anomaly_score"} else "timestamp"
        direction = "DESC" if descending else "ASC"
        with _conn(self.db_path) as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]
            frame = pd.read_sql_query(
                f"SELECT * FROM events{where} ORDER BY {sort_column} {direction}, id DESC LIMIT ? OFFSET ?",
                connection,
                params=[*params, max(1, int(limit)), max(0, int(offset))],
            )
        return frame, int(total)

    @staticmethod
    def _event_where(search, severities, sources, event_types, run_id, date_from, date_to) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, values in (("severity", severities), ("source_file", sources), ("event_type", event_types)):
            values = [str(v) for v in (values or [])]
            if values:
                clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
                params.extend(values)
        if run_id:
            clauses.append("analysis_run = ?")
            params.append(run_id)
        if date_from:
            clauses.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("timestamp <= ?")
            params.append(date_to)
        term = (search or "").strip()
        if term:
            like = f"%{term}%"
            clauses.append("(event_key LIKE ? OR source_ip LIKE ? OR source_host LIKE ? OR username LIKE ? OR message LIKE ?)")
            params.extend([like] * 5)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def distinct_values(self, column: str, limit: int = 200) -> list[str]:
        if column not in EVENT_FILTER_COLUMNS:
            return []
        with _conn(self.db_path) as connection:
            rows = connection.execute(
                f"SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL AND {column} != '' ORDER BY {column} LIMIT ?", (limit,)
            ).fetchall()
        return [row[0] for row in rows]

    def query_alerts(self, *, search: str = "", severities: Iterable[str] | None = None, statuses: Iterable[str] | None = None, limit: int = 50, offset: int = 0, sort_by: str = "timestamp", descending: bool = True) -> tuple[pd.DataFrame, int]:
        """One page of alerts plus the detector evidence of the event that raised each one."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, values in (("a.severity", severities), ("a.status", statuses)):
            values = [str(v) for v in (values or [])]
            if values:
                clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
                params.extend(values)
        term = (search or "").strip()
        if term:
            clauses.append("(a.event LIKE ? OR a.source LIKE ? OR a.alert_id LIKE ?)")
            params.extend([f"%{term}%"] * 3)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        order_map = {
            "timestamp": "a.timestamp", "risk_score": "a.risk_score", "status": "a.status", "source": "a.source",
            "severity": "CASE a.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END",
        }
        order = order_map.get(sort_by, "a.timestamp")
        direction = "DESC" if descending else "ASC"
        with _conn(self.db_path) as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM alerts a{where}", params).fetchone()[0]
            frame = pd.read_sql_query(
                f"""SELECT a.*, e.prediction AS prediction, e.statistical_score AS statistical_score,
                           e.rule_match_count AS rule_match_count, e.algorithm AS algorithm
                    FROM alerts a LEFT JOIN events e ON e.event_key = a.event_key{where}
                    ORDER BY {order} {direction}, a.risk_score DESC LIMIT ? OFFSET ?""",
                connection,
                params=[*params, max(1, int(limit)), max(0, int(offset))],
            )
        return frame, int(total)

    def get_event(self, event_key: str) -> dict[str, Any] | None:
        with _conn(self.db_path) as connection:
            frame = pd.read_sql_query("SELECT * FROM events WHERE event_key = ? LIMIT 1", connection, params=[event_key])
        return None if frame.empty else frame.iloc[0].to_dict()

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with _conn(self.db_path) as connection:
            frame = pd.read_sql_query("SELECT * FROM alerts WHERE alert_id = ? LIMIT 1", connection, params=[alert_id])
        return None if frame.empty else frame.iloc[0].to_dict()

    # ------------------------------------------------------------------
    # Critical-alert notifications (separate from the alert lifecycle)
    # ------------------------------------------------------------------
    def new_critical_alerts(self) -> pd.DataFrame:
        """Critical alerts whose first in-app notification has not been shown."""
        with _conn(self.db_path) as connection:
            return pd.read_sql_query(
                """
                SELECT a.alert_id, a.timestamp, a.source, a.event, a.risk_score, a.severity
                FROM alerts a LEFT JOIN notification_state n ON n.alert_id = a.alert_id
                WHERE a.severity = 'Critical' AND n.notified_at IS NULL
                ORDER BY a.risk_score DESC, a.timestamp DESC
                """,
                connection,
            )

    def mark_notified(self, alert_ids: Iterable[str]) -> None:
        now = _utcnow()
        rows = [(str(a), now) for a in alert_ids]
        if not rows:
            return
        with _conn(self.db_path) as connection:
            connection.executemany(
                "INSERT INTO notification_state (alert_id, notified_at) VALUES (?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET notified_at = COALESCE(notification_state.notified_at, excluded.notified_at)",
                rows,
            )

    def acknowledge_notifications(self, alert_ids: Iterable[str] | None = None) -> int:
        """Acknowledge notifications (all unacknowledged criticals when ids is None)."""
        now = _utcnow()
        with _conn(self.db_path) as connection:
            if alert_ids is None:
                ids = [r[0] for r in connection.execute(
                    "SELECT a.alert_id FROM alerts a LEFT JOIN notification_state n ON n.alert_id = a.alert_id "
                    "WHERE a.severity = 'Critical' AND n.acknowledged_at IS NULL").fetchall()]
            else:
                ids = [str(a) for a in alert_ids]
            connection.executemany(
                "INSERT INTO notification_state (alert_id, notified_at, acknowledged_at) VALUES (?, ?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET acknowledged_at = excluded.acknowledged_at, "
                "notified_at = COALESCE(notification_state.notified_at, excluded.notified_at)",
                [(i, now, now) for i in ids],
            )
        return len(ids)

    def unacknowledged_critical_count(self) -> int:
        with _conn(self.db_path) as connection:
            return int(connection.execute(
                "SELECT COUNT(*) FROM alerts a LEFT JOIN notification_state n ON n.alert_id = a.alert_id "
                "WHERE a.severity = 'Critical' AND n.acknowledged_at IS NULL").fetchone()[0])

    def list_notifications(self, limit: int = 25) -> pd.DataFrame:
        with _conn(self.db_path) as connection:
            return pd.read_sql_query(
                """
                SELECT a.alert_id, a.timestamp, a.source, a.event, a.risk_score, a.severity, a.status,
                       n.acknowledged_at
                FROM alerts a LEFT JOIN notification_state n ON n.alert_id = a.alert_id
                WHERE a.severity = 'Critical'
                ORDER BY (n.acknowledged_at IS NOT NULL), a.timestamp DESC LIMIT ?
                """,
                connection,
                params=[max(1, int(limit))],
            )

    def update_alert_status(self, alert_id: str, status: str, user: str | None = None, notes: str | None = None) -> None:
        now = _utcnow()
        with _conn(self.db_path) as connection:
            connection.execute("UPDATE alerts SET status = ?, notes = COALESCE(?, notes), updated_at = ? WHERE alert_id = ?", (status, notes, now, alert_id))
            connection.execute(
                "INSERT INTO alert_history (alert_id, action, notes, user, timestamp) VALUES (?, ?, ?, ?, ?)",
                (alert_id, status, notes, user, now),
            )

    def add_alert_history(self, alert_id: str, action: str, notes: str | None = None, user: str | None = None) -> None:
        with _conn(self.db_path) as connection:
            connection.execute(
                "INSERT INTO alert_history (alert_id, action, notes, user, timestamp) VALUES (?, ?, ?, ?, ?)",
                (alert_id, action, notes, user, _utcnow()),
            )

    def list_alerts(self, status: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT alert_id, timestamp, source, event, detectors, risk_score, severity, explanation, status, notes FROM alerts"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY timestamp DESC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        with _conn(self.db_path) as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "alert_id": row[0],
                "timestamp": row[1],
                "source": row[2],
                "event": row[3],
                "detectors": row[4].split(",") if row[4] else [],
                "risk_score": float(row[5]),
                "severity": row[6],
                "explanation": row[7],
                "status": row[8],
                "notes": row[9],
            }
            for row in rows
        ]

    def list_analysis_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent analysis runs with their persisted alert counts."""
        self.initialize()
        with _conn(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    r.run_id, r.timestamp_start, r.timestamp_end, r.sources,
                    r.total_records, r.anomalies, r.algorithm, r.contamination,
                    r.status,
                    SUM(CASE WHEN e.severity IN ('Medium', 'High', 'Critical') THEN 1 ELSE 0 END)
                FROM analysis_runs AS r
                LEFT JOIN events AS e ON e.analysis_run = r.run_id
                GROUP BY r.run_id
                ORDER BY r.timestamp_start DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [
            {
                "run_id": row[0],
                "timestamp_start": row[1],
                "timestamp_end": row[2],
                "sources": row[3],
                "total_records": int(row[4] or 0),
                "anomalies": int(row[5] or 0),
                "algorithm": row[6],
                "contamination": float(row[7] or 0.0),
                "status": row[8],
                "alerts": int(row[9] or 0),
            }
            for row in rows
        ]

    def list_events_for_run(self, run_id: str, limit: int = 10_000) -> pd.DataFrame:
        """Load persisted analyzed logs for one historical run."""
        self.initialize()
        query = """
            SELECT timestamp, severity, risk_score, anomaly_score, prediction,
                   source, source_file, source_ip, username, event_type, message,
                   raw_log, analysis_run
            FROM events
            WHERE analysis_run = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """
        with _conn(self.db_path) as connection:
            return pd.read_sql_query(query, connection, params=(run_id, max(1, int(limit))))

    def list_history(self, alert_id: str) -> list[dict[str, Any]]:
        with _conn(self.db_path) as connection:
            rows = connection.execute(
                "SELECT id, alert_id, action, notes, user, timestamp FROM alert_history WHERE alert_id = ? ORDER BY timestamp",
                (alert_id,),
            ).fetchall()
        return [
            {"id": row[0], "alert_id": row[1], "action": row[2], "notes": row[3], "user": row[4], "timestamp": row[5]}
            for row in rows
        ]

    def log_audit(self, action: str, details: str) -> None:
        with _conn(self.db_path) as connection:
            connection.execute(
                "INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)",
                (_utcnow(), action, details),
            )

    def set_setting(self, key: str, value: str) -> None:
        with _conn(self.db_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO application_settings (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_setting(self, key: str) -> str | None:
        with _conn(self.db_path) as connection:
            row = connection.execute("SELECT value FROM application_settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def list_recent_events(self, limit: int = 1000) -> pd.DataFrame:
        """Return recent scored events for threshold baselining."""
        with _conn(self.db_path) as connection:
            rows = connection.execute(
                "SELECT timestamp, source, event_type, severity, risk_score, anomaly_score FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        if not rows:
            return pd.DataFrame()
        frame = pd.DataFrame(
            rows,
            columns=["timestamp", "source", "event_type", "severity", "risk_score", "anomaly_score"],
        )
        frame["risk_score"] = pd.to_numeric(frame["risk_score"], errors="coerce").fillna(0.0)
        frame["anomaly_score"] = pd.to_numeric(frame["anomaly_score"], errors="coerce").fillna(0.0)
        return frame
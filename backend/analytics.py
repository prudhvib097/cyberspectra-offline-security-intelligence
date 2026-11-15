"""Read-only analytics over the persisted SQLite data.

The dashboard calls these functions and only draws the results. Every number is
computed in SQL from rows the canonical pipeline persisted; nothing is invented
and nothing is added together across detectors without being labelled.

Scope: every function accepts ``run_id`` (limit to one analysis run, or ``None``
for everything) and ``since`` (an ISO ``YYYY-MM-DD HH:MM:SS`` lower bound on the
event timestamp, or ``None``).
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import Any

import pandas as pd

from backend.config import load_config
from backend.database import SQLiteStore

SEVERITIES = ["Critical", "High", "Medium", "Low"]
# Same threshold the explanation text uses for "strong" detector evidence.
STRONG_SIGNAL = 0.6
VALID_TS = "timestamp GLOB '[12][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*'"
TIME_RANGES = {"1H": timedelta(hours=1), "6H": timedelta(hours=6), "24H": timedelta(hours=24), "7D": timedelta(days=7), "30D": timedelta(days=30), "ALL": None}


def _connect(store: SQLiteStore) -> sqlite3.Connection:
    connection = sqlite3.connect(store.db_path)
    connection.row_factory = sqlite3.Row
    return connection


def _scope(run_id: str | None, since: str | None, with_time: bool = True) -> tuple[str, list[Any]]:
    clauses, params = ["1=1"], []
    if run_id:
        clauses.append("analysis_run = ?")
        params.append(run_id)
    if since and with_time:
        clauses.append(f"{VALID_TS} AND timestamp >= ?")
        params.append(since)
    return " AND ".join(clauses), params


def _query(store: SQLiteStore, sql: str, params: list[Any] | tuple = ()) -> pd.DataFrame:
    with closing(_connect(store)) as connection:
        return pd.read_sql_query(sql, connection, params=list(params))


def signature(store: SQLiteStore) -> tuple:
    """Cheap fingerprint of the persisted data; used as a cache key."""
    with closing(_connect(store)) as connection:
        events = connection.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM events").fetchone()
        alerts = connection.execute("SELECT COUNT(*), COALESCE(MAX(updated_at), '') FROM alerts").fetchone()
        ack = connection.execute("SELECT COUNT(acknowledged_at) FROM notification_state").fetchone()
    return (events[0], events[1], alerts[0], alerts[1], ack[0])


def latest_run(store: SQLiteStore) -> dict[str, Any] | None:
    runs = store.list_analysis_runs(limit=1)
    return runs[0] if runs else None


def data_extent(store: SQLiteStore, run_id: str | None = None) -> tuple[str | None, str | None]:
    where, params = _scope(run_id, None)
    frame = _query(store, f"SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM events WHERE {where} AND {VALID_TS}", params)
    lo, hi = frame.iloc[0]["lo"], frame.iloc[0]["hi"]
    return (None if lo is None or pd.isna(lo) else str(lo), None if hi is None or pd.isna(hi) else str(hi))


def since_for_range(store: SQLiteStore, range_key: str, run_id: str | None = None) -> str | None:
    """Lower time bound for a range, measured back from the newest event.

    Logs are usually historical, so the window is relative to the latest event
    timestamp in scope (not the wall clock). ``ALL`` returns ``None``.
    """
    delta = TIME_RANGES.get(range_key)
    if delta is None:
        return None
    _, hi = data_extent(store, run_id)
    if hi is None:
        return None
    return str(pd.Timestamp(hi) - delta)[:19]


def kpis(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> dict[str, Any]:
    where, params = _scope(run_id, since)
    row = _query(
        store,
        f"""SELECT COUNT(*) AS total,
                   COALESCE(SUM(prediction = -1), 0) AS anomalies,
                   COALESCE(SUM(severity IN ('High','Critical')), 0) AS high_risk,
                   COALESCE(SUM(severity = 'Critical'), 0) AS critical,
                   COALESCE(SUM(severity IN ('Medium','High','Critical')), 0) AS alert_events,
                   AVG(risk_score) AS avg_risk, MAX(risk_score) AS max_risk
            FROM events WHERE {where}""",
        params,
    ).iloc[0]
    total = int(row["total"] or 0)
    return {
        "total": total,
        "anomalies": int(row["anomalies"]),
        "high_risk": int(row["high_risk"]),
        "critical": int(row["critical"]),
        "alert_events": int(row["alert_events"]),
        "avg_risk": None if row["avg_risk"] is None or pd.isna(row["avg_risk"]) else float(row["avg_risk"]),
        "max_risk": None if row["max_risk"] is None or pd.isna(row["max_risk"]) else float(row["max_risk"]),
    }


def severity_counts(store: SQLiteStore, run_id: str | None = None, since: str | None = None, table: str = "events") -> dict[str, int]:
    if table == "alerts":
        frame = _query(store, "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")
    else:
        where, params = _scope(run_id, since)
        frame = _query(store, f"SELECT severity, COUNT(*) AS n FROM events WHERE {where} GROUP BY severity", params)
    counts = {name: 0 for name in SEVERITIES}
    for severity, n in zip(frame["severity"], frame["n"]):
        if severity in counts:
            counts[severity] = int(n)
    return counts


def activity_series(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> tuple[pd.DataFrame, str]:
    """Events / anomalies / alert-severity events per time bucket plus the bucket unit."""
    where, params = _scope(run_id, since)
    lo, hi = data_extent(store, run_id)
    if lo is None:
        return pd.DataFrame(columns=["bucket", "events", "anomalies", "alerts"]), "hour"
    span = pd.Timestamp(hi) - pd.Timestamp(since or lo)
    if span <= timedelta(hours=2):
        width, unit = 16, "minute"
    elif span <= timedelta(days=3):
        width, unit = 13, "hour"
    else:
        width, unit = 10, "day"
    frame = _query(
        store,
        f"""SELECT substr(timestamp, 1, {width}) AS bucket, COUNT(*) AS events,
                   SUM(prediction = -1) AS anomalies,
                   SUM(severity IN ('Medium','High','Critical')) AS alerts
            FROM events WHERE {where} AND {VALID_TS} GROUP BY bucket ORDER BY bucket""",
        params,
    )
    return frame, unit


def risk_histogram(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> pd.DataFrame:
    boundaries = load_config().get("risk", {}).get("severity_boundaries", {})
    low, medium, high = (float(boundaries.get(k, d)) for k, d in (("low", 25), ("medium", 50), ("high", 75)))
    where, params = _scope(run_id, since)
    row = _query(
        store,
        f"""SELECT COALESCE(SUM(risk_score < ?), 0) AS low_n,
                   COALESCE(SUM(risk_score >= ? AND risk_score < ?), 0) AS med_n,
                   COALESCE(SUM(risk_score >= ? AND risk_score < ?), 0) AS high_n,
                   COALESCE(SUM(risk_score >= ?), 0) AS crit_n FROM events WHERE {where}""",
        [low, low, medium, medium, high, high, *params],
    ).iloc[0]
    fmt = lambda a, b: f"{int(a)}–{int(b) - 1}"
    return pd.DataFrame(
        {
            "range": [fmt(0, low), fmt(low, medium), fmt(medium, high), f"{int(high)}–100"],
            "severity": ["Low", "Medium", "High", "Critical"],
            "count": [int(row["low_n"]), int(row["med_n"]), int(row["high_n"]), int(row["crit_n"])],
        }
    )


def detection_sources(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> dict[str, Any]:
    """Per-detector signals, deliberately kept separate from unique event counts.

    One event can trip several detectors, so ``signals`` must never be summed
    into a count of events; ``unique_flagged`` is the de-duplicated union.
    """
    where, params = _scope(run_id, since)
    row = _query(
        store,
        f"""SELECT
              COALESCE(SUM(prediction = -1 AND COALESCE(algorithm,'isolation_forest') = 'isolation_forest'), 0) AS iforest,
              COALESCE(SUM(prediction = -1 AND algorithm = 'one_class_svm'), 0) AS ocsvm,
              COALESCE(SUM(statistical_score >= {STRONG_SIGNAL}), 0) AS stat,
              COALESCE(SUM(rule_match_count > 0), 0) AS rules,
              COALESCE(SUM(prediction = -1 OR statistical_score >= {STRONG_SIGNAL} OR rule_match_count > 0), 0) AS unique_flagged,
              COALESCE(SUM(severity IN ('Medium','High','Critical')), 0) AS alerts
            FROM events WHERE {where}""",
        params,
    ).iloc[0]
    return {
        "signals": {
            "Isolation Forest": int(row["iforest"]),
            "One-Class SVM": int(row["ocsvm"]),
            "Statistical Detection": int(row["stat"]),
            "Rule Engine": int(row["rules"]),
        },
        "unique_flagged": int(row["unique_flagged"]),
        "alerts": int(row["alerts"]),
    }


def activity_heatmap(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> pd.DataFrame | None:
    """Weekday x hour matrix, or ``None`` when the data is too thin to be meaningful."""
    where, params = _scope(run_id, since)
    frame = _query(
        store,
        f"""SELECT CAST(strftime('%w', substr(timestamp,1,19)) AS INTEGER) AS dow,
                   CAST(substr(timestamp, 12, 2) AS INTEGER) AS hour, COUNT(*) AS n,
                   COUNT(DISTINCT substr(timestamp, 1, 10)) AS days
            FROM events WHERE {where} AND {VALID_TS} AND length(timestamp) >= 13 GROUP BY dow, hour""",
        params,
    )
    if frame.empty or int(frame["n"].sum()) < 20 or frame["hour"].nunique() < 3:
        return None
    matrix = frame.pivot(index="dow", columns="hour", values="n").reindex(index=range(7), columns=range(24)).fillna(0)
    return matrix


def top_entities(store: SQLiteStore, column: str, limit: int = 8, run_id: str | None = None, since: str | None = None) -> pd.DataFrame:
    if column not in {"source_ip", "source_host", "username"}:
        raise ValueError(f"Unsupported entity column: {column}")
    where, params = _scope(run_id, since)
    return _query(
        store,
        f"""SELECT {column} AS entity, COUNT(*) AS events, COALESCE(SUM(prediction = -1), 0) AS anomalies,
                   MAX(risk_score) AS max_risk
            FROM events WHERE {where} AND {column} IS NOT NULL AND {column} NOT IN ('', 'nan', 'None', 'unknown')
            GROUP BY {column} ORDER BY anomalies DESC, events DESC LIMIT ?""",
        [*params, limit],
    )


def engineered_signals(store: SQLiteStore, run_id: str | None = None, since: str | None = None) -> dict[str, Any]:
    """Summary of the engineered behavioural features that were persisted."""
    where, params = _scope(run_id, since)
    row = _query(
        store,
        f"""SELECT COUNT(*) AS n,
                   COALESCE(SUM(failed_login_count > 0), 0) AS failed_events, COALESCE(MAX(failed_login_count), 0) AS max_failed,
                   COALESCE(MAX(event_rate_per_min), 0) AS max_rate, AVG(event_rate_per_min) AS avg_rate,
                   COALESCE(SUM(alert_keyword_count > 0), 0) AS error_events,
                   COUNT(DISTINCT NULLIF(source_ip, '')) AS unique_ips, COALESCE(MAX(unique_source_ips_window), 0) AS max_ips_window,
                   COALESCE(SUM(off_hours = 1), 0) AS off_hours_events,
                   COALESCE(SUM(login_burst_score >= 1.0), 0) AS burst_events, COALESCE(MAX(login_burst_score), 0) AS max_burst
            FROM events WHERE {where}""",
        params,
    ).iloc[0]
    return {key: (None if pd.isna(value) else float(value)) for key, value in row.items()}


def recent_alerts(store: SQLiteStore, limit: int = 200) -> pd.DataFrame:
    return _query(
        store,
        "SELECT alert_id, severity, timestamp, event, source, detectors, risk_score, status FROM alerts "
        "ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, risk_score DESC, timestamp DESC LIMIT ?",
        [limit],
    )


def run_summary(store: SQLiteStore, run_id: str) -> dict[str, Any] | None:
    frame = _query(store, "SELECT * FROM analysis_runs WHERE run_id = ?", [run_id])
    return None if frame.empty else frame.iloc[0].to_dict()

"""Regression tests for the SOC upgrade: vectorized rules, analytics, notifications, monitor, UI smoke, offline assets."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from backend import analytics
from backend.database import SQLiteStore
from backend.monitoring import ContinuousOfflineMonitor
from backend.pipeline import run_pipeline
from backend.rules import RuleDefinition, RuleEngine
from src.model import LogAnomalyModel

ROOT = Path(__file__).resolve().parents[1]


def _bruteforce(n: int = 40) -> pd.DataFrame:
    rows = []
    for i in range(n):
        ts = pd.Timestamp("2026-05-01 10:00:00") + pd.Timedelta(seconds=i)
        line = f"{ts:%Y-%m-%d %H:%M:%S} host sshd: Failed password for root from 203.0.113.9 port 5{i:04d} ssh2"
        rows.append({"timestamp": ts, "raw_line": line, "message": line, "source_file": "auth.log", "source": "auth.log", "line_number": i + 1})
    for i in range(30):
        ts = pd.Timestamp("2026-05-02 09:00:00") + pd.Timedelta(minutes=i)
        line = f"{ts:%Y-%m-%d %H:%M:%S} host sshd: Accepted publickey for analyst from 10.0.0.5 port 4{i:04d} ssh2"
        rows.append({"timestamp": ts, "raw_line": line, "message": line, "source_file": "auth.log", "source": "auth.log", "line_number": 100 + i})
    return pd.DataFrame(rows)


@pytest.fixture()
def seeded(tmp_path):
    store = SQLiteStore(str(tmp_path / "t.db"))
    bundle = run_pipeline(_bruteforce(), run_id="run-a", store=store)
    return store, bundle


def test_vectorized_rules_match_scalar_evaluation() -> None:
    engine = RuleEngine()
    engine.add_rule(RuleDefinition("r1", "burst", "", True, "failed_login_count >= 3 and login_burst_score > 0.5", 3, "High", 1.2))
    engine.add_rule(RuleDefinition("r2", "unsafe-ish", "", True, "abs(failed_login_count - 4) <= 1", 3, "Low", 0.5))
    frame = pd.DataFrame({"failed_login_count": [0, 2, 3, 4, 9], "login_burst_score": [0.0, 0.4, 0.6, 0.8, 1.0]})
    counts, weights = engine.evaluate_frame(frame)
    expected_counts, expected_weights = [], []
    for row in frame.to_dict("records"):
        matched = [r for r in engine.rules if engine.evaluate_rule(r, dict(row))]
        expected_counts.append(len(matched))
        expected_weights.append(min(1.0, sum(r.weight for r in matched)))
    assert counts.tolist() == expected_counts
    assert np.allclose(weights, expected_weights)


def test_vectorized_rules_skip_rule_when_column_missing() -> None:
    engine = RuleEngine()
    engine.add_rule(RuleDefinition("r", "x", "", True, "nonexistent_signal > 1", 1, "High", 1.0))
    counts, _ = engine.evaluate_frame(pd.DataFrame({"a": [1, 2]}))
    assert counts.tolist() == [0, 0]


def test_one_class_svm_caps_training_rows_but_scores_everything() -> None:
    rng = np.random.default_rng(0)
    frame = pd.DataFrame(rng.normal(size=(300, 3)), columns=["message_length", "message_word_count", "unique_word_count"])
    model = LogAnomalyModel(algorithm="one_class_svm")
    model.OCSVM_MAX_FIT_ROWS = 100
    scored = model.fit_predict(frame)
    assert model.fit_rows == 100 and len(scored) == 300


def test_pipeline_reports_real_stage_timings(seeded) -> None:
    _, bundle = seeded
    assert {"parsing", "normalization", "aggregation", "features", "detection", "risk", "persistence", "alerts"} <= set(bundle.timings)
    assert all(v >= 0 for v in bundle.timings.values())


def test_progress_callback_fires_start_then_done_per_stage() -> None:
    events: list[tuple[str, str]] = []
    run_pipeline(_bruteforce(), persist=False, progress=lambda s, st: events.append((s, st)))
    stages = [s for s, _ in events if _ == "start"]
    assert stages[0] == "parsing" and "detection" in stages
    for stage in stages:
        assert events.index((stage, "start")) < events.index((stage, "done"))


def test_events_persist_detector_evidence_and_batch_is_idempotent(seeded) -> None:
    store, bundle = seeded
    with sqlite3.connect(store.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(bundle.scored_frame)
        assert c.execute("SELECT MAX(failed_login_count) FROM events").fetchone()[0] >= 10
    run_pipeline(_bruteforce(), run_id="run-b", store=store)  # identical events: no duplicates
    with sqlite3.connect(store.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(bundle.scored_frame)


def test_analytics_counts_are_consistent(seeded) -> None:
    store, bundle = seeded
    k = analytics.kpis(store)
    scored = bundle.scored_frame
    assert k["total"] == len(scored)
    assert k["anomalies"] == int((scored["prediction"] == -1).sum())
    assert k["critical"] == int((scored["severity"] == "Critical").sum())
    assert sum(analytics.severity_counts(store).values()) == k["total"]
    assert analytics.risk_histogram(store)["count"].sum() == k["total"]
    sources = analytics.detection_sources(store)
    assert sources["unique_flagged"] <= k["total"]
    assert sources["unique_flagged"] <= sum(sources["signals"].values()) or sources["unique_flagged"] == 0
    assert sources["alerts"] == k["alert_events"]


def test_activity_series_and_heatmap_honest_on_thin_data(seeded) -> None:
    store, _ = seeded
    series, unit = analytics.activity_series(store)
    assert series["events"].sum() == analytics.kpis(store)["total"]
    assert analytics.activity_heatmap(store) is None  # only a few distinct hours: refuses to draw


def test_time_range_is_measured_from_newest_event(seeded) -> None:
    store, _ = seeded
    since = analytics.since_for_range(store, "24H")
    assert since is not None and since.startswith("2026-05-01")
    assert analytics.since_for_range(store, "ALL") is None


def test_top_entities_rejects_unknown_columns(seeded) -> None:
    store, _ = seeded
    with pytest.raises(ValueError):
        analytics.top_entities(store, "message; DROP TABLE events")
    assert not analytics.top_entities(store, "source_ip").empty


def test_event_query_filters_paginates_and_searches_in_sql(seeded) -> None:
    store, _ = seeded
    page, total = store.query_events(search="203.0.113.9", limit=10)
    assert total == 40 and len(page) == 10
    page2, _ = store.query_events(search="203.0.113.9", limit=10, offset=10)
    assert set(page["event_key"]).isdisjoint(page2["event_key"])
    _, none = store.query_events(search="no-such-host")
    assert none == 0
    page_low, total_low = store.query_events(severities=["Low"], sort_by="risk_score", descending=False, limit=5)
    assert (page_low["severity"] == "Low").all() and total_low >= len(page_low)


def test_critical_notification_fires_once_and_ack_is_separate_from_alert(seeded) -> None:
    store, _ = seeded
    store.upsert_alerts_batch([
        {"alert_id": f"crit-{i}", "timestamp": "2026-05-03 01:00:00", "source": "auth.log", "event": f"critical event {i}", "detectors": ["isolation_forest"],
         "risk_score": 90 + i, "severity": "Critical", "explanation": "x", "event_key": None, "status": "NEW"} for i in range(3)
    ])
    criticals = store.new_critical_alerts()
    ids = criticals["alert_id"].tolist()
    assert {"crit-0", "crit-1", "crit-2"} <= set(ids)
    assert store.unacknowledged_critical_count() == len(ids)
    store.mark_notified(ids)
    assert store.new_critical_alerts().empty                 # a rerun cannot announce them again
    assert store.unacknowledged_critical_count() == len(ids)  # but the bell still counts them
    store.acknowledge_notifications([ids[0]])
    assert store.unacknowledged_critical_count() == len(ids) - 1
    assert store.get_alert(ids[0]) is not None and store.get_alert(ids[0])["status"] == "NEW"  # alert untouched
    store.acknowledge_notifications(None)
    assert store.unacknowledged_critical_count() == 0


def test_preexisting_alerts_are_not_announced_as_new(tmp_path) -> None:
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL, event TEXT NOT NULL, detectors TEXT NOT NULL, risk_score REAL NOT NULL, severity TEXT NOT NULL, explanation TEXT NOT NULL, status TEXT NOT NULL, notes TEXT NOT NULL)")
        c.execute("INSERT INTO alerts VALUES ('old','2026-01-01','s','e','d',90,'Critical','x','NEW','')")
    store = SQLiteStore(str(db))
    store.initialize()
    assert store.new_critical_alerts().empty and store.unacknowledged_critical_count() == 1


def test_alert_status_lifecycle_persists_with_history(seeded) -> None:
    store, _ = seeded
    alert_id = store.query_alerts(limit=1)[0].iloc[0]["alert_id"]
    store.update_alert_status(alert_id, "INVESTIGATING", user="t", notes="looking")
    store.update_alert_status(alert_id, "FALSE_POSITIVE", user="t")
    assert store.get_alert(alert_id)["status"] == "FALSE_POSITIVE"
    assert [h["action"] for h in store.list_history(alert_id)] == ["INVESTIGATING", "FALSE_POSITIVE"]
    run_pipeline(_bruteforce(), run_id="run-c", store=store)  # re-analysis must not reset a triaged alert
    assert store.get_alert(alert_id)["status"] == "FALSE_POSITIVE"


def test_monitor_survives_a_failing_batch_and_counts_real_work(tmp_path) -> None:
    log = tmp_path / "w.log"
    log.write_text("2026-05-01 10:00:00 host sshd: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    calls: list[int] = []

    def flaky(frame, path):
        calls.append(len(frame))
        if len(calls) == 1:
            raise RuntimeError("boom")

    from backend.checkpoint import CheckpointStore

    monitor = ContinuousOfflineMonitor([str(log)], on_batch=flaky, checkpoint_store=CheckpointStore(SQLiteStore(str(tmp_path / "c.db"))))
    monitor.process_file(str(log))
    assert monitor.last_error and "boom" in monitor.last_error and monitor.batches_processed == 0
    monitor.process_file(str(log))  # checkpoint not advanced after the failure: same bytes retried
    assert monitor.batches_processed == 1 and monitor.records_processed == 1 and monitor.last_error is None


def test_dashboard_renders_every_page_without_exceptions(tmp_path, monkeypatch) -> None:
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    st.cache_resource.clear()
    monkeypatch.setenv("CYBERSPECTRA_DB", str(tmp_path / "ui.db"))
    monkeypatch.setenv("CYBERSPECTRA_AUDIT_LOG", str(tmp_path / "audit.log"))
    store = SQLiteStore()
    run_pipeline(_bruteforce(), store=store)
    at = AppTest.from_file(str(ROOT / "app" / "dashboard.py"), default_timeout=90).run()
    assert not at.exception
    for page in ["Monitoring", "Detection", "Alerts", "History", "Reports", "System", "Overview"]:
        next(b for b in at.button if b.key == f"nav-{page}").click().run()
        assert not at.exception, f"{page}: {[e.value for e in at.exception]}"
    next(b for b in at.button if b.key == "nav-System").click().run()
    for section in ["Detection Models", "Rules & Thresholds", "Audit Log", "Data Sources"]:
        at.segmented_control[0].set_value(section).run()
        assert not at.exception, section


def test_theme_toggle_persists_in_sqlite(tmp_path, monkeypatch) -> None:
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    st.cache_resource.clear()
    monkeypatch.setenv("CYBERSPECTRA_DB", str(tmp_path / "th.db"))
    monkeypatch.setenv("CYBERSPECTRA_AUDIT_LOG", str(tmp_path / "audit.log"))
    at = AppTest.from_file(str(ROOT / "app" / "dashboard.py"), default_timeout=90).run()
    assert at.session_state["theme"] == "light"
    next(b for b in at.button if b.key == "theme-toggle").click().run()
    assert at.session_state["theme"] == "dark"
    assert SQLiteStore(str(tmp_path / "th.db")).get_setting("theme") == "dark"


def test_ui_has_no_remote_assets() -> None:
    """Air-gap guard: UI code and CSS must not reference any remote URL or CDN."""
    pattern = re.compile(r"(?:src|href)\s*=\s*[\"']https?://|url\(\s*[\"']?https?://|@import\s+url\(|https?://(?:fonts|cdn|cdnjs|unpkg|ajax)\.", re.I)
    for path in list((ROOT / "app").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert not pattern.search(text), f"remote asset reference in {path}"


def test_system_logs_collect_and_analyze(tmp_path):
    """The host-log collector returns pipeline-ready rows on this OS; the pipeline scores them."""
    from backend import system_logs
    from backend.database import SQLiteStore
    from backend.pipeline import run_pipeline

    log = tmp_path / "auth.log"
    log.write_text("\n".join(f"Nov 14 10:{i % 60:02d}:00 host sshd[1]: Failed password for root from 10.0.0.{i % 9} port 22 ssh2" for i in range(120)))
    frame, notes = system_logs.collect([f"file:{log}"], 100)
    assert len(frame) == 100 and notes[0].endswith("100 records")
    assert {"raw_line", "source_file", "timestamp"} <= set(frame.columns)
    bundle = run_pipeline(frame, contamination=0.1, algorithm="isolation_forest", store=SQLiteStore(tmp_path / "t.db"))
    assert len(bundle.scored_frame) == 100

    frame, notes = system_logs.collect(["file:/nonexistent/x.log", "bogus"], 10)
    assert frame.empty and len(notes) == 2
    assert all(isinstance(o["ok"], bool) for o in system_logs.available_sources())

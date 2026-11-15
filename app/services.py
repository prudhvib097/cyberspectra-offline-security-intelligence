"""Session, caching and service wiring for the dashboard.

Thin glue only: it calls the canonical backend pipeline and the SQLite store and
holds Streamlit session state. No detection, scoring or severity logic lives here.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

import pandas as pd
import streamlit as st

from backend import analytics
from backend.audit import AuditLogger
from backend.config import load_config
from backend.database import SQLiteStore
from backend.monitoring import ContinuousOfflineMonitor
from backend.pipeline import run_pipeline
from src.ingestion import load_uploaded_files

PAGES = ["Overview", "Monitoring", "Detection", "Alerts", "History", "Reports", "System"]
ALERT_STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
# UI stage label -> backend pipeline stages that must all finish first.
PIPELINE_STAGES: list[tuple[str, tuple[str, ...]]] = [
    ("LOG INGESTION", ("ingestion",)),
    ("PARSING", ("parsing",)),
    ("NORMALIZATION", ("normalization",)),
    ("FEATURE ENGINEERING", ("aggregation", "features")),
    ("ML DETECTION", ("detection",)),
    ("RISK SCORING", ("risk",)),
    ("ALERT GENERATION", ("persistence", "alerts")),
]


@st.cache_resource(show_spinner=False)
def get_store() -> SQLiteStore:
    store = SQLiteStore()
    store.initialize()
    return store


@st.cache_resource(show_spinner=False)
def get_audit() -> AuditLogger:
    return AuditLogger()


def init_state() -> None:
    store = get_store()
    if "theme" not in st.session_state:
        saved = None
        try:
            saved = store.get_setting("theme")
        except sqlite3.Error:
            pass
        st.session_state.theme = saved if saved in ("light", "dark") else "light"
    st.session_state.setdefault("page", "Overview")
    st.session_state.setdefault("selected_alert", None)
    st.session_state.setdefault("banner", None)
    st.session_state.setdefault("analysis_results", {})
    st.session_state.setdefault("last_result", None)
    st.session_state.setdefault("raw_frame", pd.DataFrame())
    st.session_state.setdefault("source_names", [])


def goto(page: str, alert_id: str | None = None) -> None:
    st.session_state.page = page
    if alert_id is not None:
        st.session_state.selected_alert = alert_id


def toggle_theme() -> None:
    new = "dark" if st.session_state.theme == "light" else "light"
    st.session_state.theme = new
    try:
        get_store().set_setting("theme", new)
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
@dataclass
class AnalysisResult:
    run_id: str
    algorithm: str
    contamination: float
    records: int
    anomalies: int
    alerts: int
    critical: int
    malformed: int
    timings: dict
    model_info: dict
    sources: list
    key: str
    finished_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def config_signature() -> str:
    return hashlib.sha1(json.dumps(load_config(), sort_keys=True, default=str).encode()).hexdigest()[:12]


def analysis_key(frame: pd.DataFrame, contamination: float, algorithm: str) -> str:
    """Identity of an analysis: data content + engine + sensitivity + configuration."""
    digest = int(pd.util.hash_pandas_object(frame.astype(str), index=False).sum())
    return f"{digest}:{len(frame)}:{contamination:.4f}:{algorithm}:{config_signature()}"


def load_uploads(files: Iterable[object]) -> tuple[pd.DataFrame, list[str], str | None]:
    files = list(files or [])
    if not files:
        return pd.DataFrame(), [], None
    try:
        frame, names = load_uploaded_files(files)
        return frame, names, None
    except (OSError, UnicodeError, ValueError) as exc:
        return pd.DataFrame(), [], f"The selected file(s) could not be read: {exc}"


def run_analysis(frame: pd.DataFrame, names: list[str], contamination: float, algorithm: str, progress: Callable[[str, str], None] | None = None) -> tuple[AnalysisResult, bool]:
    """Run the canonical pipeline once per distinct (data, engine, sensitivity, config)."""
    store = get_store()
    key = analysis_key(frame, contamination, algorithm)
    cached = st.session_state.analysis_results.get(key)
    if cached is not None and analytics.run_summary(store, cached.run_id) is not None:
        st.session_state.last_result = cached
        return cached, True
    bundle = run_pipeline(frame, contamination=contamination, algorithm=algorithm, store=store, progress=progress)
    scored = bundle.scored_frame
    result = AnalysisResult(
        run_id=bundle.run_id, algorithm=algorithm, contamination=contamination, records=len(scored),
        anomalies=int((scored["prediction"] == -1).sum()) if not scored.empty else 0,
        alerts=int(scored["alert_required"].sum()) if not scored.empty else 0,
        critical=int((scored["severity"] == "Critical").sum()) if not scored.empty else 0,
        malformed=bundle.malformed_count, timings=dict(bundle.timings), model_info=dict(bundle.model_info),
        sources=list(names), key=key,
    )
    # Keep only the lightweight summary in the session; events live in SQLite.
    st.session_state.analysis_results[key] = result
    st.session_state.last_result = result
    st.session_state.scope = "Latest run"
    return result, False


# ---------------------------------------------------------------------------
# Continuous monitoring (real watcher or nothing)
# ---------------------------------------------------------------------------
class MonitorManager:
    """Owns the single ContinuousOfflineMonitor; survives Streamlit reruns."""

    def __init__(self) -> None:
        self.monitor: ContinuousOfflineMonitor | None = None
        self.paths: list[str] = []
        self.started_at: str | None = None

    def start(self, paths: list[str]) -> None:
        if self.monitor is not None:
            return
        self.monitor = ContinuousOfflineMonitor(paths)
        self.monitor.start()
        self.paths, self.started_at = paths, datetime.now(timezone.utc).isoformat(timespec="seconds")

    def stop(self) -> None:
        if self.monitor is not None:
            self.monitor.stop()
        self.monitor, self.paths, self.started_at = None, [], None

    def status(self) -> dict:
        m = self.monitor
        return {
            "active": bool(m and m.enabled), "paths": list(self.paths), "started_at": self.started_at,
            "batches": m.batches_processed if m else 0, "records": m.records_processed if m else 0,
            "last_batch_at": m.last_batch_at if m else None, "last_error": m.last_error if m else None,
        }


@st.cache_resource(show_spinner=False)
def get_monitor() -> MonitorManager:
    return MonitorManager()


# ---------------------------------------------------------------------------
# Verified system state (used by the header and the health panel)
# ---------------------------------------------------------------------------
def health() -> dict[str, tuple[str, str]]:
    """component -> (state ok|warn|bad, detail). Only things checked right now."""
    result: dict[str, tuple[str, str]] = {}
    store = get_store()
    try:
        with sqlite3.connect(store.db_path) as connection:
            connection.execute("SELECT 1 FROM alerts LIMIT 1")
        result["Database"] = ("ok", "SQLite reachable")
    except sqlite3.Error as exc:
        result["Database"] = ("bad", f"error: {exc}")
    try:
        import sklearn  # noqa: F401

        result["ML Engine"] = ("ok", "scikit-learn loaded")
    except ImportError:
        result["ML Engine"] = ("bad", "scikit-learn missing")
    try:
        import watchdog  # noqa: F401

        watcher_ready = True
    except ImportError:
        watcher_ready = False
    status = get_monitor().status()
    if status["last_error"]:
        result["Log Collector"] = ("bad", "last batch failed")
    elif status["active"]:
        result["Log Collector"] = ("ok", f"watching {len(status['paths'])} path(s)")
    elif watcher_ready:
        result["Log Collector"] = ("warn", "ready, not watching")
    else:
        result["Log Collector"] = ("bad", "watchdog missing")
    rules = [r for r in load_config().get("rules", []) if r.get("enabled", True)]
    result["Alert Engine"] = ("ok", f"{len(rules)} rule(s) loaded") if result["Database"][0] == "ok" else ("bad", "database unavailable")
    return result


def windows_collection_supported() -> bool:
    return platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Critical-alert notifications
# ---------------------------------------------------------------------------
def pull_new_criticals() -> None:
    """Detect genuinely new Critical alerts once; later reruns find nothing new.

    Each alert is marked as notified the moment it is surfaced, so a Streamlit
    rerun can never announce it again. Acknowledgement is tracked separately.
    """
    store = get_store()
    fresh = store.new_critical_alerts()
    if fresh.empty:
        return
    store.mark_notified(fresh["alert_id"].tolist())
    previous = st.session_state.banner or {"ids": [], "count": 0}
    latest = fresh.iloc[0]
    st.session_state.banner = {
        "ids": previous["ids"] + fresh["alert_id"].tolist(),
        "count": previous["count"] + len(fresh),
        "event": str(latest["event"]), "risk": float(latest["risk_score"]), "source": str(latest["source"]), "alert_id": str(latest["alert_id"]),
    }
    st.session_state.beep = True
    st.toast(f"CRITICAL SECURITY ALERT — {len(fresh)} new critical alert(s)", icon="🚨")
    get_audit().log("critical_alert_notified", {"count": len(fresh)})


def acknowledge(alert_ids: list[str] | None) -> None:
    store = get_store()
    n = store.acknowledge_notifications(alert_ids)
    get_audit().log("notification_acknowledged", {"count": n})
    st.session_state.banner = None


def dismiss_banner() -> None:
    st.session_state.banner = None


def sound_enabled() -> bool:
    return get_store().get_setting("sound_on_critical") == "1"


def set_sound(enabled: bool) -> None:
    get_store().set_setting("sound_on_critical", "1" if enabled else "0")

from __future__ import annotations

import hashlib
import uuid
from contextlib import contextmanager
from time import perf_counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

import pandas as pd

from backend.aggregation import build_aggregated_features
from backend.alert_generator import build_alert_feed
from backend.config import load_config
from backend.database import SQLiteStore
from backend.explanations import build_explanations
from backend.log_collector import collect_from_paths, collect_from_uploaded_files
from backend.reporting import build_summary_metrics
from backend.risk import build_risk_scores
from backend.thresholds import apply_thresholds, load_history_thresholds
from src.feature_engineering import build_features
from src.model import LogAnomalyModel
from backend.parsers import parse_records
from src.preprocessing import apply_schema_and_preprocess, preprocess_logs  # noqa: F401  (re-exported for callers/tests)
from src.severity import assign_severity, summarize_severity


@dataclass
class PipelineBundle:
    raw_frame: pd.DataFrame
    cleaned_frame: pd.DataFrame
    feature_frame: pd.DataFrame
    scored_frame: pd.DataFrame
    alert_feed: pd.DataFrame
    summary: dict
    severity_breakdown: pd.DataFrame
    algorithm: str
    contamination: float
    run_id: str = ""
    malformed_count: int = 0
    thresholds: dict = field(default_factory=dict)
    timings: dict = field(default_factory=dict)
    model_info: dict = field(default_factory=dict)


def _event_key(timestamp: str, source_file: str, line_number: object, raw_log: str) -> str:
    digest = hashlib.sha256(f"{timestamp}|{source_file}|{line_number}|{raw_log}".encode("utf-8", errors="ignore")).hexdigest()
    return digest[:32]


def _alert_id(source: str, event: str, timestamp: str) -> str:
    digest = hashlib.sha256(f"{timestamp}|{source}|{event}".encode("utf-8", errors="ignore")).hexdigest()
    return f"alert-{digest[:24]}"


def _text_column(frame: pd.DataFrame, name: str, default: str = "") -> pd.Series:
    if name not in frame.columns:
        return pd.Series(default, index=frame.index, dtype=object)
    return frame[name].where(frame[name].notna(), default).astype(str)


def _number_column(frame: pd.DataFrame, name: str, default: float = 0.0) -> pd.Series:
    if name not in frame.columns:
        return pd.Series(default, index=frame.index, dtype=float)
    return pd.to_numeric(frame[name], errors="coerce").fillna(default)


def _persist_bundle(scored: pd.DataFrame, run_id: str, algorithm: str, contamination: float, store: SQLiteStore, start_time: str) -> None:
    """Persist the run, its alerts and every scored event in batched transactions."""
    store.initialize()

    anomaly_count = int((scored["prediction"] == -1).sum()) if not scored.empty and "prediction" in scored.columns else 0
    store.record_analysis_run(
        run_id=run_id,
        timestamp_start=start_time,
        timestamp_end=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sources=",".join(sorted(scored["source_file"].dropna().astype(str).unique().tolist())) if not scored.empty and "source_file" in scored.columns else "",
        total_records=len(scored),
        anomalies=anomaly_count,
        algorithm=algorithm,
        contamination=contamination,
        status="completed",
    )

    if scored.empty:
        return

    timestamps = _text_column(scored, "timestamp")
    source_files = _text_column(scored, "source_file")
    raw_lines = _text_column(scored, "raw_line").str.slice(0, 1000)
    line_numbers = _text_column(scored, "line_number")
    messages = _text_column(scored, "message")
    event_keys = [
        _event_key(t, f, n, r)
        for t, f, n, r in zip(timestamps.tolist(), source_files.tolist(), line_numbers.tolist(), raw_lines.tolist())
    ]
    risk = _number_column(scored, "risk_score")
    severity = _text_column(scored, "severity", "Low")
    explanation = _text_column(scored, "explanation")
    alert_mask = scored["alert_required"].fillna(False).astype(bool).to_numpy() if "alert_required" in scored.columns else None

    alert_records = []
    if alert_mask is not None and alert_mask.any():
        detector_lists = scored["detectors"].tolist() if "detectors" in scored.columns else [None] * len(scored)
        source_list, message_list, timestamp_list = source_files.tolist(), messages.tolist(), timestamps.tolist()
        risk_list, severity_list, explanation_list = risk.tolist(), severity.tolist(), explanation.tolist()
        for position in alert_mask.nonzero()[0].tolist():
            source = source_list[position] or "unknown"
            event = message_list[position][:500]
            timestamp = timestamp_list[position]
            alert_records.append(
                {
                    "alert_id": _alert_id(source, event, timestamp),
                    "timestamp": timestamp,
                    "source": source,
                    "event": event,
                    "detectors": [str(d) for d in (detector_lists[position] or [algorithm])],
                    "risk_score": float(risk_list[position]),
                    "severity": severity_list[position],
                    "explanation": explanation_list[position][:1000],
                    "event_key": event_keys[position],
                    "status": "NEW",
                }
            )
    store.upsert_alerts_batch(alert_records)

    frame = pd.DataFrame(
        {
            "event_key": event_keys,
            "timestamp": timestamps.to_numpy(),
            "source": _text_column(scored, "source").to_numpy(),
            "source_file": source_files.to_numpy(),
            "source_host": _text_column(scored, "source_host").to_numpy(),
            "source_ip": _text_column(scored, "source_ip").to_numpy(),
            "username": _text_column(scored, "username").to_numpy(),
            "event_type": _text_column(scored, "event_type").to_numpy(),
            "severity": severity.to_numpy(),
            "risk_score": risk.to_numpy(),
            "anomaly_score": _number_column(scored, "anomaly_score").to_numpy(),
            "prediction": _number_column(scored, "prediction", 1).astype(int).to_numpy(),
            "message": messages.str.slice(0, 2000).to_numpy(),
            "raw_log": _text_column(scored, "raw_line").str.slice(0, 3000).to_numpy(),
            "analysis_run": run_id,
            "statistical_score": _number_column(scored, "statistical_score").to_numpy(),
            "rule_match_count": _number_column(scored, "rule_match_count").astype(int).to_numpy(),
            "rule_weight": _number_column(scored, "rule_weight").to_numpy(),
            "context_score": _number_column(scored, "context_score").to_numpy(),
            "failed_login_count": _number_column(scored, "failed_login_count").astype(int).to_numpy(),
            "destination_ip": _text_column(scored, "destination_ip").to_numpy(),
            "action": _text_column(scored, "action").to_numpy(),
            "protocol": _text_column(scored, "protocol").to_numpy(),
            "port": _text_column(scored, "port").str.replace(r"\.0$", "", regex=True).to_numpy(),
            "explanation": explanation.str.slice(0, 1000).to_numpy(),
            "algorithm": algorithm,
            "event_rate_per_min": _number_column(scored, "event_rate_per_min").to_numpy(),
            "login_burst_score": _number_column(scored, "login_burst_score").to_numpy(),
            "off_hours": (1 - _number_column(scored, "is_business_hours", 1)).astype(int).to_numpy(),
            "unique_source_ips_window": _number_column(scored, "unique_source_ips_window").astype(int).to_numpy(),
            "alert_keyword_count": _number_column(scored, "alert_keyword_count").astype(int).to_numpy(),
        }
    )
    store.insert_events_frame(frame)


def run_pipeline(frame: pd.DataFrame, contamination: float = 0.12, algorithm: str = "isolation_forest", start_time: str | None = None, run_id: str | None = None, persist: bool = True, store: SQLiteStore | None = None, progress: Callable[[str, str], None] | None = None) -> PipelineBundle:
    """Canonical pipeline: parse → schema → aggregate → features → ML →
    statistics → thresholds → fusion → severity → explainable alerts → DB.

    Every interface (CLI, dashboard, monitoring, reports) must call this
    function so severity, alerts and explanations are always consistent.

    ``progress(stage, state)`` is called with state ``"start"`` / ``"done"``
    around each real stage (used by the dashboard's pipeline tracker);
    measured wall-clock seconds per stage are returned in ``bundle.timings``.
    """
    config = load_config()
    resolved_run_id = run_id or uuid.uuid4().hex[:12]
    resolved_store = store or SQLiteStore()
    timings: dict[str, float] = {}

    @contextmanager
    def stage(name: str):
        if progress:
            progress(name, "start")
        started = perf_counter()
        try:
            yield
        finally:
            timings[name] = perf_counter() - started
        if progress:
            progress(name, "done")

    with stage("parsing"):
        schema_frame = parse_records(frame) if not frame.empty else frame
    with stage("normalization"):
        cleaned = preprocess_logs(schema_frame)
        malformed_count = int(cleaned["parse_status"].eq("unparsed").sum()) if "parse_status" in cleaned.columns else 0
    with stage("aggregation"):
        cleaned = build_aggregated_features(cleaned, config)
    with stage("features"):
        feature_frame = build_features(cleaned)
    model = LogAnomalyModel(contamination=contamination, algorithm=algorithm)
    with stage("detection"):
        scored = assign_severity(model.fit_predict(feature_frame))

    scored_start = start_time or (str(cleaned["timestamp"].min()) if not cleaned.empty and cleaned["timestamp"].notna().any() else datetime.now(timezone.utc).isoformat(timespec="seconds"))
    with stage("risk"):
        scored = build_risk_scores(scored, config=config, algorithm=algorithm)
        thresholds = load_history_thresholds(resolved_store if resolved_store is not None else None, config)
        scored = apply_thresholds(scored, thresholds)
        scored = build_explanations(scored, config=config)

    with stage("persistence"):
        if persist:
            _persist_bundle(scored, resolved_run_id, algorithm, contamination, resolved_store, scored_start)

    with stage("alerts"):
        alerts = build_alert_feed(scored)
        summary = build_summary_metrics(scored)
        severity_breakdown = summarize_severity(scored)
    return PipelineBundle(
        raw_frame=frame,
        cleaned_frame=cleaned,
        feature_frame=feature_frame,
        scored_frame=scored,
        alert_feed=alerts,
        summary=summary,
        severity_breakdown=severity_breakdown,
        algorithm=algorithm,
        contamination=contamination,
        run_id=resolved_run_id,
        malformed_count=malformed_count,
        thresholds=thresholds,
        timings=timings,
        model_info={"algorithm": algorithm, "feature_count": len(model.required_features), "fit_rows": model.fit_rows, "events": len(scored)},
    )


def run_pipeline_on_paths(paths: Sequence[str] | Sequence[Path], contamination: float = 0.12, algorithm: str = "isolation_forest", recursive: bool = True) -> PipelineBundle:
    frame = collect_from_paths([str(path) for path in paths], recursive=recursive)
    return run_pipeline(frame, contamination=contamination, algorithm=algorithm)


def run_pipeline_on_uploaded_files(uploaded_files: Iterable[object], contamination: float = 0.12, algorithm: str = "isolation_forest") -> PipelineBundle:
    frame, _ = collect_from_uploaded_files(uploaded_files)
    return run_pipeline(frame, contamination=contamination, algorithm=algorithm)


def compare_models(frame: pd.DataFrame, contamination: float = 0.12) -> dict[str, PipelineBundle]:
    return {
        algorithm: run_pipeline(frame, contamination=contamination, algorithm=algorithm)
        for algorithm in ["isolation_forest", "one_class_svm"]
    }
"""System Center: Data Sources, Detection Models, Rules & Thresholds, Audit Log."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from app import services
from app.ui.components import empty_state, esc, html_table, page_header, paginator, panel_title, pill
from backend import analytics
from backend.config import load_config
from backend.thresholds import compute_thresholds
from src.feature_engineering import FEATURE_COLUMNS

SECTIONS = ["Data Sources", "Detection Models", "Rules & Thresholds", "Audit Log"]


def render() -> None:
    page_header("System Center", "Local configuration, sources, models, rules and audit records.", eyebrow="SECURITY OPERATIONS CENTER / SYSTEM")
    section = st.segmented_control("Section", SECTIONS, default=st.session_state.get("system_section", SECTIONS[0]), label_visibility="collapsed", key="system-ctl") or SECTIONS[0]
    st.session_state.system_section = section
    {"Data Sources": _sources, "Detection Models": _models, "Rules & Thresholds": _rules, "Audit Log": _audit}[section]()


def _sources() -> None:
    store = services.get_store()
    status = services.get_monitor().status()
    with st.container(key="panel-sys-sources"):
        panel_title("Data sources")
        watch = pill("ACTIVE", "low") if status["active"] else pill("NOT WATCHING", "neutral")
        st.markdown(f'<div style="font-size:14px;margin-bottom:8px">Folder watcher: {watch} {esc(", ".join(status["paths"]))} · Windows Event Log collection: '
                    f'{pill("AVAILABLE", "low") if services.windows_collection_supported() else pill("WINDOWS ONLY", "neutral")}</div>', unsafe_allow_html=True)
        runs = pd.DataFrame(store.list_analysis_runs(limit=25))
        if runs.empty:
            empty_state("NO SOURCES COLLECTED", "No log data has been analyzed yet.", "Upload local security logs on the Monitoring page.")
        else:
            html_table(runs[["timestamp_start", "sources", "total_records", "anomalies", "alerts", "algorithm", "status"]], severity_col=None, labels={"timestamp_start": "analyzed at"})


def _models() -> None:
    cfg = load_config()
    with st.container(key="panel-sys-models"):
        panel_title("Detection models", "Both engines run inside the canonical pipeline")
        rows = [
            {"model": "Isolation Forest", "role": "Primary", "parameters": "n_estimators=100, random_state=42, contamination=sensitivity", "features": len(FEATURE_COLUMNS)},
            {"model": "One-Class SVM", "role": "Alternative", "parameters": "kernel=rbf, gamma=scale, nu=sensitivity; fit sample ≤ 20,000 rows", "features": len(FEATURE_COLUMNS)},
            {"model": "Statistical detector", "role": "Fusion input", "parameters": "rolling z-score, percentile baseline, rate change", "features": "—"},
            {"model": "Rule engine", "role": "Fusion input", "parameters": f"{len(cfg.get('rules', []))} declarative rule(s), safe expression evaluator", "features": "—"},
        ]
        html_table(pd.DataFrame(rows), severity_col=None)
        weights = cfg["model"]["weights"]
        st.markdown(f'<div class="cs-panel-note" style="margin-top:8px">Risk fusion weights: ' + " · ".join(f"{k} {v}" for k, v in weights.items()) + " (normalised to sum 1.0). Default sensitivity: " + str(cfg["model"]["default_contamination"]) + ".</div>", unsafe_allow_html=True)


def _rules() -> None:
    cfg = load_config()
    with st.container(key="panel-sys-rules"):
        panel_title("Detection rules", "Loaded from config/defaults.json and evaluated by the canonical pipeline")
        rules = pd.DataFrame(cfg.get("rules", []))
        if rules.empty:
            empty_state("NO RULES", "No detection rules are configured.", "")
        else:
            html_table(rules[["rule_id", "name", "condition", "severity", "weight", "enabled"]], severity_col="severity", mono=["condition"])
    with st.container(key="panel-sys-thresholds"):
        panel_title("Severity boundaries & thresholds")
        boundaries = cfg["risk"]["severity_boundaries"]
        st.markdown(f'<div style="font-size:14px">Risk score bands: {pill("Low")} 0–{boundaries["low"] - 1} · {pill("Medium")} {boundaries["low"]}–{boundaries["medium"] - 1} · {pill("High")} {boundaries["medium"]}–{boundaries["high"] - 1} · {pill("Critical")} {boundaries["high"]}–100</div>', unsafe_allow_html=True)
        thresholds = compute_thresholds(cfg, history=services.get_store().list_recent_events(limit=1000))
        html_table(pd.DataFrame([{"setting": k, "value": v} for k, v in {**cfg["aggregation"], **thresholds}.items()]), severity_col=None)


def _audit() -> None:
    audit = services.get_audit()
    with st.container(key="panel-sys-audit"):
        panel_title("Audit log", "Actions recorded by the dashboard and backend (logs/audit.log)")
        rows = []
        path = audit.log_path
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows.append({"timestamp": entry.get("timestamp", ""), "action": entry.get("action", ""), "details": json.dumps(entry.get("details", {}))})
        if not rows:
            empty_state("NO AUDIT ENTRIES", "No actions have been recorded yet.", "")
            return
        frame = pd.DataFrame(rows).iloc[::-1].reset_index(drop=True)
        size = 20
        page = st.session_state.get("audit-page", 1)
        html_table(frame.iloc[(page - 1) * size : page * size], severity_col=None, mono=["timestamp", "details"])
        paginator("audit", len(frame), size)

"""Monitoring Center: ingest local files / Windows events and run the canonical pipeline."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from app import services
from app.ui.components import empty_state, esc, fmt_int, html_table, kpi_card, page_header, panel_title, pill
from backend.config import load_config

from backend import system_logs

SOURCES = ["Local Log Files", f"{system_logs.os_name()} System Logs"]
ENGINES = {"Isolation Forest": "isolation_forest", "One-Class SVM": "one_class_svm"}


def _tracker(slot, states: dict[str, str]) -> None:
    steps = []
    for label, _ in services.PIPELINE_STAGES:
        state = states.get(label, "")
        steps.append(f'<span class="cs-step {state}">{"✓ " if state == "done" else ""}{label}</span>')
    slot.markdown('<div class="cs-pipe">' + '<span class="cs-arrow">→</span>'.join(steps) + "</div>", unsafe_allow_html=True)


def _run(frame: pd.DataFrame, names: list[str], contamination: float, algorithm: str, ingest_seconds: float) -> None:
    slot = st.empty()
    states: dict[str, str] = {label: "done" if label == "LOG INGESTION" else "" for label, _ in services.PIPELINE_STAGES}
    finished: set[str] = {"ingestion"}
    _tracker(slot, states)

    def progress(stage: str, state: str) -> None:
        if state == "done":
            finished.add(stage)
        for label, parts in services.PIPELINE_STAGES:
            if all(p in finished for p in parts):
                states[label] = "done"
            elif any(p == stage for p in parts) and state == "start":
                states[label] = "running"
        _tracker(slot, states)

    try:
        result, reused = services.run_analysis(frame, names, contamination, algorithm, progress)
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean message; details below
        for label in states:
            if states[label] == "running":
                states[label] = "failed"
        _tracker(slot, states)
        st.error("The analysis could not be completed. No results were saved for this run.")
        with st.expander("Technical details (for developers)"):
            st.exception(exc)
        services.get_audit().log("analysis_failed", {"error": f"{type(exc).__name__}: {exc}"})
        return
    if reused:
        for label in states:
            states[label] = "done"
        _tracker(slot, states)
        st.info("This exact data, engine, sensitivity and configuration were already analyzed — showing the stored result instead of recomputing.")
    services.get_audit().log("dashboard_analysis_completed", {"records": result.records, "sources": names, "algorithm": algorithm, "reused": reused})
    services.pull_new_criticals()
    st.success(f"Analysis complete: {fmt_int(result.records)} records, {fmt_int(result.alerts)} alerts ({fmt_int(result.critical)} critical).")


def render() -> None:
    page_header("Monitoring Center", "Ingest local security logs and run them through the offline parse → detect → score → alert pipeline.")
    config = load_config()

    with st.container(key="panel-input"):
        panel_title("Input source")
        source = st.segmented_control("Source", SOURCES, default=st.session_state.get("input_source", SOURCES[0]), label_visibility="collapsed", key="source-ctl") or SOURCES[0]
        st.session_state.input_source = source
        files, frame, names, error = [], pd.DataFrame(), [], None
        if source == SOURCES[0]:
            files = st.file_uploader("Drag and drop log files here", type=["csv", "txt", "log", "json", "jsonl"], accept_multiple_files=True, help="CSV, TXT, LOG, JSON or JSONL · processed locally, never uploaded anywhere")
            if files:
                chips = " ".join(pill(f"{f.name} · {f.size / 1024:,.0f} KB", "accent") for f in files)
                st.markdown(f'<div style="margin:4px 0">{chips}</div>', unsafe_allow_html=True)
        else:
            _system_source()

        a, b, c = st.columns([4, 3, 2], vertical_alignment="bottom")
        contamination = a.slider("Detection sensitivity", 0.01, 0.30, float(config["model"].get("default_contamination", 0.12)), 0.01, help="Expected share of anomalous events (contamination / nu)")
        engine_label = b.segmented_control("Detection engine", list(ENGINES), default="Isolation Forest", key="engine-ctl") or "Isolation Forest"
        has_input = bool(files) if source == SOURCES[0] else not st.session_state.raw_frame.empty
        go = c.button("Analyze locally", key="analyze", type="primary", disabled=not has_input, width="stretch")

    if go:
        from time import perf_counter

        started = perf_counter()
        if source == SOURCES[0]:
            frame, names, error = services.load_uploads(files)
        else:
            frame, names = st.session_state.raw_frame, st.session_state.source_names
        ingest_seconds = perf_counter() - started
        if error:
            st.error(error)
        elif frame.empty:
            st.warning("The selected input contained no readable records.")
        else:
            st.session_state.raw_frame, st.session_state.source_names = frame, names
            with st.container(key="panel-pipeline"):
                panel_title("Analysis pipeline", "Each stage turns green only when it has genuinely finished")
                _run(frame, names, contamination, ENGINES[engine_label], ingest_seconds)

    result = st.session_state.get("last_result")
    if result is not None:
        with st.container(key="panel-result"):
            panel_title("Latest analysis", f"Run {result.run_id} · {result.algorithm.replace('_', ' ')} · sensitivity {result.contamination:.2f}")
            cols = st.columns(4)
            with cols[0]:
                kpi_card("Records", fmt_int(result.records), f"{len(result.sources)} source(s)", "accent")
            with cols[1]:
                kpi_card("Anomalies", fmt_int(result.anomalies), "ML flagged", "high")
            with cols[2]:
                kpi_card("Alerts", fmt_int(result.alerts), f"{fmt_int(result.critical)} critical", "critical")
            with cols[3]:
                kpi_card("Malformed rows", fmt_int(result.malformed), "kept as 'unparsed', not dropped", "medium")
            if result.timings:
                timing = pd.DataFrame([{"stage": k, "seconds": round(v, 2)} for k, v in result.timings.items()])
                with st.expander("Measured stage timings"):
                    html_table(timing, severity_col=None)
            st.button("Open Overview →", key="to-overview", on_click=services.goto, args=("Overview",))
    elif not go:
        empty_state("NO ANALYSIS YET", "No log data has been analyzed in this session.", "Select local log files and choose Analyze locally.")

    _watch_section()


def _system_source() -> None:
    """Collect this computer's own logs: Windows Event Log, systemd journal / /var/log, or the macOS unified log."""
    options = system_logs.available_sources()
    if not options:
        st.info("Collecting system logs is not supported on this operating system. Use Local Log Files and upload an export instead.")
        return
    usable = {o["id"]: o for o in options if o["ok"]}
    for o in options:
        if not o["ok"]:
            st.caption(f"Unavailable · {o['label']}: {o['reason']}")
    if not usable:
        st.warning("No readable system log source was found. Try running CyberSpectra with elevated permissions, or upload exported logs.")
        return
    chosen = st.multiselect("Sources to collect", list(usable), default=list(usable)[:2], format_func=lambda i: usable[i]["label"])
    channels = None
    if "windows-events" in usable:
        channels = st.multiselect("Windows channels", system_logs.WINDOWS_CHANNELS, ["System", "Application"])
    a, b = st.columns(2)
    max_events = a.number_input("Maximum events per source", 100, 50000, 2000, 100)
    hours = b.number_input("Look back (hours)", 1, 720, 24, 1, disabled="journal" not in usable and "mac-unified" not in usable)
    if st.button(f"Collect from this {system_logs.os_name()} computer", key="sys-collect", disabled=not chosen):
        with st.spinner("Reading local logs…"):
            frame, notes = system_logs.collect(chosen, int(max_events), int(hours), channels)
        for line in notes:
            st.caption(line)
        if frame.empty:
            st.warning("No records were collected. Check the notes above (permissions are the usual cause).")
        else:
            st.session_state.raw_frame = frame
            st.session_state.source_names = list(frame["source_file"].dropna().unique())
            services.get_audit().log("system_logs_collected", {"os": system_logs.os_name(), "records": len(frame), "sources": chosen})
            st.success(f"Collected {len(frame):,} records at {system_logs.collected_at()}. Choose Analyze locally to process them.")
    elif not st.session_state.raw_frame.empty and st.session_state.get("input_source") != SOURCES[0]:
        st.caption(f"{len(st.session_state.raw_frame):,} collected records are ready to analyze.")


def _watch_section() -> None:
    manager = services.get_monitor()
    status = manager.status()
    with st.container(key="panel-watch"):
        panel_title("Continuous offline watch", "Watches a local folder or file and sends newly appended lines through the same pipeline")
        if status["active"]:
            st.markdown(f'{pill("ACTIVE", "low")} watching <span class="cs-mono">{esc(", ".join(status["paths"]))}</span> since {esc(status["started_at"])}', unsafe_allow_html=True)
            st.markdown(f'<div class="cs-sub">Batches processed: <b>{status["batches"]}</b> · records: <b>{fmt_int(status["records"])}</b> · last batch: {esc(status["last_batch_at"] or "none yet")}</div>', unsafe_allow_html=True)
            if status["last_error"]:
                st.error(f"The last batch failed and will be retried on the next file change: {status['last_error']}")
            if st.button("Stop watching", key="watch-stop"):
                manager.stop()
                services.get_audit().log("monitoring_stopped", {})
                st.rerun()
        else:
            st.markdown(f'{pill("NOT WATCHING", "neutral")} <span class="cs-sub">Monitoring is ready; nothing is being collected until you start a watch.</span>', unsafe_allow_html=True)
            path = st.text_input("Folder or file to watch", "data/logs", key="watch-path", help="Existing files are processed once from their saved checkpoint, then new lines as they are appended.")
            exists = Path(path).expanduser().exists()
            if not exists:
                st.caption("That path does not exist.")
            if st.button("Start watching", key="watch-start", disabled=not exists):
                manager.start([str(Path(path).expanduser())])
                services.get_audit().log("monitoring_started", {"path": path})
                st.rerun()

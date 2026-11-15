# Usage

1. **Start:** `streamlit run app/dashboard.py`.
2. **Ingest (Monitoring):** upload CSV/TXT/LOG/JSON/JSONL, or choose "<OS> System Logs" and press Collect. Collection runs in a separate worker process (on Windows it opens a console window showing the real collection progress; on macOS/Linux it runs in the background) and the same activity appears live in the page. Press Cancel to stop it; only one collection runs at a time. When it finishes the events go straight to the analysis pipeline (optional auto-analyze). Pick the detection engine and sensitivity, then **Analyze locally**. The stage tracker turns green only when each stage has finished.
3. **Review (Overview, Detection):** KPIs, activity, severity and detection-source charts, top entities.
4. **Investigate (Alerts):** open an alert for evidence, risk contributions and event details; move it through its lifecycle. History shows the audit trail.
5. **Notifications:** new Critical alerts show a banner once; the bell lists unacknowledged ones.
6. **Reports:** export CSV or PDF.
7. **Watch (Monitoring):** point the watcher at a folder or file to process appended lines continuously.
8. **System:** data sources, models, rules and thresholds, audit log. Switch Light/Dark from the header.

Batch mode: `python main.py <log files>` writes CSV/PDF into `reports/`.

**Hosted edition:** a website cannot open a terminal or read logs on your computer, so system-log collection is disabled there (`CYBERSPECTRA_EDITION=hosted`); upload exported logs instead.

## Windows Event Log collection

- Launch: `streamlit run app/dashboard.py` from a normal terminal. System, Application and Defender channels need no elevation.
- **Security** needs an elevated session: open the terminal with *Run as administrator* and launch the same command. CyberSpectra never elevates itself or changes permissions.
- Each channel ends as `SUCCESS`, `EMPTY`, `ACCESS_DENIED`, `CHANNEL_NOT_FOUND`, `DISABLED` or `ERROR`; the overall result is `SUCCESS`, `PARTIAL`, `EMPTY` or `FAILED`.
- Diagnose from a terminal (read-only): `python -m backend.windows_events --diagnose`. Compare with `Get-WinEvent -LogName System -MaxEvents 5`.
- Tests with mocked Windows APIs run everywhere; they do not prove the collector on a real Windows machine.

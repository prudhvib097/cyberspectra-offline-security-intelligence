# Usage

1. **Start:** `streamlit run app/dashboard.py`.
2. **Ingest (Monitoring):** upload CSV/TXT/LOG/JSON/JSONL, or choose "<OS> System Logs" and press Collect. Pick the detection engine and sensitivity, then **Analyze locally**. The stage tracker turns green only when each stage has finished.
3. **Review (Overview, Detection):** KPIs, activity, severity and detection-source charts, top entities.
4. **Investigate (Alerts):** open an alert for evidence, risk contributions and event details; move it through its lifecycle. History shows the audit trail.
5. **Notifications:** new Critical alerts show a banner once; the bell lists unacknowledged ones.
6. **Reports:** export CSV or PDF.
7. **Watch (Monitoring):** point the watcher at a folder or file to process appended lines continuously.
8. **System:** data sources, models, rules and thresholds, audit log. Switch Light/Dark from the header.

Batch mode: `python main.py <log files>` writes CSV/PDF into `reports/`.

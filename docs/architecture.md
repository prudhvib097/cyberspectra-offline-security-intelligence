# Architecture

One canonical pipeline (`backend/pipeline.py`) serves the dashboard, the CLI and the folder watcher. The UI never recomputes metrics: it reads rows the pipeline persisted in SQLite.

## Stages (timed individually)

| Stage | Module | What it does |
|---|---|---|
| Parsing | `src/ingestion.py`, `backend/schema.py` | Reads files / frames, extracts timestamp, level, message; malformed rows are kept as `unparsed`, not dropped |
| Normalization | `src/preprocessing.py` | Timestamps (naive UTC, ns), level mapping, text cleanup |
| Aggregation | `backend/aggregation.py` | Windowed counts (failed logins, unique IPs, event rate) |
| Features | `src/feature_engineering.py` | Security and frequency features |
| Detection | `src/model.py` | Isolation Forest or One-Class SVM (SVM trains on ≤ 20,000 sampled rows, scores all) |
| Risk | `backend/risk.py`, `backend/rules.py`, `backend/statistical.py`, `backend/fusion.py` | Rule engine (vectorized AST evaluation), statistical score, weighted fusion into 0–100 risk, severity |
| Persistence | `backend/database.py` | Idempotent batched inserts into SQLite |
| Alerts | `backend/alert_generator.py` | Alerts for Medium and above with evidence |

## Components

- **Collectors:** `backend/log_collector.py` (files/folders), `backend/system_logs.py` (host logs per OS), `backend/monitoring.py` (watcher with checkpoints and failure recovery).
- **Storage:** SQLite (`data/monitoring.db` by default; override with `CYBERSPECTRA_DB`) with additive migrations; tables include events, alerts, runs, audit logs and `notification_state`.
- **Analytics:** `backend/analytics.py` read-only SQL for KPIs, charts and entity rankings.
- **UI:** `app/dashboard.py` entry point; `app/views/*` pages; `app/ui/*` theme, charts, components; `app/services.py` session and analysis orchestration.
- **Reporting:** `backend/reporting.py` CSV and PDF.

## Notifications

Critical alerts with no `notified_at` raise a banner/toast once and are then marked notified. The bell counts critical alerts without `acknowledged_at`. Acknowledging does not change the alert.

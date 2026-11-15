# Data

`data/logs/` holds **small synthetic sample logs** (Linux auth/syslog, Apache, Nginx, AWS CloudTrail-style, Windows-style) for trying the pipeline.

## Using your own logs
Upload them through the dashboard or pass paths to `python main.py`. Supported: CSV, TXT, LOG, JSON, JSONL. Plain-text lines starting with an ISO timestamp are parsed natively; CSV/JSON columns such as `timestamp`, `level`, `message`, `source` are recognised (common aliases accepted).

## Privacy
Never commit real logs. `.gitignore` excludes SQLite databases (`*.db`), generated reports, `logs/*` and `data/logs/windows_events_admin.csv` (the output of the local Windows collector). Anonymise hostnames, usernames and IPs before sharing any sample.

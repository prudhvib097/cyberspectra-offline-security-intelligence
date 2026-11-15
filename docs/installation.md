# Installation

## Prerequisites
- Python 3.11 or newer (developed on 3.14)
- Any modern browser
- Internet access **only** for the one-time `pip install` (use an internal mirror or wheel cache in restricted networks)

## Steps
```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # add requirements-dev.txt for tests
streamlit run app/dashboard.py
```
The app opens at http://localhost:8501.

## Optional environment variables
See `.env.example`: `CYBERSPECTRA_DB` and `CYBERSPECTRA_AUDIT_LOG`. No secrets are needed.

## Host log collection permissions
- **Linux:** `/var/log/auth.log` and similar need read access (`sudo` or the `adm` group); the journal needs `journalctl` access.
- **macOS:** the unified log works for the current user; some files need elevated access.
- **Windows:** `wevtutil` works for System/Application; the Security channel needs an elevated session.

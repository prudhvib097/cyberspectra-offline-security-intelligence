# Contributing

1. Create a virtual environment and `pip install -r requirements-dev.txt`.
2. Keep changes surgical and match the existing style; the UI is a thin client over `backend/pipeline.py`, so detection logic belongs in `backend/` or `src/`.
3. Run `python -m pytest -q` before opening a pull request; add tests for new behaviour.
4. Never commit real logs, databases, reports or secrets (see `.gitignore`).
5. Do not add network calls or remote assets: the product must run offline.

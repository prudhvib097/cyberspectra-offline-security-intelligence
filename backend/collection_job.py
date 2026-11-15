"""Controlled launcher and tracker for collection worker processes.

One job at a time. The dashboard asks this module to start a job, then polls `status()`, which is derived ONLY from the
worker's structured status.jsonl (never from console text). Everything the worker needs goes through a private job
directory (request.json in, status.jsonl + result.csv out); nothing user-controlled reaches a shell or argv.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import pandas as pd

from backend import system_logs

ROOT = Path(__file__).resolve().parents[1]
JOB_PREFIX = "cyberspectra-job-"
CREATE_NEW_CONSOLE = 0x00000010  # subprocess.CREATE_NEW_CONSOLE (defined only on Windows)
CREATE_NO_WINDOW = 0x08000000
MAX_JOB_SECONDS = 900
STALE_JOB_SECONDS = 24 * 3600
LIMITS = {"max_events": (100, 50_000), "hours": (1, 720)}


def validate_request(sources: list[str], channels: list[str] | None, max_events: int, hours: int) -> dict:
    """Allow-list validation: only sources this machine really offers, only known Windows channels, bounded numbers."""
    usable = {o["id"] for o in system_logs.available_sources() if o["ok"]}
    if not sources:
        raise ValueError("Select at least one source to collect.")
    bad = [s for s in sources if s not in usable]
    if bad:
        raise ValueError(f"Source not available on this computer: {bad[0]}")
    channels = list(channels or [])
    unknown = [c for c in channels if c not in system_logs.WINDOWS_CHANNELS]
    if unknown:
        raise ValueError(f"Unsupported Windows channel: {unknown[0]}")
    if "windows-events" in sources and not channels:
        raise ValueError("Select at least one Windows channel.")
    for name, value in (("max_events", max_events), ("hours", hours)):
        low, high = LIMITS[name]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f"{name.replace('_', ' ')} must be a whole number between {low} and {high}.")
    return {"sources": list(dict.fromkeys(sources)), "channels": list(dict.fromkeys(channels)), "max_events": max_events, "hours": hours}


def creation_flags(console: bool, windows: bool | None = None) -> int:
    """Windows: a visible console for the worker, or no window at all. Elsewhere: no special flags."""
    is_windows = (os.name == "nt") if windows is None else windows
    if not is_windows:
        return 0
    return CREATE_NEW_CONSOLE if console else CREATE_NO_WINDOW


def local_console_allowed() -> bool:
    """A terminal can only be opened on the machine running this server: never in the hosted edition."""
    return os.name == "nt" and os.environ.get("CYBERSPECTRA_EDITION", "local").lower() != "hosted"


def collection_allowed() -> bool:
    """Reading a server's own system logs is meaningless (and unsafe) in the hosted edition."""
    return os.environ.get("CYBERSPECTRA_EDITION", "local").lower() != "hosted"


class CollectionManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._dir: Path | None = None
        self._job_id: str | None = None
        self._started = 0.0
        self._console = False
        self._cancelled = False
        self._consumed = False
        self._purge_stale()

    # ---- lifecycle -------------------------------------------------------------------------------------------------
    @staticmethod
    def _purge_stale() -> None:
        base = Path(tempfile.gettempdir())
        for path in base.glob(f"{JOB_PREFIX}*"):
            try:
                if path.is_dir() and time.time() - path.stat().st_mtime > STALE_JOB_SECONDS:
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and not self._finished_event()

    def start(self, sources: list[str], channels: list[str] | None, max_events: int, hours: int, console: bool = True) -> str:
        request = validate_request(sources, channels, max_events, hours)
        if not collection_allowed():
            raise PermissionError("Collecting local system logs is disabled in the hosted edition.")
        with self._lock:
            if self.is_running():
                raise RuntimeError("A collection is already running.")
            self._cleanup_dir()
            console = bool(console and local_console_allowed())
            job_dir = Path(tempfile.mkdtemp(prefix=JOB_PREFIX))
            os.chmod(job_dir, 0o700)
            (job_dir / "request.json").write_text(json.dumps({**request, "hold": console}), encoding="utf-8")
            (job_dir / "status.jsonl").touch()
            kwargs: dict = {"cwd": str(ROOT), "creationflags": creation_flags(console)} if os.name == "nt" else {"cwd": str(ROOT)}
            if not console:
                kwargs.update(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self._proc = subprocess.Popen([sys.executable, "-m", "backend.collector_worker", str(job_dir)], **kwargs)
            except OSError as exc:
                shutil.rmtree(job_dir, ignore_errors=True)
                raise RuntimeError(f"The collection worker could not be started: {exc}") from exc
            self._dir, self._job_id, self._started = job_dir, uuid.uuid4().hex[:8], time.time()
            self._console, self._cancelled, self._consumed = console, False, False
            return self._job_id

    def cancel(self) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None and not self._finished_event():
                self._cancelled = True
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()

    # ---- status ----------------------------------------------------------------------------------------------------
    def _events(self) -> list[dict]:
        if self._dir is None or not (self._dir / "status.jsonl").exists():
            return []
        out = []
        for line in (self._dir / "status.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _finished_event(self) -> dict | None:
        return next((e for e in reversed(self._events()) if e.get("event") == "finished"), None)

    def status(self) -> dict | None:
        if self._job_id is None or self._dir is None:
            return None
        events = self._events()
        finished = next((e for e in reversed(events) if e.get("event") == "finished"), None)
        proc, elapsed = self._proc, time.time() - self._started
        returncode = proc.poll() if proc else None
        if self._cancelled:
            state, outcome = "cancelled", "cancelled"
        elif finished:
            outcome = finished.get("status", "failed")
            state = "failed" if outcome == "failed" else "completed"
        elif returncode is not None:
            state, outcome = "failed", "failed"
            events.append({"ts": datetime.now().isoformat(timespec="seconds"), "level": "ERROR", "message": f"The collection worker exited unexpectedly (code {returncode}).", "event": "log"})
        elif elapsed > MAX_JOB_SECONDS:
            self.cancel()
            state, outcome = "failed", "failed"
            events.append({"ts": datetime.now().isoformat(timespec="seconds"), "level": "ERROR", "message": f"Collection exceeded {MAX_JOB_SECONDS} seconds and was stopped.", "event": "log"})
        else:
            state, outcome = ("running" if events else "starting"), None
        progress = [e for e in events if e.get("event") == "progress"]
        starts = [e for e in events if e.get("event") == "source_started"]
        done = {e.get("source") for e in events if e.get("event") == "source_finished"}
        current = next((e["source"] for e in reversed(starts) if e["source"] not in done), None)
        shown = [e for e in events if e.get("event") != "progress" or e is progress[-1]][-14:]
        return {
            "job_id": self._job_id, "state": state, "outcome": outcome, "current": current,
            "current_count": progress[-1].get("count") if progress and current else None,
            "lines": [(e.get("ts", "")[11:19], e.get("level", "INFO"), e.get("message", "")) for e in shown],
            "summary": finished, "elapsed": round(elapsed, 1), "console": self._console, "returncode": returncode, "consumed": self._consumed,
        }

    # ---- result ----------------------------------------------------------------------------------------------------
    def take_result(self) -> pd.DataFrame:
        """Return the collected events once, then delete the job directory (event data must not linger on disk)."""
        if self._dir is None or self._consumed:
            return pd.DataFrame()
        path = self._dir / "result.csv"
        frame = pd.read_csv(path) if path.exists() else pd.DataFrame()
        if "timestamp" in frame:
            frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        self._consumed = True
        for name in ("result.csv", "request.json"):
            try:
                (self._dir / name).unlink()
            except OSError:
                pass
        return frame

    def _cleanup_dir(self) -> None:
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None

    def dismiss(self) -> None:
        with self._lock:
            if not self.is_running():
                self._cleanup_dir()
                self._job_id = None

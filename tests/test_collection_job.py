"""Collection job manager, worker and Windows wevtutil streaming (the latter exercised with a fake `wevtutil`)."""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

import pandas as pd
import pytest

from backend import collection_job, system_logs
from backend.collection_job import CollectionManager, creation_flags, validate_request


def _wait(manager: CollectionManager, timeout: float = 60.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        status = manager.status()
        if status and status["state"] not in ("starting", "running"):
            return status
        time.sleep(0.3)
    raise AssertionError("collection did not finish in time")


@pytest.fixture()
def log_source(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(f"Nov 14 10:{i % 60:02d}:00 host sshd[1]: Failed password for root from 10.0.0.{i % 9} port 22 ssh2" for i in range(120)))
    source_id = f"file:{log}"
    real = system_logs.available_sources
    monkeypatch.setattr(system_logs, "available_sources", lambda: real() + [{"id": source_id, "label": str(log), "ok": True, "reason": "test"}])
    return source_id


def test_validation_rejects_bad_requests(log_source):
    with pytest.raises(ValueError):
        validate_request([], None, 500, 24)
    with pytest.raises(ValueError):
        validate_request(["file:/etc/shadow"], None, 500, 24)  # not an offered source
    with pytest.raises(ValueError):
        validate_request(["windows-events"], ["Security; calc.exe"], 500, 24)
    with pytest.raises(ValueError):
        validate_request([log_source], None, 5, 24)
    with pytest.raises(ValueError):
        validate_request([log_source], None, 500, 100000)
    with pytest.raises(ValueError):
        validate_request([log_source], None, True, 24)  # bool is not a count
    assert validate_request([log_source, log_source], None, 500, 24)["sources"] == [log_source]


def test_windows_console_flags_only_on_windows():
    assert creation_flags(True, windows=True) == collection_job.CREATE_NEW_CONSOLE
    assert creation_flags(False, windows=True) == collection_job.CREATE_NO_WINDOW
    assert creation_flags(True, windows=False) == 0


def test_job_collects_and_hands_over_result_once(log_source):
    manager = CollectionManager()
    manager.start([log_source], None, 100, 24, console=False)
    status = _wait(manager)
    assert status["state"] == "completed" and status["outcome"] == "success"
    assert status["summary"]["total_events"] == 100 and status["summary"]["failed"] == 0
    job_dir = manager._dir
    frame = manager.take_result()
    assert len(frame) == 100 and {"raw_line", "timestamp", "source_file"} <= set(frame.columns)
    assert not (job_dir / "result.csv").exists() and manager.take_result().empty  # no event data left, and no double delivery
    manager.dismiss()
    assert not job_dir.exists()


def test_second_start_while_running_is_refused(log_source, monkeypatch):
    real_popen = collection_job.subprocess.Popen
    monkeypatch.setattr(collection_job.subprocess, "Popen", lambda args, **kw: real_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kw))
    manager = CollectionManager()
    manager.start([log_source], None, 100, 24, console=False)
    with pytest.raises(RuntimeError, match="already running"):
        manager.start([log_source], None, 100, 24, console=False)
    manager.cancel()
    assert manager.status()["state"] == "cancelled"
    manager.start([log_source], None, 100, 24, console=False)  # allowed again after cancellation
    manager.cancel()


def test_worker_crash_is_reported_not_success(log_source, monkeypatch):
    real_popen = collection_job.subprocess.Popen
    monkeypatch.setattr(collection_job.subprocess, "Popen", lambda args, **kw: real_popen([sys.executable, "-c", "raise SystemExit(3)"], **kw))
    manager = CollectionManager()
    manager.start([log_source], None, 100, 24, console=False)
    status = _wait(manager)
    assert status["state"] == "failed" and any("exited unexpectedly" in line[2] for line in status["lines"])


def test_unreadable_source_fails_honestly(tmp_path, monkeypatch):
    missing = f"file:{tmp_path / 'nope.log'}"
    real = system_logs.available_sources
    monkeypatch.setattr(system_logs, "available_sources", lambda: real() + [{"id": missing, "label": "nope", "ok": True, "reason": "test"}])
    manager = CollectionManager()
    manager.start([missing], None, 100, 24, console=False)
    status = _wait(manager)
    assert status["state"] == "failed" and status["summary"]["total_events"] == 0 and status["outcome"] == "failed"


def test_hosted_edition_blocks_collection_and_console(log_source, monkeypatch):
    monkeypatch.setenv("CYBERSPECTRA_EDITION", "hosted")
    assert not collection_job.local_console_allowed() and not collection_job.collection_allowed()
    with pytest.raises(PermissionError):
        CollectionManager().start([log_source], None, 100, 24, console=True)


EVENT = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID><Level>{lvl}</Level><TimeCreated SystemTime='2026-11-14T10:20:{sec:02d}.000000000Z'/><Computer>HOST1</Computer></System><EventData><Data Name='p'>svc {n}</Data></EventData></Event>"""


def _fake_wevtutil(tmp_path: Path, monkeypatch, body: str) -> Path:
    script = tmp_path / "bin" / "wevtutil"
    script.parent.mkdir(exist_ok=True)
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ['PATH']}")
    return script


def test_wevtutil_stream_parses_namespaced_events_and_reports_real_progress(tmp_path, monkeypatch):
    events = "\n".join(EVENT.format(lvl=2 if i % 2 else 4, sec=i % 60, n=i) for i in range(600))
    _fake_wevtutil(tmp_path, monkeypatch, f"cat <<'EOF'\n{events}\nEOF\n")
    from src.windows_event_ingest import stream_wevtutil

    seen: list[int] = []
    frame = stream_wevtutil("System", 600, 24, seen.append)
    assert len(frame) == 600 and seen == [250, 500, 600]
    assert set(frame["level"]) == {"ERROR", "INFO"} and frame["computer"].eq("HOST1").all()


def test_wevtutil_errors_map_to_specific_exceptions(tmp_path, monkeypatch):
    from src.windows_event_ingest import stream_wevtutil

    _fake_wevtutil(tmp_path, monkeypatch, "echo 'Access is denied.' >&2; exit 5\n")
    with pytest.raises(PermissionError):
        stream_wevtutil("Security", 10)
    _fake_wevtutil(tmp_path, monkeypatch, "echo 'The specified channel could not be found.' >&2; exit 15007\n")
    with pytest.raises(LookupError):
        stream_wevtutil("Nope", 10)


def test_windows_channel_collection_uses_live_reader_not_exported_csv(tmp_path, monkeypatch):
    events = "\n".join(EVENT.format(lvl=3, sec=i, n=i) for i in range(5))
    _fake_wevtutil(tmp_path, monkeypatch, f"cat <<'EOF'\n{events}\nEOF\n")
    frame = system_logs.collect_windows_channel("Application", 100, 24)
    assert len(frame) == 5 and frame["source_file"].eq("Application").all() and pd.api.types.is_datetime64_any_dtype(frame["timestamp"])
    with pytest.raises(ValueError):
        system_logs.collect_windows_channel("Security; calc", 10)

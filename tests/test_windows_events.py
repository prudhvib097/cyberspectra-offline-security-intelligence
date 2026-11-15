"""Windows channel reader: statuses, parsing, filters, API path, overall status, pipeline + persistence.

Mocked Windows only (a fake `wevtutil` script and a fake `win32evtlog` module). These tests prove the logic, NOT that the
collector works on a real Windows 11 machine; that needs `python -m backend.windows_events --diagnose` run there.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
import time
import types
from pathlib import Path

import pandas as pd
import pytest

from backend import system_logs, windows_events as we
from backend.collection_job import CollectionManager
from backend.database import SQLiteStore
from backend.pipeline import run_pipeline

EV = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Svc'/><EventID>{eid}</EventID><Level>{lvl}</Level>"
      "<TimeCreated SystemTime='{ts}'/><EventRecordID>{rid}</EventRecordID><Computer>HOST1</Computer></System><EventData><Data>msg {rid}</Data></EventData></Event>")


def ev(rid: int, ts: str | None = None, eid: int = 7036, lvl: int = 4) -> str:
    stamp = ts or (pd.Timestamp.now(tz="UTC") - pd.Timedelta(minutes=rid)).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
    return EV.format(eid=eid, lvl=lvl, ts=stamp, rid=rid)


def fake_wevtutil(tmp_path: Path, monkeypatch, *, qe="", gl="Enabled: true", gli="numberOfLogRecords: 100", qe_rc=0, gl_rc=0, qe_probe=None) -> Path:
    """sh script emulating `wevtutil gl|gli|qe`. `qe_probe` (if given) is printed for queries WITHOUT a /q: filter."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (tmp_path / "args.txt").write_text("")
    qe_file, probe_file = tmp_path / "qe.xml", tmp_path / "probe.xml"
    qe_file.write_text(qe)
    probe_file.write_text(qe_probe if qe_probe is not None else qe)
    script = bin_dir / "wevtutil"
    script.write_text(f"""#!/bin/sh
echo "$@" >> "{tmp_path / 'args.txt'}"
case "$1" in
  gl) if [ {gl_rc} -ne 0 ]; then echo 'The specified channel could not be found.' >&2; exit 1; fi; printf '%s\\n' "name: x" "{gl}"; exit 0;;
  gli) printf '%s\\n' "{gli}"; exit 0;;
  qe) case "$*" in *"/q:"*) cat "{qe_file}";; *) cat "{probe_file}";; esac
      if [ {qe_rc} -ne 0 ]; then echo 'Access is denied.' >&2; fi; exit {qe_rc};;
esac
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return tmp_path / "args.txt"


def test_system_and_application_retrieve_parsed_events(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe="\n".join(ev(i) for i in range(1, 51)))
    for channel in ("System", "Application"):
        r = we.read_channel(channel, 100, 24)
        assert r.status == we.SUCCESS and r.count == 50 and r.raw_count == r.parsed_count == 50
        row = r.events.iloc[0]
        assert row.event_id == 7036 and row.source == "Svc" and row.level == "INFO" and row.computer == "HOST1" and "<Event" in row.raw_xml


def test_lookback_and_max_are_passed_to_windows_and_newest_first(tmp_path, monkeypatch):
    args = fake_wevtutil(tmp_path, monkeypatch, qe=ev(1))
    we.read_channel("System", 123, 6)
    line = [l for l in args.read_text().splitlines() if l.startswith("qe System")][0]
    assert "/c:123" in line and "/rd:true" in line and f"<= {6 * 3600 * 1000}" in line and "/f:xml" in line


def test_unparseable_events_are_an_error_not_a_silent_zero(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe="<Event><garbage></Event>\n<Event>also bad</Event>")
    r = we.read_channel("System", 100, 24)
    assert r.status == we.ERROR and r.raw_count == 2 and r.parsed_count == 0 and "none could be parsed" in r.message


def test_malformed_events_are_skipped_but_counted(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe=ev(1) + "\n<Event>bad</Event>\n" + ev(2))
    r = we.read_channel("System", 100, 24)
    assert r.status == we.SUCCESS and r.count == 2 and r.raw_count == 3 and r.parse_errors == 1 and "malformed" in r.message


def test_invalid_timestamp_keeps_the_event(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe=ev(1, ts="not-a-time"))
    r = we.read_channel("System", 10, 24)
    assert r.count == 1 and pd.isna(r.events.iloc[0].timestamp)


def test_security_access_denied_gives_actionable_message(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe_rc=5)
    r = we.read_channel("Security", 100, 24)
    assert r.status == we.ACCESS_DENIED and "Run as administrator" in r.message and r.count == 0


def test_missing_and_disabled_and_empty_channels_are_distinct(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, gl_rc=15007)
    assert we.read_channel("ForwardedEvents", 10, 24).status == we.CHANNEL_NOT_FOUND
    fake_wevtutil(tmp_path, monkeypatch, gl="Enabled: false", gli="numberOfLogRecords: 0")
    assert we.read_channel("Microsoft-Windows-Windows Defender/Operational", 10, 24).status == we.DISABLED
    fake_wevtutil(tmp_path, monkeypatch, gl="Enabled: true", gli="numberOfLogRecords: 0")
    r = we.read_channel("ForwardedEvents", 10, 24)
    assert r.status == we.EMPTY and "contains no events" in r.message


def test_empty_window_is_explained_with_the_newest_event(tmp_path, monkeypatch):
    old = ev(1, ts=(pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%S.000000000Z"))
    fake_wevtutil(tmp_path, monkeypatch, qe="", qe_probe=old, gli="numberOfLogRecords: 400")
    r = we.read_channel("System", 100, 24)
    assert r.status == we.EMPTY and "newest event" in r.message and "400" in r.message


def test_windows_has_records_but_query_returns_none_is_flagged(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe="", qe_probe="", gli="numberOfLogRecords: 500")
    r = we.read_channel("System", 100, 24)
    assert r.status == we.ERROR and "500" in r.message


def test_duplicate_records_are_removed(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe=ev(1, ts="2026-11-14T10:00:00.000000000Z") + "\n" + ev(1, ts="2026-11-14T10:00:00.000000000Z") + "\n" + ev(2))
    r = we.read_channel("System", 100, None)
    assert r.count == 2 and r.duplicates == 1


def _fake_win32evtlog(monkeypatch, events: list[str], error: Exception | None = None):
    mod = types.ModuleType("win32evtlog")
    mod.EvtQueryChannelPath, mod.EvtQueryReverseDirection, mod.EvtRenderEventXml = 0x1, 0x200, 1
    calls = {"query": None, "pos": 0}

    def EvtQuery(channel, flags, query, session):
        if error:
            raise error
        calls["query"] = (channel, flags, query)
        return "h"

    def EvtNext(handle, count):
        batch = events[calls["pos"]:calls["pos"] + count]
        calls["pos"] += len(batch)
        return batch

    mod.EvtQuery, mod.EvtNext, mod.EvtRender = EvtQuery, EvtNext, lambda event, flag: event
    monkeypatch.setitem(sys.modules, "win32evtlog", mod)
    return calls


def test_event_api_path_respects_limit_filter_and_order(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe="")  # metadata calls only
    calls = _fake_win32evtlog(monkeypatch, [ev(i) for i in range(1, 301)])
    r = we.read_channel("Application", 150, 12)
    assert r.status == we.SUCCESS and r.count == 150 and r.method == "windows-event-api"
    channel, flags, query = calls["query"]
    assert channel == "Application" and flags & 0x200 and f"<= {12 * 3600 * 1000}" in query


def test_event_api_access_denied_maps_to_status(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch)
    err = Exception(5, "EvtQuery", "Access is denied.")
    err.winerror = 5
    _fake_win32evtlog(monkeypatch, [], err)
    assert we.read_channel("Security", 10, 24).status == we.ACCESS_DENIED


def test_event_api_unexpected_failure_falls_back_to_wevtutil(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe=ev(1) + "\n" + ev(2))
    _fake_win32evtlog(monkeypatch, [], RuntimeError("boom"))
    r = we.read_channel("System", 10, 24)
    assert r.status == we.SUCCESS and r.count == 2 and r.method == "wevtutil"


def test_unsupported_channel_is_rejected():
    with pytest.raises(ValueError):
        we.read_channel("System; calc", 10, 24)


def test_diagnose_reports_without_changing_anything(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe=ev(1))
    report = we.diagnose(["System"], 24)
    assert report["channels"]["System"]["probe_status"] == we.SUCCESS and report["elevated"] is None  # not Windows here
    assert "System:" in we.format_report(report)


# ---- overall collection status through the real worker process -------------------------------------------------------
def _run_job(monkeypatch, channels):
    real = system_logs.available_sources
    monkeypatch.setattr(system_logs, "available_sources", lambda: real() + [{"id": "windows-events", "label": "Windows Event Log", "ok": True, "reason": "test"}])
    manager = CollectionManager()
    manager.start(["windows-events"], channels, 100, 24, console=False)
    end = time.time() + 60
    while time.time() < end:
        status = manager.status()
        if status["state"] not in ("starting", "running"):
            return manager, status
        time.sleep(0.3)
    raise AssertionError("job did not finish")


def test_partial_all_failed_and_empty_overall_statuses(tmp_path, monkeypatch):
    # System readable, Security denied -> partial (cannot mix per-channel behaviour in one fake, so use a script keyed on the channel)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ok_file = tmp_path / "ok.xml"
    ok_file.write_text(ev(1) + "\n" + ev(2))
    script = bin_dir / "wevtutil"
    script.write_text(f"""#!/bin/sh
case "$1" in
  gl) echo "Enabled: true"; exit 0;;
  gli) echo "numberOfLogRecords: 0"; exit 0;;
  qe) case "$2" in Security) echo 'Access is denied.' >&2; exit 5;; System) cat "{ok_file}"; exit 0;; *) exit 0;; esac;;
esac
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    manager, status = _run_job(monkeypatch, ["System", "Security", "Application"])
    summary = status["summary"]
    assert status["outcome"] == "partial" and summary["total_events"] == 2
    assert summary["sources"]["System"]["status"] == "SUCCESS" and summary["sources"]["Security"]["status"] == "ACCESS_DENIED"
    assert summary["sources"]["Application"]["status"] == "EMPTY"
    assert (summary["ok"], summary["empty"], summary["failed"]) == (1, 1, 1)
    assert len(manager.take_result()) == 2
    manager.dismiss()

    manager, status = _run_job(monkeypatch, ["Security"])
    assert status["outcome"] == "failed" and status["state"] == "failed" and manager.take_result().empty
    manager.dismiss()

    manager, status = _run_job(monkeypatch, ["Application"])
    assert status["outcome"] == "empty" and status["summary"]["total_events"] == 0
    manager.dismiss()


# ---- pipeline integration + persistence ------------------------------------------------------------------------------
def test_collected_windows_events_reach_the_pipeline_and_persist_without_duplicates(tmp_path, monkeypatch):
    fake_wevtutil(tmp_path, monkeypatch, qe="\n".join(ev(i, eid=4625 if i % 3 == 0 else 7036, lvl=2 if i % 3 == 0 else 4) for i in range(1, 121)))
    frame = system_logs.collect_windows_channel("System", 200, 24)
    assert len(frame) == 120 and "raw_event" in frame.columns
    db = tmp_path / "t.db"
    store = SQLiteStore(str(db))
    bundle = run_pipeline(frame, contamination=0.1, algorithm="isolation_forest", store=store)
    assert len(bundle.scored_frame) == 120
    count = lambda: sqlite3.connect(db).execute("select count(*) from events").fetchone()[0]
    first = count()
    assert first == 120
    run_pipeline(frame, contamination=0.1, algorithm="isolation_forest", store=SQLiteStore(str(db)))
    assert count() == first  # re-collecting an overlapping window does not duplicate events

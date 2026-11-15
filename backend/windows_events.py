"""Windows Event Log reader with explicit per-channel outcomes and a diagnostic report.

Design rules (this module exists because a collection once "succeeded" with 0 events and nothing explained why):
  * Every channel ends in exactly one status: SUCCESS, EMPTY, ACCESS_DENIED, CHANNEL_NOT_FOUND, DISABLED or ERROR.
  * Events are counted twice, raw (as received) and parsed; a mismatch is an ERROR, never silently ignored.
  * An EMPTY result is cross-checked against Windows' own record count and newest-event time for that channel,
    so "nothing in the look-back window" can be told apart from "the query is wrong".
  * Reads use the Windows Event Log API (pywin32 EvtQuery/EvtNext/EvtRender) when available and `wevtutil` otherwise.
    Channel names are validated against an allow-list and passed as single argv items, never through a shell.
  * No fake data, no reading of previously exported files, no permission changes, no automatic elevation.

CLI (run on the Windows machine to see exactly what Windows returns):
    python -m backend.windows_events --diagnose
    python -m backend.windows_events --channel System --hours 24 --max 5
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

SUCCESS, EMPTY, ACCESS_DENIED, CHANNEL_NOT_FOUND, DISABLED, ERROR = "SUCCESS", "EMPTY", "ACCESS_DENIED", "CHANNEL_NOT_FOUND", "DISABLED", "ERROR"
CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational", "ForwardedEvents"]
ELEVATION_HINT = ("Security event collection requires an elevated Windows session. Restart CyberSpectra using Run as administrator "
                  "to collect this channel (or have an administrator add your account to the 'Event Log Readers' group).")
ERR_ACCESS_DENIED, ERR_CHANNEL_NOT_FOUND = 5, 15007
LEVELS = {1: "CRITICAL", 2: "ERROR", 3: "WARNING", 4: "INFO", 5: "DEBUG", 0: "INFO"}
_XMLNS = re.compile(r'\sxmlns(?::\w+)?=("[^"]*"|\'[^\']*\')')
COLUMNS = ["timestamp", "record_id", "event_id", "level", "source", "message", "computer", "raw_xml"]


@dataclass
class ChannelResult:
    channel: str
    status: str
    events: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=COLUMNS))
    raw_count: int = 0
    parsed_count: int = 0
    parse_errors: int = 0
    duplicates: int = 0
    message: str = ""
    info: dict = field(default_factory=dict)
    method: str = ""

    @property
    def count(self) -> int:
        return len(self.events)


def is_windows() -> bool:
    return os.name == "nt"


def is_elevated() -> bool | None:
    """True/False on Windows, None elsewhere. Read-only check of the current process token."""
    if not is_windows():
        return None
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return None


def validate_channel(channel: str) -> str:
    if channel not in CHANNELS:
        raise ValueError(f"unsupported Windows channel: {channel!r}")
    return channel


# ---- parsing ---------------------------------------------------------------------------------------------------------
def parse_event_xml(xml: str) -> dict:
    """Parse ONE event's XML. Raises ValueError (with the reason) instead of returning nothing."""
    try:
        ev = ET.fromstring(_XMLNS.sub("", xml.strip().lstrip("﻿")))
    except ET.ParseError as exc:
        raise ValueError(f"invalid event XML: {exc}") from exc
    system = ev.find("System")
    if system is None:
        raise ValueError("event has no <System> section")

    def text(tag: str) -> str | None:
        el = system.find(tag)
        return el.text if el is not None else None

    tc = system.find("TimeCreated")
    stamp = pd.to_datetime(tc.attrib.get("SystemTime") if tc is not None else None, utc=True, errors="coerce")
    prov = system.find("Provider")
    provider = prov.attrib.get("Name") if prov is not None else None
    try:
        event_id = int((text("EventID") or "").strip())
    except ValueError:
        event_id = None
    try:
        level = LEVELS.get(int((text("Level") or "4").strip()), "INFO")
    except ValueError:
        level = "INFO"
    data = [d.text for d in ev.findall("./EventData/Data") if d.text] + [d.text for d in ev.findall("./UserData//*") if d.text and not list(d)]
    message = " | ".join(data) if data else f"{provider or 'Unknown provider'} event {event_id if event_id is not None else '?'} (no description data)"
    return {"timestamp": stamp, "record_id": text("EventRecordID"), "event_id": event_id, "level": level, "source": provider,
            "message": message, "computer": text("Computer"), "raw_xml": xml.strip()}


# ---- channel metadata (read-only, fixed commands) --------------------------------------------------------------------
def _run(args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)


def _kv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            out[key.strip().lower()] = value.strip()
    return out


def channel_info(channel: str) -> dict:
    """exists / enabled / record count / newest write time as reported by Windows itself (best effort)."""
    info: dict = {"exists": None, "enabled": None, "records": None, "last_write": None, "error": None}
    try:
        gl = _run(["wevtutil", "gl", validate_channel(channel)])
    except (OSError, subprocess.TimeoutExpired) as exc:
        info["error"] = f"wevtutil unavailable: {exc}"
        return info
    if gl.returncode == ERR_CHANNEL_NOT_FOUND or (gl.returncode and "could not be found" in (gl.stderr or "").lower()):
        info["exists"] = False
        return info
    if gl.returncode == ERR_ACCESS_DENIED:
        info["exists"], info["error"] = True, "access denied reading channel configuration"
    elif gl.returncode == 0:
        info["exists"] = True
        enabled = _kv(gl.stdout).get("enabled")
        info["enabled"] = None if enabled is None else enabled.lower() == "true"
    try:
        gli = _run(["wevtutil", "gli", channel])
        if gli.returncode == 0:
            kv = _kv(gli.stdout)
            if kv.get("numberoflogrecords", "").isdigit():
                info["records"] = int(kv["numberoflogrecords"])
            info["last_write"] = kv.get("lastwritetime")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return info


# ---- readers ---------------------------------------------------------------------------------------------------------
class _Collector:
    def __init__(self, on_progress, step: int = 250) -> None:
        self.records: list[dict] = []
        self.raw = 0
        self.errors: list[str] = []
        self.error_count = 0
        self.on_progress, self.step = on_progress, step

    def add(self, xml: str) -> None:
        self.raw += 1
        try:
            self.records.append(parse_event_xml(xml))
        except ValueError as exc:
            if len(self.errors) < 5:
                self.errors.append(str(exc))
            self.error_count += 1
        if self.on_progress and self.raw % self.step == 0:
            self.on_progress(len(self.records))


def _xpath(hours: int | None) -> str:
    return "*" if not hours else f"*[System[TimeCreated[timediff(@SystemTime) <= {int(hours) * 3600 * 1000}]]]"


def _read_evt_api(channel: str, limit: int, hours: int | None, sink: _Collector) -> None:
    """Windows Event Log API through pywin32 (no subprocess, no quoting, no console encoding)."""
    import win32evtlog  # type: ignore

    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = win32evtlog.EvtQuery(channel, flags, _xpath(hours), None)
    while sink.raw < limit:
        batch = win32evtlog.EvtNext(handle, min(100, limit - sink.raw))
        if not batch:
            break
        for event in batch:
            sink.add(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))


def _read_wevtutil(channel: str, limit: int, hours: int | None, sink: _Collector, timeout: float = 180.0) -> None:
    cmd = ["wevtutil", "qe", channel, "/f:xml", f"/c:{int(limit)}", "/rd:true"]
    if hours:
        cmd.append(f"/q:{_xpath(hours)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    timed_out = threading.Event()
    timer = threading.Timer(timeout, lambda: (timed_out.set(), proc.kill()))
    timer.start()
    buffer: list[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            buffer.append(line)
            if "</Event>" in line:
                sink.add("".join(buffer))
                buffer = []
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
    stderr = (proc.stderr.read() if proc.stderr else "") or ""
    if timed_out.is_set():
        raise TimeoutError(f"wevtutil did not finish within {int(timeout)} seconds")
    if proc.returncode not in (0, None):
        if proc.returncode == ERR_ACCESS_DENIED or "access is denied" in stderr.lower():
            raise PermissionError("access denied")
        if proc.returncode == ERR_CHANNEL_NOT_FOUND or "could not be found" in stderr.lower():
            raise LookupError("channel not found")
        raise RuntimeError(f"wevtutil exited with code {proc.returncode}: {stderr.strip()[:200]}")


def _winerror(exc: Exception) -> int | None:
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None) and isinstance(exc.args[0], int):
        code = exc.args[0]
    return code


def read_channel(channel: str, limit: int = 500, hours: int | None = 24, on_progress=None, prefer_api: bool = True) -> ChannelResult:
    """Read one channel and classify the outcome. Never raises for expected Windows conditions."""
    validate_channel(channel)
    result = ChannelResult(channel=channel, status=ERROR)
    info = result.info = channel_info(channel)
    if info.get("exists") is False:
        result.status, result.message = CHANNEL_NOT_FOUND, f"The channel '{channel}' does not exist on this computer."
        return result

    sink = _Collector(on_progress)
    attempts: list[tuple[str, object]] = []
    if prefer_api:
        try:
            import win32evtlog  # type: ignore  # noqa: F401

            attempts.append(("windows-event-api", _read_evt_api))
        except ImportError:
            pass
    attempts.append(("wevtutil", _read_wevtutil))

    failure: tuple[str, str] | None = None
    for method, reader in attempts:
        sink.records, sink.raw, sink.errors = [], 0, []
        sink.error_count = 0
        try:
            reader(channel, limit, hours, sink)
            result.method, failure = method, None
            break
        except PermissionError:
            result.method, failure = method, (ACCESS_DENIED, ELEVATION_HINT if channel == "Security" else
                                              f"Access denied reading '{channel}'. Run CyberSpectra as administrator, or have an administrator add your account to the 'Event Log Readers' group.")
            break
        except LookupError:
            result.method, failure = method, (CHANNEL_NOT_FOUND, f"The channel '{channel}' does not exist on this computer.")
            break
        except TimeoutError as exc:
            result.method, failure = method, (ERROR, f"{channel}: {exc}")
            break
        except Exception as exc:  # noqa: BLE001 - includes pywintypes.error; classify by Windows error code, else try the next reader
            code = _winerror(exc)
            if code == ERR_ACCESS_DENIED:
                result.method, failure = method, (ACCESS_DENIED, ELEVATION_HINT if channel == "Security" else f"Access denied reading '{channel}' (Windows error 5).")
                break
            if code == ERR_CHANNEL_NOT_FOUND:
                result.method, failure = method, (CHANNEL_NOT_FOUND, f"The channel '{channel}' does not exist on this computer.")
                break
            failure = (ERROR, f"{method} failed: {type(exc).__name__}: {exc}")
            continue
    result.raw_count, result.parsed_count, result.parse_errors = sink.raw, len(sink.records), sink.error_count
    if failure:
        result.status, result.message = failure
        return result

    frame = pd.DataFrame.from_records(sink.records, columns=COLUMNS) if sink.records else pd.DataFrame(columns=COLUMNS)
    if not frame.empty:
        before = len(frame)
        frame = frame.drop_duplicates(subset=["record_id", "timestamp"], keep="first").reset_index(drop=True)
        result.duplicates = before - len(frame)
    result.events = frame
    if on_progress:
        on_progress(len(frame))

    if result.raw_count and not result.parsed_count:
        result.status = ERROR
        result.message = f"{result.raw_count} events were received but none could be parsed ({'; '.join(sink.errors[:2])}). Nothing was discarded silently."
    elif result.parse_errors:
        result.status = SUCCESS if len(frame) else ERROR
        result.message = f"{len(frame)} events parsed; {result.parse_errors} malformed events skipped ({sink.errors[0]})."
    elif len(frame):
        result.status = SUCCESS
        result.message = f"Retrieved {len(frame)} events."
    else:
        result.status, result.message = _classify_empty(channel, hours, info, prefer_api)
    return result


def _classify_empty(channel: str, hours: int | None, info: dict, prefer_api: bool) -> tuple[str, str]:
    """Zero events: decide between a disabled channel, an empty channel, an empty window, and a suspicious query."""
    if info.get("enabled") is False:
        return DISABLED, f"The channel '{channel}' is disabled in Windows, so no new events are being recorded."
    total = info.get("records")
    if total == 0:
        return EMPTY, f"The channel '{channel}' exists and is readable but contains no events."
    if hours:
        probe = _Collector(None)
        try:
            _read_wevtutil(channel, 1, None, probe, timeout=30)
            if probe.records:
                newest = probe.records[0]["timestamp"]
                age = (datetime.now(timezone.utc) - newest.to_pydatetime()).total_seconds() / 3600 if pd.notna(newest) else None
                where = f"{newest:%Y-%m-%d %H:%M} UTC" + (f", {age:.1f} h ago" if age is not None else "")
                return EMPTY, f"No events in the last {hours} h. The newest event in '{channel}' is from {where}" + (f" (Windows reports {total} records)." if total else ".") + " Increase the look-back period."
        except Exception:  # noqa: BLE001 - the probe is advisory only
            pass
    if total:
        return ERROR, f"Windows reports {total} records in '{channel}' but the query returned none. This should not happen; run `python -m backend.windows_events --diagnose` and report the output."
    return EMPTY, f"No events matched in '{channel}'."


# ---- diagnostics -----------------------------------------------------------------------------------------------------
def event_log_service_state() -> str:
    if not is_windows():
        return "not applicable (not Windows)"
    try:
        out = _run(["sc", "query", "EventLog"], 10).stdout
        match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
        return match.group(1) if match else "unknown"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unknown ({exc})"


def diagnose(channels: list[str] | None = None, hours: int = 24) -> dict:
    """Read-only environment report. Changes nothing."""
    try:
        import win32evtlog  # type: ignore  # noqa: F401

        pywin32 = True
    except ImportError:
        pywin32 = False
    report = {"os": platform.platform(), "windows": is_windows(), "python": sys.version.split()[0], "pywin32": pywin32,
              "event_log_service": event_log_service_state(), "elevated": is_elevated(), "channels": {}}
    for channel in channels or CHANNELS:
        info = channel_info(channel)
        probe = read_channel(channel, limit=1, hours=hours, prefer_api=pywin32)
        report["channels"][channel] = {"exists": info.get("exists"), "enabled": info.get("enabled"), "records_per_windows": info.get("records"),
                                       "last_write": info.get("last_write"), "probe_status": probe.status, "probe_message": probe.message, "reader": probe.method}
    return report


def format_report(report: dict) -> str:
    lines = [f"OS: {report['os']}", f"Python: {report['python']}  pywin32: {'yes' if report['pywin32'] else 'no (using wevtutil)'}",
             f"Event Log service: {report['event_log_service']}",
             f"Elevated (Run as administrator): {'yes' if report['elevated'] else 'no' if report['elevated'] is False else 'n/a'}", ""]
    for name, c in report["channels"].items():
        lines.append(f"{name}: exists={c['exists']} enabled={c['enabled']} records(Windows)={c['records_per_windows']} -> {c['probe_status']}")
        lines.append(f"    {c['probe_message']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberSpectra Windows Event Log diagnostics")
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--channel", choices=CHANNELS)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--max", type=int, default=5)
    args = parser.parse_args(argv)
    if args.diagnose or not args.channel:
        print(format_report(diagnose(hours=args.hours)))
        return 0
    result = read_channel(args.channel, args.max, args.hours)
    print(f"{args.channel}: {result.status} via {result.method or 'n/a'} - {result.message}")
    print(f"raw={result.raw_count} parsed={result.parsed_count} malformed={result.parse_errors} duplicates={result.duplicates}")
    for row in result.events.head(args.max).itertuples(index=False):
        print(f"  {row.timestamp}  id={row.event_id}  {row.level}  {row.source}")
    return 0 if result.status in (SUCCESS, EMPTY) else 1


if __name__ == "__main__":
    sys.exit(main())

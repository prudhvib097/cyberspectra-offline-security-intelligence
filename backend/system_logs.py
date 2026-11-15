"""Cross-platform collection of the host's own system logs (Windows, Linux, macOS).

Everything here reads local sources only (no network) and returns a frame in the
same shape the file ingestion path produces, so the canonical pipeline handles it
unchanged. Each collector reports honest diagnostics: a source that needs
privileges or a tool that is missing is reported, never silently faked.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import pandas as pd

LINUX_FILES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log"]
MAC_FILES = ["/var/log/system.log", "/var/log/install.log", "/var/log/wifi.log"]
WINDOWS_CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational", "ForwardedEvents"]
_JOURNAL_LEVEL = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR", 4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG"}
_MAC_LEVEL = {"Fault": "CRITICAL", "Error": "ERROR", "Default": "INFO", "Info": "INFO", "Debug": "DEBUG"}
COLUMNS = ["timestamp", "level", "source", "message", "host", "raw_line", "source_file", "ingest_method"]


def os_name() -> str:
    return {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(platform.system(), platform.system() or "Unknown")


def _syslog_line(ts: pd.Timestamp | None, host: str, ident: str, message: str) -> str:
    if ts is not None and not pd.isna(ts) and ts.tzinfo is not None:
        ts = ts.tz_convert(datetime.now().astimezone().tzinfo).tz_localize(None)
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S") if ts is not None and not pd.isna(ts) else ""
    return f"{stamp} {host} {ident}: {message}".strip()


def _frame(rows: list[dict], source_file: str, method: str) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=COLUMNS)
    frame = pd.DataFrame(rows)
    if "timestamp" in frame and isinstance(frame["timestamp"].dtype, pd.DatetimeTZDtype):
        # Hour-of-day / business-hours features need the machine's local wall-clock time, not UTC.
        frame["timestamp"] = frame["timestamp"].dt.tz_convert(datetime.now().astimezone().tzinfo).dt.tz_localize(None)
    frame["source_file"] = source_file
    frame["ingest_method"] = method
    for column in COLUMNS:
        if column not in frame:
            frame[column] = None
    return frame[COLUMNS]


def _readable(path: str) -> tuple[bool, str]:
    p = Path(path)
    if not p.exists():
        return False, "not present on this system"
    try:
        with p.open("rb") as handle:
            handle.read(1)
        return True, "readable"
    except PermissionError:
        return False, "exists but needs elevated permission (run with sudo or add your user to the 'adm' group)"
    except OSError as exc:
        return False, f"unreadable ({exc.strerror or exc})"


def _tail_lines(path: str, limit: int) -> list[str]:
    from collections import deque

    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for line in deque(handle, maxlen=limit) if line.strip()]


_SYSLOG_STAMP = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")


def _with_year(stamp: str, now: datetime) -> pd.Timestamp:
    """Classic syslog omits the year: assume this year, or last year if that would land in the future."""
    ts = pd.to_datetime(f"{now.year} {' '.join(stamp.split())}", format="%Y %b %d %H:%M:%S", errors="coerce")
    if pd.notna(ts) and ts > pd.Timestamp(now.replace(tzinfo=None)) + pd.Timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def _collect_file(path: str, limit: int) -> pd.DataFrame:
    now = datetime.now()
    rows = []
    for line in _tail_lines(path, limit):
        match = _SYSLOG_STAMP.match(line)
        ts = _with_year(match.group("stamp"), now) if match else pd.NaT
        raw = f"{ts:%Y-%m-%d %H:%M:%S} {match.group('rest')}" if match and pd.notna(ts) else line
        rows.append({"timestamp": ts, "raw_line": raw, "message": match.group("rest") if match else line, "source": Path(path).name})
    return _frame(rows, Path(path).name, "local-file")


def _collect_journal(limit: int, hours: int) -> pd.DataFrame:
    proc = subprocess.run(
        ["journalctl", "-o", "json", "--no-pager", "-n", str(limit), "--since", f"{hours} hours ago"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise PermissionError((proc.stderr or "journalctl returned no data").strip().splitlines()[0])
    rows = []
    for line in proc.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = pd.to_datetime(int(item["__REALTIME_TIMESTAMP"]), unit="us", utc=True, errors="coerce") if item.get("__REALTIME_TIMESTAMP") else pd.NaT
        message = item.get("MESSAGE")
        if isinstance(message, list):  # journald encodes binary messages as byte arrays
            message = bytes(message).decode("utf-8", "replace")
        ident = str(item.get("SYSLOG_IDENTIFIER") or item.get("_COMM") or "journal")
        host = str(item.get("_HOSTNAME") or "localhost")
        try:
            level = _JOURNAL_LEVEL.get(int(item.get("PRIORITY", 6)), "INFO")
        except (TypeError, ValueError):
            level = "INFO"
        rows.append({"timestamp": ts, "level": level, "source": ident, "message": str(message or ""), "host": host,
                     "raw_line": _syslog_line(ts, host, ident, str(message or ""))})
    return _frame(rows, "systemd-journal", "journalctl")


def _collect_mac_unified(limit: int, hours: int) -> pd.DataFrame:
    """Read the macOS unified log. Warning-and-above only: the full stream is enormous and mostly noise."""
    proc = subprocess.Popen(
        ["log", "show", "--last", f"{hours}h", "--style", "ndjson", "--predicate", 'messageType == "Error" OR messageType == "Fault" OR process == "sshd" OR process == "sudo" OR process == "loginwindow" OR process == "authd" OR process == "opendirectoryd"'],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    rows: list[dict] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = pd.to_datetime(item.get("timestamp"), errors="coerce", utc=True)
            ident = Path(str(item.get("processImagePath") or "unknown")).name
            message = str(item.get("eventMessage") or "")
            host = platform.node() or "localhost"
            rows.append({"timestamp": ts, "level": _MAC_LEVEL.get(str(item.get("messageType")), "INFO"), "source": ident,
                         "message": message, "host": host, "raw_line": _syslog_line(ts, host, ident, message)})
            if len(rows) >= limit:
                break
    finally:
        proc.kill()
        proc.wait()
    return _frame(rows, "macos-unified-log", "log-show")


def _collect_windows(channels: list[str], limit: int) -> tuple[pd.DataFrame, list[str]]:
    from src.windows_event_ingest import collect_event_logs

    frame, diagnostics = collect_event_logs(channels, server="localhost", max_per_log=limit)
    if frame.empty:
        return pd.DataFrame(columns=COLUMNS), list(diagnostics)
    out = pd.DataFrame({
        "timestamp": frame.get("timestamp"), "level": frame.get("level"), "source": frame.get("source"),
        "message": frame.get("message", "").astype(str), "host": frame.get("computer"),
    })
    out["raw_line"] = frame["message"].astype(str) if "message" in frame else ""
    out["source_file"] = frame["log_type"] if "log_type" in frame else "WindowsEvent"
    out["ingest_method"] = frame["ingest_method"] if "ingest_method" in frame else "wevtutil"
    if "event_id" in frame:
        out["event_id"] = frame["event_id"]
    return out, list(diagnostics)


def available_sources() -> list[dict]:
    """What can be collected on THIS machine, with the reason when something cannot."""
    system = platform.system()
    sources: list[dict] = []
    if system == "Windows":
        sources.append({"id": "windows-events", "label": "Windows Event Log", "ok": shutil.which("wevtutil") is not None,
                        "reason": "wevtutil found" if shutil.which("wevtutil") else "wevtutil not found on PATH"})
    elif system == "Linux":
        has_journal = shutil.which("journalctl") is not None
        sources.append({"id": "journal", "label": "systemd journal", "ok": has_journal,
                        "reason": "journalctl found" if has_journal else "journalctl not installed (non-systemd system)"})
        for path in LINUX_FILES:
            ok, reason = _readable(path)
            sources.append({"id": f"file:{path}", "label": path, "ok": ok, "reason": reason})
    elif system == "Darwin":
        has_log = shutil.which("log") is not None
        sources.append({"id": "mac-unified", "label": "macOS unified log", "ok": has_log,
                        "reason": "log command found" if has_log else "the 'log' command is missing"})
        for path in MAC_FILES:
            ok, reason = _readable(path)
            sources.append({"id": f"file:{path}", "label": path, "ok": ok, "reason": reason})
    return sources


def collect(source_ids: list[str], max_events: int = 2000, hours: int = 24, windows_channels: list[str] | None = None,
            progress: Callable[[str], None] | None = None) -> tuple[pd.DataFrame, list[str]]:
    """Collect from the chosen sources. Returns (frame, one diagnostic line per source)."""
    frames: list[pd.DataFrame] = []
    notes: list[str] = []
    for source_id in source_ids:
        if progress:
            progress(source_id)
        try:
            if source_id == "windows-events":
                frame, diag = _collect_windows(windows_channels or ["System", "Application"], max_events)
                notes.extend(diag)
            elif source_id == "journal":
                frame = _collect_journal(max_events, hours)
            elif source_id == "mac-unified":
                frame = _collect_mac_unified(max_events, hours)
            elif source_id.startswith("file:"):
                frame = _collect_file(source_id[5:], max_events)
            else:
                notes.append(f"{source_id}: unknown source")
                continue
        except subprocess.TimeoutExpired:
            notes.append(f"{source_id}: timed out; reduce the time window or maximum events")
            continue
        except (PermissionError, OSError, ValueError) as exc:
            notes.append(f"{source_id}: {exc}")
            continue
        notes.append(f"{source_id}: {len(frame):,} records")
        if not frame.empty:
            frames.append(frame)
    if not frames:
        return pd.DataFrame(columns=COLUMNS), notes
    return pd.concat(frames, ignore_index=True), notes


def collected_at() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

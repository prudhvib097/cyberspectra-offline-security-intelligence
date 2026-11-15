from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, Tuple

import pandas as pd

WINDOWS_AVAILABLE = sys.platform.startswith("win")
ADMIN_CSV_PATH = Path(__file__).parent.parent / "data" / "logs" / "windows_events_admin.csv"


def _import_pywin32():
    try:
        import win32evtlog  # type: ignore

        return win32evtlog
    except Exception:
        return None


_XMLNS = re.compile(r'\sxmlns(?::\w+)?=("[^"]*"|\'[^\']*\')')
_EVENT_LEVELS = {1: "CRITICAL", 2: "ERROR", 3: "WARNING", 4: "INFO", 5: "DEBUG"}


def _parse_wevtutil_xml(xml_blob: str) -> List[dict]:
    """Parse `wevtutil qe /f:xml` output. Real events declare a default XML namespace, which is stripped first
    (otherwise ElementTree would never match the <Event> elements)."""
    records: List[dict] = []
    try:
        root = ET.fromstring(f"<Events>{_XMLNS.sub('', xml_blob)}</Events>")
    except ET.ParseError:
        return records

    for ev in root.findall("./Event"):
        system = ev.find("System")
        event_id = None
        time_generated = None
        provider = None
        level = None
        computer = None
        if system is not None:
            ev_id_el = system.find("EventID")
            if ev_id_el is not None:
                try:
                    event_id = int(ev_id_el.text or 0)
                except Exception:
                    event_id = None
            tc = system.find("TimeCreated")
            if tc is not None:
                time_generated = tc.attrib.get("SystemTime")
            prov = system.find("Provider")
            if prov is not None:
                provider = prov.attrib.get("Name")
            level_el = system.find("Level")
            if level_el is not None and (level_el.text or "").strip().isdigit():
                level = _EVENT_LEVELS.get(int(level_el.text))
            comp_el = system.find("Computer")
            if comp_el is not None:
                computer = comp_el.text

        # EventData may contain multiple Data elements
        msg_parts: List[str] = []
        ed = ev.find("EventData")
        if ed is not None:
            for data in ed.findall("Data"):
                if data.text:
                    msg_parts.append(data.text)

        records.append({
            "timestamp": pd.to_datetime(time_generated, errors="coerce") if time_generated else pd.NaT,
            "event_id": event_id,
            "level": level,
            "source": provider,
            "message": " | ".join(msg_parts) if msg_parts else "",
            "computer": computer,
        })
    return records


def stream_wevtutil(channel: str, max_records: int = 500, hours: int | None = None, on_progress=None,
                    step: int = 250, timeout: float = 180.0) -> pd.DataFrame:
    """Read a channel with `wevtutil qe`, newest first, counting real events as they stream in.

    `channel` must already be validated by the caller (it is passed as a single argv item, never through a shell).
    Raises PermissionError (access denied), LookupError (unknown channel) or TimeoutError.
    """
    import threading

    cmd = ["wevtutil", "qe", channel, "/f:xml", f"/c:{int(max_records)}", "/rd:true"]
    if hours:
        cmd.append(f"/q:*[System[TimeCreated[timediff(@SystemTime) <= {int(hours) * 3600 * 1000}]]]")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    timed_out = threading.Event()

    def _kill() -> None:
        timed_out.set()
        proc.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    records: List[dict] = []
    buffer: List[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            buffer.append(line)
            if "</Event>" in line:
                records.extend(_parse_wevtutil_xml("".join(buffer)))
                buffer = []
                if on_progress and len(records) % step == 0:
                    on_progress(len(records))
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
    stderr = (proc.stderr.read() if proc.stderr else "") or ""
    if timed_out.is_set():
        raise TimeoutError(f"{channel}: wevtutil did not finish within {int(timeout)} seconds")
    if proc.returncode not in (0, None):
        lowered = stderr.lower()
        if proc.returncode == 5 or "access is denied" in lowered:
            raise PermissionError(f"{channel}: access denied (this channel needs an elevated session)")
        if proc.returncode == 15007 or "could not be found" in lowered or "channel" in lowered and "not" in lowered:
            raise LookupError(f"{channel}: channel not found")
        raise RuntimeError(f"{channel}: wevtutil exited with code {proc.returncode}")
    if on_progress:
        on_progress(len(records))
    frame = pd.DataFrame.from_records(records) if records else pd.DataFrame(columns=["timestamp", "event_id", "level", "source", "message", "computer"])
    frame["ingest_method"] = "wevtutil"
    return frame


def _read_with_wevtutil(log_type: str, max_records: int = 500) -> pd.DataFrame:
    """Fallback reader using `wevtutil qe` to query Windows Event logs and parse XML output."""
    cmd = [
        "wevtutil",
        "qe",
        log_type,
        "/f:xml",
        f"/c:{max_records}",
    ]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return pd.DataFrame()

    records = _parse_wevtutil_xml(output)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame.from_records(records)
    df["ingest_method"] = "wevtutil"
    return df


def _read_with_pywin32(log_type: str, server: str = "localhost", max_records: int = 500) -> pd.DataFrame:
    win32evtlog = _import_pywin32()
    if win32evtlog is None:
        return pd.DataFrame()

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception:
        return pd.DataFrame()

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    records: List[dict] = []
    read = 0
    while read < max_records:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break
        for ev in events:
            try:
                event_id = int(ev.EventID & 0xFFFF)
            except Exception:
                event_id = int(getattr(ev, "EventID", 0))

            try:
                time_generated = pd.to_datetime(str(ev.TimeGenerated))
            except Exception:
                time_generated = pd.NaT

            try:
                message = " | ".join(ev.StringInserts) if getattr(ev, "StringInserts", None) else ""
            except Exception:
                message = ""

            record = {
                "timestamp": time_generated,
                "event_id": event_id,
                "level": getattr(ev, "EventType", None),
                "source": getattr(ev, "SourceName", None),
                "message": message,
                "computer": getattr(ev, "ComputerName", None),
            }
            records.append(record)
            read += 1
            if read >= max_records:
                break

    try:
        win32evtlog.CloseEventLog(handle)
    except Exception:
        pass

    if not records:
        return pd.DataFrame()
    df = pd.DataFrame.from_records(records)
    df["ingest_method"] = "pywin32"
    return df


def collect_event_logs(log_types: Iterable[str], server: str = "localhost", max_per_log: int = 500) -> Tuple[pd.DataFrame, List[str]]:
    """Attempt to collect logs for the provided `log_types`.

    Returns a tuple of (DataFrame, diagnostics list). The DataFrame may be empty; the
    diagnostics list will contain messages about attempts and failures.
    
    Priority:
    1. Try reading from admin-exported CSV (if it exists)
    2. Try pywin32
    3. Fall back to wevtutil
    """
    diagnostics: List[str] = []
    
    # First, try reading from the admin-exported CSV if it exists
    if ADMIN_CSV_PATH.exists():
        try:
            df = pd.read_csv(ADMIN_CSV_PATH)
            if not df.empty:
                # Filter by requested log_types if "log_type" column exists
                if "log_type" in df.columns:
                    log_types_list = list(log_types)
                    if log_types_list:
                        df = df[df["log_type"].isin(log_types_list)]
                if not df.empty:
                    diagnostics.append(f"Read {len(df)} events from admin-exported CSV file")
                    return df, diagnostics
        except Exception as exc:
            diagnostics.append(f"Could not read admin CSV: {exc}")
    
    # Fallback: try direct collection (likely to fail without Admin)
    frames: List[pd.DataFrame] = []
    for lt in log_types:
        # try pywin32 first
        df = _read_with_pywin32(lt, server=server, max_records=max_per_log)
        if not df.empty:
            df["log_type"] = lt
            frames.append(df)
            diagnostics.append(f"{lt}: read {len(df)} records via pywin32")
            continue

        # fallback to wevtutil
        df2 = _read_with_wevtutil(lt, max_records=max_per_log)
        if not df2.empty:
            df2["log_type"] = lt
            frames.append(df2)
            diagnostics.append(f"{lt}: read {len(df2)} records via wevtutil")
            continue

        diagnostics.append(f"{lt}: no records (try running as Administrator)")

    if not frames:
        msg = (
            "No events collected. To read Windows Event Logs, you need Administrator privileges. "
            "Use the PowerShell script 'collect_windows_logs.ps1' (run as Administrator) to export logs."
        )
        diagnostics.append(msg)
        return pd.DataFrame(columns=["timestamp", "event_id", "level", "source", "message", "computer", "log_type", "ingest_method"]), diagnostics

    combined = pd.concat(frames, ignore_index=True, sort=False)
    return combined, diagnostics


def list_available_logs() -> List[str]:
    """Return a list of available event channels via `wevtutil el` as a best-effort."""
    try:
        output = subprocess.check_output(["wevtutil", "el"], stderr=subprocess.DEVNULL, text=True)
        return [line.strip() for line in output.splitlines() if line.strip()]
    except Exception:
        return []


def run_powershell_collection_script(
    show_window: bool = True,
    log_types: Iterable[str] | None = None,
    max_records: int = 500,
) -> Tuple[bool, str]:
    """
    Launch the Windows Event Log collection PowerShell script.
    When running on Windows, a visible PowerShell console is opened so the user can
    watch the collection steps and then see it close when the script completes.
    Returns (success: bool, message: str)
    """
    script_path = Path(__file__).parent.parent / "collect_windows_logs.ps1"

    if not script_path.exists():
        return False, f"PowerShell script not found at: {script_path}"

    channels = list(log_types or [])
    channel_args = ""
    if channels:
        escaped_channels = "|".join(channel.replace('"', '""') for channel in channels)
        channel_args = f' -SelectedChannels "{escaped_channels}"'
    max_arg = f" -MaxEventsPerLog {int(max_records)}"
    try:
        if show_window and WINDOWS_AVAILABLE:
            launch_cmd = (
                f'start "Windows Event Log Collector" powershell.exe -NoExit -NoProfile '
                f'-ExecutionPolicy Bypass -File "{script_path}"{max_arg}{channel_args}'
            )
            subprocess.Popen(
                launch_cmd,
                cwd=str(script_path.parent),
                shell=True,
            )
            return True, "PowerShell window launched and will stay open after collection finishes."

        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=300)
        if "Successfully exported" in output:
            return True, output.strip()
        return False, f"Script ran but may not have succeeded:\n{output}"
    except subprocess.CalledProcessError as e:
        return False, f"PowerShell execution failed (may need Administrator): {e.output}"
    except subprocess.TimeoutExpired:
        return False, "PowerShell script timed out (>300 seconds)"
    except Exception as e:
        return False, f"Error running PowerShell script: {e}"

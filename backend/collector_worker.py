"""Collection worker: runs in its own process (and, on Windows, its own console window).

    python -m backend.collector_worker <job_dir>

Reads <job_dir>/request.json (validated by backend.collection_job), collects from each source with the same
functions the rest of the app uses, and reports through TWO channels:
  * a human-readable console (the Windows terminal) fed by Python logging, and
  * <job_dir>/status.jsonl, one JSON object per line. The dashboard reads ONLY this file for status, never console text.
Collected events go to <job_dir>/result.csv *before* the final "finished" event is written. Console output carries
counts and statuses only, never event contents.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from backend import system_logs, windows_events  # noqa: E402

BAR = "=" * 60


class JsonlHandler(logging.Handler):
    """Appends every log record as a structured JSON line (timestamp, level, source, message, progress fields)."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path

    def emit(self, record: logging.LogRecord) -> None:
        payload = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "level": record.levelname,
            "source": getattr(record, "source", ""),
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
        }
        for key in ("count", "total", "ok", "empty", "failed", "status", "duration", "sources", "total_events"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")


class ConsoleHandler(logging.StreamHandler):
    TAGS = {"INFO": "[INFO]", "WARNING": "[WARN]", "ERROR": "[ERROR]"}

    def format(self, record: logging.LogRecord) -> str:
        tag = getattr(record, "tag", None) or self.TAGS.get(record.levelname, "[INFO]")
        return f"{tag} {record.getMessage()}"


def _hold_window(seconds: int = 20) -> None:
    """Keep the console readable after finishing (Windows only, only when interactive)."""
    if os.name != "nt" or not sys.stdin or not sys.stdout.isatty():
        return
    import msvcrt

    print(f"\nThis window closes in {seconds} s. Press any key to close it now.")
    end = time.time() + seconds
    while time.time() < end:
        if msvcrt.kbhit():
            msvcrt.getch()
            return
        time.sleep(0.2)


def run(job_dir: Path) -> int:
    request = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    log = logging.getLogger("cyberspectra.collector")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    log.addHandler(JsonlHandler(job_dir / "status.jsonl"))
    console = ConsoleHandler(sys.stdout)
    log.addHandler(console)

    sources: list[str] = request["sources"]
    channels: list[str] = request.get("channels") or []
    limit, hours = int(request["max_events"]), int(request["hours"])
    started = time.time()

    print(f"{BAR}\n CYBERSPECTRA - {system_logs.os_name().upper()} LOG COLLECTOR\n Offline Security Intelligence\n{BAR}\n", flush=True)
    log.info("Initializing collector...", extra={"event": "started"})
    log.info(f"Operating system: {system_logs.os_name()} ({platform.release()})", extra={"event": "log"})
    labels = {o["id"]: o["label"] for o in system_logs.available_sources()}
    log.info("Collection configuration:", extra={"event": "config", "sources": sources})
    print(f"       Sources: {', '.join(labels.get(s, s) for s in sources)}", flush=True)
    if channels:
        print(f"       Channels: {', '.join(channels)}", flush=True)
    print(f"       Maximum events per source: {limit}\n       Look-back period: {hours} hours\n", flush=True)

    if os.name == "nt":
        log.info("Checking the Windows Event Log service...", extra={"event": "log"})
        log.info(f"Event Log service: {windows_events.event_log_service_state()}", extra={"event": "log"})
        elevated = windows_events.is_elevated()
        log.info("Current process permissions: " + ("elevated (administrator)" if elevated else "standard user (Security channel will be denied)"), extra={"event": "log"})

    frames: list[pd.DataFrame] = []
    outcomes: dict[str, dict] = {}  # name -> {status, count, message}

    units: list[tuple[str, str, str | None]] = []  # (display name, source id, windows channel)
    for source_id in sources:
        if source_id == "windows-events":
            for channel in channels or ["System", "Application"]:
                units.append((channel, source_id, channel))
        else:
            units.append((labels.get(source_id, source_id), source_id, None))

    for name, source_id, channel in units:
        log.info(f"Reading {name}...", extra={"event": "source_started", "source": name, "tag": "[RUNNING]"})

        def on_progress(count: int, name: str = name) -> None:
            log.info(f"Retrieved {count} events", extra={"event": "progress", "source": name, "count": count, "tag": "[PROGRESS]"})

        status, message, frame = "ERROR", "", pd.DataFrame()
        try:
            if channel is not None:
                result = windows_events.read_channel(channel, limit, hours, on_progress)
                status, message, frame = result.status, result.message, system_logs.windows_result_frame(result)
                if result.duplicates:
                    message += f" ({result.duplicates} duplicate records removed)"
            else:
                frame, notes = system_logs.collect([source_id], limit, hours, None, None, lambda _s, n: on_progress(n))
                bad = [n.split(":", 1)[1].strip() for n in notes if ":" in n and "records" not in n]
                if frame.empty and bad:
                    status, message = ("ACCESS_DENIED" if "permission" in bad[0].lower() or "elevated" in bad[0].lower() else "ERROR"), bad[0]
                else:
                    status, message = ("SUCCESS" if len(frame) else "EMPTY"), f"Retrieved {len(frame)} events." if len(frame) else "No events matched."
        except PermissionError as exc:
            status, message = "ACCESS_DENIED", str(exc)
        except Exception as exc:  # noqa: BLE001 - a worker must always report, never die silently
            status, message = "ERROR", f"{type(exc).__name__}: {exc}"
        count = len(frame)
        outcomes[name] = {"status": status, "count": count, "message": message}
        if count:
            frames.append(frame)
        tag = {"SUCCESS": "[SUCCESS]", "EMPTY": "[INFO]", "DISABLED": "[WARN]"}.get(status, "[ERROR]")
        line = f"{name}: {status} - {message}" if status != "SUCCESS" else f"Retrieved {count} {name} events."
        (log.error if tag == "[ERROR]" else log.info)(line, extra={"event": "source_finished", "source": name, "count": count, "status": status, "ok": status in ("SUCCESS", "EMPTY"), "tag": tag})

    log.info("Normalizing and saving collected events...", extra={"event": "log"})
    total = int(sum(o["count"] for o in outcomes.values()))
    duration = round(time.time() - started, 1)
    if frames:
        pd.concat(frames, ignore_index=True).to_csv(job_dir / "result.csv", index=False)
    failed_n = sum(o["status"] in ("ACCESS_DENIED", "CHANNEL_NOT_FOUND", "ERROR") for o in outcomes.values())
    ok_n = sum(o["status"] == "SUCCESS" for o in outcomes.values())
    empty_n = sum(o["status"] in ("EMPTY", "DISABLED") for o in outcomes.values())
    status = ("partial" if total else "failed") if failed_n else ("success" if total else "empty")

    print(f"\n{BAR}\n COLLECTION SUMMARY\n{BAR}\n", flush=True)
    for name, o in outcomes.items():
        print(f"{name}: {o['count']} events [{o['status']}]" + (f" - {o['message']}" if o["status"] not in ("SUCCESS",) else ""), flush=True)
    print(f"\nTotal events collected: {total}\nSources with events: {ok_n}   Empty: {empty_n}   Failed: {failed_n}\n"
          f"Collection status: {status.upper()}\nDuration: {duration}s\n", flush=True)

    if status in ("success", "partial"):
        log.info("Collected events saved. Handing over to the CyberSpectra analysis pipeline.", extra={"event": "log"})
    elif status == "empty":
        log.warning("No matching events were found for the selected sources and look-back period.", extra={"event": "log"})
    log.info(f"Collection {status}.", extra={"event": "finished", "status": status, "total_events": total, "ok": ok_n, "empty": empty_n, "failed": failed_n,
                                             "duration": duration, "sources": outcomes, "tag": "[SUCCESS]" if status == "success" else "[WARN]" if status != "failed" else "[ERROR]"})
    print(BAR, flush=True)
    if request.get("hold"):
        _hold_window()
    return 0 if status in ("success", "partial", "empty") else 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m backend.collector_worker <job_dir>", file=sys.stderr)
        return 2
    job_dir = Path(argv[1])
    try:
        return run(job_dir)
    except Exception as exc:  # noqa: BLE001
        with (job_dir / "status.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), "level": "ERROR", "event": "finished", "status": "failed",
                                     "message": f"worker crashed: {type(exc).__name__}: {exc}", "total_events": 0}) + "\n")
        print(f"[ERROR] worker crashed: {type(exc).__name__}: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

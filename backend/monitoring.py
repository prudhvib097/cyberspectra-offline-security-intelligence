from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from pathlib import Path
from typing import Any, Callable

import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from backend.checkpoint import CheckpointStore
from src.ingestion import SUPPORTED_EXTENSIONS, _build_text_frame

@dataclass
class MonitorState:
    watched_paths: list[str]
    polling_interval_seconds: int = 10
    enabled: bool = False


class OfflineMonitor:
    def __init__(self, state: MonitorState | None = None) -> None:
        self.state = state or MonitorState(watched_paths=[])

    def add_path(self, path: str) -> None:
        if path not in self.state.watched_paths:
            self.state.watched_paths.append(path)

    def enable(self) -> None:
        self.state.enabled = True

    def disable(self) -> None:
        self.state.enabled = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.state.enabled,
            "watched_paths": self.state.watched_paths,
            "polling_interval_seconds": self.state.polling_interval_seconds,
        }


class _FileEventHandler(FileSystemEventHandler):
    def __init__(self, monitor: "ContinuousOfflineMonitor") -> None:
        super().__init__()
        self.monitor = monitor

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.monitor.process_file(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self.monitor.process_file(event.src_path)


class ContinuousOfflineMonitor:
    """Watch configured local files/directories and process appended records."""

    def __init__(
        self,
        watched_paths: list[str],
        on_batch: Callable[[pd.DataFrame, str], Any] | None = None,
        checkpoint_store: CheckpointStore | None = None,
        recursive: bool = True,
    ) -> None:
        self.watched_paths = [str(Path(path).resolve()) for path in watched_paths]
        self.on_batch = on_batch or self._default_pipeline
        self.checkpoints = checkpoint_store or CheckpointStore()
        self.recursive = recursive
        self.observer: Observer | None = None
        self._lock = threading.Lock()
        self._watched_files: set[str] = set()
        # Real activity counters, surfaced by the dashboard instead of any
        # claim of "live" monitoring.
        self.batches_processed = 0
        self.records_processed = 0
        self.last_batch_at: str | None = None
        self.last_error: str | None = None

    @staticmethod
    def _default_pipeline(frame: pd.DataFrame, source_path: str) -> Any:
        from backend.pipeline import run_pipeline

        return run_pipeline(frame, persist=True)

    def _is_supported(self, path: str) -> bool:
        return Path(path).suffix.lower() in SUPPORTED_EXTENSIONS

    def _files_for_path(self, path: str) -> list[str]:
        candidate = Path(path)
        if candidate.is_file():
            return [str(candidate)] if self._is_supported(str(candidate)) else []
        if not candidate.is_dir():
            return []
        iterator = candidate.rglob("*") if self.recursive else candidate.glob("*")
        return [str(item) for item in iterator if item.is_file() and self._is_supported(str(item))]

    def process_file(self, path: str) -> None:
        path_obj = Path(path).resolve()
        if not path_obj.is_file() or not self._is_supported(str(path_obj)):
            return
        with self._lock:
            try:
                stat = path_obj.stat()
                checkpoint = self.checkpoints.get(str(path_obj))
                if checkpoint.inode and checkpoint.inode != int(getattr(stat, "st_ino", 0)):
                    checkpoint.offset = 0
                    checkpoint.line_number = 0
                if stat.st_size < checkpoint.offset:
                    checkpoint.offset = 0
                    checkpoint.line_number = 0
                with path_obj.open("rb") as handle:
                    handle.seek(checkpoint.offset)
                    payload = handle.read()
                if not payload:
                    return
                complete_length = len(payload)
                if not payload.endswith(b"\n"):
                    complete_length = payload.rfind(b"\n") + 1
                if complete_length <= 0:
                    return
                complete_payload = payload[:complete_length]
                lines = complete_payload.decode("utf-8", errors="replace").splitlines()
                frame = _build_text_frame(lines, path_obj.name, str(path_obj))
                if frame.empty:
                    self.checkpoints.update_from_stat(str(path_obj), checkpoint.offset + complete_length, checkpoint.line_number)
                    return
                frame["line_number"] = range(checkpoint.line_number + 1, checkpoint.line_number + len(frame) + 1)
                self.on_batch(frame, str(path_obj))
                self.checkpoints.update_from_stat(
                    str(path_obj), checkpoint.offset + complete_length, checkpoint.line_number + len(frame)
                )
                self.batches_processed += 1
                self.records_processed += len(frame)
                self.last_batch_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - a bad batch must never kill the watcher thread
                # The checkpoint is not advanced, so the same bytes are retried
                # on the next file event; the failure stays visible to the UI.
                self.last_error = f"{type(exc).__name__}: {exc}"
                return

    def start(self) -> None:
        if self.observer is not None:
            return
        observer = Observer()
        scheduled: set[str] = set()
        for configured_path in self.watched_paths:
            for file_path in self._files_for_path(configured_path):
                self._watched_files.add(file_path)
                self.process_file(file_path)
            directory = str(Path(configured_path).parent if Path(configured_path).is_file() else Path(configured_path))
            if directory not in scheduled and Path(directory).is_dir():
                observer.schedule(_FileEventHandler(self), directory, recursive=self.recursive)
                scheduled.add(directory)
        observer.daemon = True
        observer.start()
        self.observer = observer

    def stop(self) -> None:
        observer = self.observer
        if observer is None:
            return
        observer.stop()
        observer.join(timeout=3.0)
        self.observer = None

    @property
    def enabled(self) -> bool:
        return self.observer is not None

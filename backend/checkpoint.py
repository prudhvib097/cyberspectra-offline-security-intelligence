from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.database import SQLiteStore


@dataclass
class FileCheckpoint:
    path: str
    offset: int = 0
    line_number: int = 0
    inode: int = 0


class CheckpointStore:
    """Persist file offsets in SQLite so monitoring survives reruns."""

    def __init__(self, store: SQLiteStore | None = None) -> None:
        self.store = store or SQLiteStore()
        self.store.initialize()

    @staticmethod
    def _key(path: str) -> str:
        normalized = str(Path(path).resolve())
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
        return f"checkpoint:{digest}"

    def get(self, path: str) -> FileCheckpoint:
        value = self.store.get_setting(self._key(path))
        if not value:
            return FileCheckpoint(path=str(Path(path).resolve()))
        try:
            data: dict[str, Any] = json.loads(value)
            return FileCheckpoint(
                path=str(data.get("path", path)),
                offset=max(0, int(data.get("offset", 0))),
                line_number=max(0, int(data.get("line_number", 0))),
                inode=max(0, int(data.get("inode", 0))),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return FileCheckpoint(path=str(Path(path).resolve()))

    def save(self, checkpoint: FileCheckpoint) -> None:
        self.store.set_setting(
            self._key(checkpoint.path),
            json.dumps(
                {
                    "path": str(Path(checkpoint.path).resolve()),
                    "offset": int(checkpoint.offset),
                    "line_number": int(checkpoint.line_number),
                    "inode": int(checkpoint.inode),
                }
            ),
        )

    def update_from_stat(self, path: str, offset: int, line_number: int) -> FileCheckpoint:
        stat = os.stat(path)
        checkpoint = FileCheckpoint(
            path=str(Path(path).resolve()),
            offset=max(0, int(offset)),
            line_number=max(0, int(line_number)),
            inode=int(getattr(stat, "st_ino", 0)),
        )
        self.save(checkpoint)
        return checkpoint

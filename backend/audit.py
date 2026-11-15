from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, log_path: str | None = None) -> None:
        self.log_path = Path(log_path or os.environ.get("CYBERSPECTRA_AUDIT_LOG") or os.path.join(os.getcwd(), "logs", "audit.log"))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, details: dict[str, Any] | None = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action,
            "details": details or {},
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

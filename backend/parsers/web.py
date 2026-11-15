"""Apache / Nginx access-log parser (combined/common format).

Example:
    203.0.113.9 - - [01/May/2026:10:00:07 +0000] "GET /login HTTP/1.1" 200 1234 "https://x/" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd

PARSER_ID = "web"

_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
_ATTACK_HINTS = ["select", "from ", "union", "script", "<script", "..", "passwd", "etc/passwd", "admin", "login"]


def detect(text: str) -> bool:
    return bool(text.startswith(('"',)) or _PATTERN.match(text))


def parse(text: str) -> dict[str, Any]:
    match = _PATTERN.match(text.strip())
    if not match:
        return {"message": text.strip(), "event_type": "web", "level": "INFO", "timestamp": pd.NaT}

    timestamp = pd.to_datetime(match.group("timestamp"), format="mixed", errors="coerce")
    if timestamp is None or pd.isna(timestamp):
        timestamp = pd.to_datetime(match.group("timestamp").split(" ")[0], errors="coerce")
    status = int(match.group("status"))
    path = match.group("path")
    method = match.group("method")
    lowered = path.lower()
    event_type = "web"
    if any(hint in lowered for hint in _ATTACK_HINTS) or status in (401, 403, 500, 502, 503):
        event_type = "auth_failure" if status in (401, 403) else "error"
    return {
        "timestamp": timestamp,
        "source_ip": match.group("ip"),
        "message": f"{method} {path} {status}",
        "event_type": event_type,
        "level": "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO",
        "http_status": status,
        "request_method": method,
        "request_path": path,
        "request_size": match.group("size"),
    }


def parse_frame(lines: pd.Series, source_name: str) -> pd.DataFrame:
    """Parse a homogeneous access-log column with vectorized string extraction."""
    extracted = lines.astype(str).str.extract(_PATTERN, expand=True)
    status = pd.to_numeric(extracted["status"], errors="coerce")
    timestamp = pd.to_datetime(extracted["timestamp"], format="mixed", errors="coerce")
    path = extracted["path"].fillna("")
    attack = path.str.lower().str.contains("|".join(re.escape(hint) for hint in _ATTACK_HINTS), regex=True, na=False)
    error = status.isin([401, 403, 500, 502, 503])
    event_type = pd.Series("web", index=lines.index)
    event_type.loc[attack | error] = "error"
    event_type.loc[status.isin([401, 403])] = "auth_failure"
    return pd.DataFrame(
        {
            "timestamp": timestamp,
            "source_ip": extracted["ip"].fillna(""),
            "message": (
                extracted["method"].fillna("")
                + " "
                + path
                + " "
                + extracted["status"].fillna("")
            ).str.strip(),
            "event_type": event_type,
            "level": np.select(
                [status >= 500, status >= 400],
                ["ERROR", "WARNING"],
                default="INFO",
            ),
            "http_status": status,
            "request_method": extracted["method"].fillna(""),
            "request_path": path,
            "request_size": extracted["size"].fillna(""),
            "source": source_name,
            "parser": PARSER_ID,
            "parse_status": "ok",
        },
        index=lines.index,
    )
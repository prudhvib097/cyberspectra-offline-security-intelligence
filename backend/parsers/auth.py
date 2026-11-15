"""SSH / authentication log parser (syslog-style auth lines).

Examples:
    2026-05-01 10:00:07 host sshd[12345]: Failed password for root from 10.0.1.44 port 58422 ssh2
    May 01 10:01:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=analyst user=root
    Accepted publickey for analyst from 10.0.1.10 port 58430 ssh2
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "auth"

_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<host>\S+))?"
    r"(?:\s+(?P<program>[^:\[\s]+)(?:\[\d+\])?):?\s*(?P<message>.*)$"
)
_FAILED = re.compile(r"\bfailed\b|\bpam_unix.*authentication failure|invalid user|refused|denied", re.IGNORECASE)
_ACCEPTED = re.compile(r"\baccepted\b|\bsession opened\b|\bnew session\b", re.IGNORECASE)
_USER_RE = re.compile(r"(?:for\s+(?:invalid\s+)?(?:user\s+)?|user=)(\S+?)(?:\s+from|\b|$)", re.IGNORECASE)
_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_PORT_RE = re.compile(r"port\s+(\d+)")
_EVENT_TYPE_HINTS = [
    ("failed password", "auth_failure"),
    ("authentication failure", "auth_failure"),
    ("invalid user", "auth_failure"),
    ("login failed", "auth_failure"),
    ("accepted", "auth_success"),
    ("session opened", "auth_success"),
    ("session closed", "auth_success"),
    ("sudo", "privilege"),
    ("useradd", "account"),
    ("userdel", "account"),
    ("passwd", "account"),
    ("groupadd", "account"),
]


def detect(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(
        token in lowered
        for token in [
            "failed password",
            "authentication failure",
            "invalid user",
            "accepted publickey",
            "accepted password",
            "session opened",
            "session closed",
            "new session",
            "pam_unix",
            "sudo:",
            "su:",
            "useradd",
            "passwd",
        ]
    ) or bool(_FAILED.search(text) and (" sshd" in lowered or "sshd[" in lowered))


def parse(text: str) -> dict[str, Any]:
    match = _PATTERN.match(text.strip())
    timestamp = None
    host = ""
    program = ""
    message = text.strip()
    if match:
        timestamp = pd.to_datetime(match.group("timestamp"), errors="coerce")
        host = match.group("host") or ""
        program = match.group("program") or ""
        message = match.group("message").strip() or text.strip()

    username = ""
    user_match = _USER_RE.search(text)
    if user_match:
        candidate = user_match.group(1).rstrip(";")
        if "=" not in candidate:
            username = candidate

    ip_matches = _IP_RE.search(text)
    source_ip = ip_matches.group(0) if ip_matches else ""
    port_match = _PORT_RE.search(text)
    port = int(port_match.group(1)) if port_match else None

    lowered = message.lower()
    event_type = "auth"
    for hint, event_kind in _EVENT_TYPE_HINTS:
        if hint in lowered:
            event_type = event_kind
            break
    if event_type == "auth" and _FAILED.search(message):
        event_type = "auth_failure"

    return {
        "timestamp": timestamp,
        "source_host": host,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "level": "ERROR" if event_type == "auth_failure" else "INFO",
        "message": message,
        "port": port,
    }


def enrich_username(message: str) -> str:
    """Extract a username from an already-parsed auth message."""
    user_match = _USER_RE.search(message)
    if user_match:
        candidate = user_match.group(1).rstrip(";")
        if "=" not in candidate:
            return candidate
    return ""
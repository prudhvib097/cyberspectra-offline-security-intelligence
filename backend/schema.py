"""Common event schema for the offline monitoring platform.

Every ingestion path (file, directory, upload, Windows Event Logs, watcher)
normalizes into this schema before feature extraction. ``raw_log`` is ALWAYS
preserved so nothing is lost downstream.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

EVENT_SCHEMA_COLUMNS = [
    "event_id",
    "timestamp",
    "source",
    "source_file",
    "source_host",
    "source_ip",
    "destination_ip",
    "username",
    "event_type",
    "action",
    "status",
    "protocol",
    "port",
    "http_method",
    "status_code",
    "severity",
    "level",
    "message",
    "raw_log",
    "parse_status",
    "parser",
]

SOURCE_KIND_LINUX = "linux"
SOURCE_KIND_WINDOWS = "windows"
SOURCE_KIND_WEB = "web"
SOURCE_KIND_CLOUD = "cloud"
SOURCE_KIND_FIREWALL = "firewall"
SOURCE_KIND_NETWORK = "network"
SOURCE_KIND_APP = "app"
SOURCE_KIND_JSONL = "jsonl"
SOURCE_KIND_GENERIC = "generic"

SOURCE_KINDS = [
    SOURCE_KIND_LINUX,
    SOURCE_KIND_WINDOWS,
    SOURCE_KIND_WEB,
    SOURCE_KIND_CLOUD,
    SOURCE_KIND_FIREWALL,
    SOURCE_KIND_NETWORK,
    SOURCE_KIND_APP,
    SOURCE_KIND_JSONL,
    SOURCE_KIND_GENERIC,
]

# Event-type families used by the parsers and rules.
EVENT_TYPE_AUTH_FAILURE = "auth_failure"
EVENT_TYPE_AUTH_SUCCESS = "auth_success"
EVENT_TYPE_AUTH = "auth"
EVENT_TYPE_SYSTEM = "system"
EVENT_TYPE_PROCESS = "process"
EVENT_TYPE_ACCOUNT = "account"
EVENT_TYPE_PRIVILEGE = "privilege"
EVENT_TYPE_WEB = "web"
EVENT_TYPE_FIREWALL = "firewall"
EVENT_TYPE_NETWORK = "network"
EVENT_TYPE_ERROR = "error"
EVENT_TYPE_AUDIT = "audit"
EVENT_TYPE_GENERIC = "generic"
EVENT_TYPE_UNPARSED = "unparsed"

_ALIASES = {
    "time": "timestamp",
    "date": "timestamp",
    "datetime": "timestamp",
    "log_time": "timestamp",
    "timestamp_utc": "timestamp",
    "msg": "message",
    "message_text": "message",
    "log_message": "message",
    "details": "message",
    "event": "message",
    "text": "message",
    "file": "source_file",
    "filename": "source_file",
    "log": "source_file",
    "host": "source_host",
    "hostname": "source_host",
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "destination": "destination_ip",
    "dst_ip": "destination_ip",
    "dstip": "destination_ip",
    "ip": "source_ip",
    "ip_address": "source_ip",
    "dst_ip": "destination_ip",
    "user": "username",
    "user_name": "username",
    "account": "username",
    "event_name": "event_type",
    "eventtime": "timestamp",
    "eventsource": "source",
    "eventname": "event_type",
    "sourceipaddress": "source_ip",
    "computer": "source_host",
    "log_type": "source",
    "source_name": "source",
    "provider": "source",
    "log_type": "source",
    "raw": "raw_log",
    "full_message": "raw_log",
}


def _apply_aliases(frame: pd.DataFrame) -> pd.DataFrame:
    renamed = frame.copy()
    for column in list(renamed.columns):
        target = _ALIASES.get(str(column).strip().lower(), column)
        if target == column:
            continue
        if target in renamed.columns:
            missing = renamed[target].isna() | renamed[target].astype(str).str.strip().isin(["", "nan", "NaT"])
            renamed.loc[missing, target] = renamed.loc[missing, column]
            renamed = renamed.drop(columns=[column])
        else:
            renamed = renamed.rename(columns={column: target})
    return renamed


def normalize_to_schema(frame: pd.DataFrame) -> pd.DataFrame:
    """Map an arbitrary DataFrame into the canonical event schema.

    Returns a frame with every ``EVENT_SCHEMA_COLUMNS`` column present.
    ``raw_log`` is always populated (from an existing raw column or the
    message) so no information is discarded.
    """
    if frame.empty:
        return pd.DataFrame(columns=EVENT_SCHEMA_COLUMNS)

    normalized = _apply_aliases(frame)
    if "raw_log" not in normalized.columns:
        if "raw_line" in normalized.columns:
            normalized["raw_log"] = normalized["raw_line"]
        else:
            normalized["raw_log"] = normalized.get("message", pd.Series([""], index=normalized.index)).astype(str)

    for column in EVENT_SCHEMA_COLUMNS:
        if column not in normalized.columns:
            normalized[column] = ""
    normalized["raw_log"] = normalized["raw_log"].fillna("")
    normalized["message"] = normalized["message"].fillna(normalized["raw_log"]).astype(str)
    normalized["raw_log"] = normalized["raw_log"].astype(str)
    normalized["timestamp"] = pd.to_datetime(normalized["timestamp"], errors="coerce")
    for column in ["source", "source_file", "source_host", "source_ip", "username", "event_type", "severity", "level"]:
        normalized[column] = normalized[column].fillna("").astype(str)
    normalized["parse_status"] = normalized.get("parse_status", "ok").fillna("ok").astype(str)
    normalized["parser"] = normalized.get("parser", "").fillna("").astype(str)
    if "event_id" not in normalized.columns or normalized["event_id"].fillna("").eq("").any():
        normalized["event_id"] = range(1, len(normalized) + 1)
    return normalized[EVENT_SCHEMA_COLUMNS + [column for column in normalized.columns if column not in EVENT_SCHEMA_COLUMNS]]


def infer_event_type(message: str) -> str:
    """Best-effort event-type classification from a raw message string."""
    text = message.lower()
    if any(token in text for token in ["failed password", "authentication failure", "invalid user", "login failed", "refused", "denied"]):
        return EVENT_TYPE_AUTH_FAILURE
    if any(token in text for token in ["accepted", "session opened", "login", "logon", "authentication success"]):
        return EVENT_TYPE_AUTH_SUCCESS
    if any(token in text for token in ["sudo", "privilege", "role", "admin"]):
        return EVENT_TYPE_PRIVILEGE
    if any(token in text for token in ["useradd", "userdel", "passwd", "account", "groupadd"]):
        return EVENT_TYPE_ACCOUNT
    if any(token in text for token in ["error", "exception", "crash", "fault", "warning"]):
        return EVENT_TYPE_ERROR
    return EVENT_TYPE_GENERIC
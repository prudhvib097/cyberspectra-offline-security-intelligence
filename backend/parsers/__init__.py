"""Modular per-format log parsers.

Each parser module exposes two pure functions:

    detect(text: str) -> bool      cheap format sniff on a raw line
    parse(text: str) -> dict       structured record (schema fields)

``parse_records`` dispatches records to the matching parser and preserves
malformed lines as ``event_type="unparsed"`` records instead of crashing, so a
broken line never aborts analysis of the rest of the file.
"""

from __future__ import annotations

from typing import Any, Iterable

import pandas as pd

from backend.schema import EVENT_TYPE_UNPARSED, infer_event_type, normalize_to_schema
from backend.parsers import app, auth, cloudtrail, firewall, jsonl, network, syslog, web, windows

_PARSER_MODULES = [
    jsonl,
    auth,
    syslog,
    web,
    windows,
    firewall,
    network,
    app,
    cloudtrail,
]

# Cheap token-based source-kind hints used when parsing whole frames.
_KIND_HINTS: dict[str, tuple[str, ...]] = {
    "linux": ("auth.log", "secure", "messages", "syslog", "sshd"),
    "windows": ("windows", "event", "evtx", "security", "system", "application"),
    "web": ("apache", "nginx", "access.log", "access_", "error.log", "httpd", "request"),
    "cloud": ("cloudtrail", "aws", "guardduty", "iam", "lambda"),
    "firewall": ("firewall", "pf", "iptables", "ufw", "deny"),
    "network": ("network", "dns", "dhcp", "flow", "netflow", "tcp", "udp"),
    "app": ("app.log", "application.log", "service.log", ".log"),
    "jsonl": (".jsonl", ".json"),
}


def safe_text(value: object) -> str:
    """Convert a possibly missing DataFrame value to normalized text."""
    if value is None:
        return ""
    try:
        missing = pd.isna(value)
        if not hasattr(missing, "__len__"):
            try:
                if bool(missing):
                    return ""
            except (TypeError, ValueError):
                return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def infer_source_kind(source_text: object) -> str:
    """Return a source-kind token from a file/directory name."""
    text = safe_text(source_text).lower()
    for kind, hints in _KIND_HINTS.items():
        if any(hint in text for hint in hints):
            return kind
    return "generic"


def detect_format(text: object) -> str:
    """Return the id of the first parser that recognizes ``text``."""
    text = safe_text(text)
    for module in _PARSER_MODULES:
        if module.detect(text):
            return getattr(module, "PARSER_ID", module.__name__.split(".")[-1])
    return "generic"


def parse_line(
    line: object,
    source_name: str = "unknown",
    parser_modules: Iterable[object] | None = None,
) -> dict[str, Any]:
    """Parse a single raw line into a schema-like record."""
    text = safe_text(line)
    source_name = safe_text(source_name) or "unknown"
    if not text:
        return {"parse_status": "empty"}
    modules = list(parser_modules) if parser_modules is not None else _PARSER_MODULES
    for module in modules:
        if module.detect(text):
            record = module.parse(text)
            record.setdefault("event_type", infer_event_type(str(record.get("message", text))))
            record.setdefault("source", source_name)
            record.setdefault("parser", getattr(module, "PARSER_ID", module.__name__.split(".")[-1]))
            record.setdefault("parse_status", "ok")
            return record
    return {
        "timestamp": pd.NaT,
        "message": text,
        "raw_log": text,
        "event_type": EVENT_TYPE_UNPARSED,
        "source": source_name,
        "parse_status": "unparsed",
        "parser": "none",
    }


def parse_records(frame: pd.DataFrame, source_ref: str = "") -> pd.DataFrame:
    """Parse every raw line in a frame into the common schema.

    Malformed lines (those no parser accepts) are kept with ``event_type``
    "unparsed" and do not abort the rest of the frame.
    """
    if frame.empty:
        return normalize_to_schema(frame)

    working = frame.copy()
    if "raw_line" not in working.columns and "raw_log" not in working.columns and "message" in working.columns:
        working["raw_line"] = working["message"]

    raw_values = working.get("raw_line", working.get("raw_log", working.get("message", "")))
    raw_lines = raw_values.map(safe_text)
    source_column = working.get("source_file")
    source_name = safe_text(source_column.iloc[0]) if source_column is not None and not source_column.empty else safe_text(source_ref)
    if infer_source_kind(source_name) == "web":
        vectorized = web.parse_frame(raw_lines, source_name or "unknown")
        if vectorized["parse_status"].eq("ok").all():
            merged = working.copy()
            for column in vectorized.columns:
                merged[column] = vectorized[column]
            merged["raw_log"] = raw_lines
            return normalize_to_schema(merged)

    records: list[dict[str, Any]] = []
    # Materialize rows once. Repeated ``DataFrame.loc`` lookups make parsing
    # large uploads quadratic in practice because every field access rebuilds a
    # Series. The record dictionaries retain the same values without changing
    # parser behavior.
    original_rows = working.to_dict(orient="records")
    for row_index, raw, original in zip(working.index, raw_lines.array, original_rows):
        source_text = safe_text(source_ref) or safe_text(original.get("source_file", "unknown")) or "unknown"
        source_kind = infer_source_kind(source_text)
        preferred = [web] if source_kind == "web" else None
        record = parse_line(raw, source_name=source_text, parser_modules=preferred)
        if preferred is not None and record.get("event_type") == EVENT_TYPE_UNPARSED:
            record = parse_line(raw, source_name=source_text)
        if not record.get("source"):
            record["source"] = source_text
        record.setdefault("raw_log", raw)
        record["raw_log"] = raw
        for column in ["timestamp", "source", "source_file", "source_host", "source_ip", "username", "event_type", "level", "message"]:
            if column not in original:
                continue
            value = original[column]
            value_text = safe_text(value)
            if value_text and value_text.lower() != "nan":
                if column in {"timestamp", "source", "source_file", "source_host", "source_ip", "username", "event_type", "level"}:
                    record[column] = value
                elif column == "message" and not record.get("message"):
                    record[column] = value
        records.append(record)

    for column in ["timestamp", "level", "message", "raw_log", "event_type", "source", "parse_status", "parser"]:
        for record in records:
            record.setdefault(column, "")
    parsed = pd.DataFrame.from_records(records, index=working.index)
    merged = working.copy()
    for column in parsed.columns:
        merged[column] = parsed[column]
    return normalize_to_schema(merged)
from __future__ import annotations

import re
from typing import Iterable

import numpy as np
import pandas as pd

from backend.parsers import parse_records

NORMALIZED_LEVELS = {
    "warn": "WARNING",
    "warning": "WARNING",
    "err": "ERROR",
    "error": "ERROR",
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "info": "INFO",
    "debug": "DEBUG",
    "trace": "TRACE",
}


def _normalize_level(value: object) -> str:
    if pd.isna(value):
        return "INFO"
    text = str(value).strip().lower()
    return NORMALIZED_LEVELS.get(text, text.upper() or "INFO")


def apply_schema_and_preprocess(frame: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Parse raw records into the common event schema, then clean/standardize.

    Returns ``(cleaned_frame, malformed_count)`` where malformed records are
    kept (``parse_status == "unparsed"``) so a single broken line never aborts
    analysis of the rest of the file.
    """
    if frame.empty:
        return preprocess_logs(frame), 0

    schema_frame = parse_records(frame)
    cleaned = preprocess_logs(schema_frame)
    malformed_count = int(cleaned.get("parse_status", "").eq("unparsed").sum())
    return cleaned, malformed_count


def preprocess_logs(frame: pd.DataFrame) -> pd.DataFrame:
    """Clean and standardize raw log records before feature extraction."""
    if frame.empty:
        return frame.copy()

    processed = frame.copy()

    if "timestamp" not in processed.columns:
        processed["timestamp"] = pd.NaT
    # Mixed naive/tz-aware sources (journal, macOS unified log, Windows events) are normalised to naive UTC at ns resolution.
    processed["timestamp"] = pd.to_datetime(processed["timestamp"], errors="coerce", utc=True).dt.tz_localize(None).astype("datetime64[ns]")

    for column in ["message", "raw_line", "source_file", "source_path", "source", "component"]:
        if column not in processed.columns:
            processed[column] = None
        processed[column] = processed[column].fillna("").astype(str).str.strip()

    if "level" not in processed.columns:
        processed["level"] = "INFO"
    level_map = {value: _normalize_level(value) for value in processed["level"].dropna().unique()}
    processed["level"] = processed["level"].map(level_map).fillna("INFO")

    processed["message"] = processed["message"].replace({"": np.nan, "nan": np.nan}).fillna(processed["raw_line"])
    processed["message"] = processed["message"].fillna("").astype(str).str.strip()
    processed["raw_line"] = processed["raw_line"].fillna(processed["message"])

    processed["normalized_message"] = (
        processed["message"]
        .str.lower()
        .str.replace(r"\s+", " ", regex=True)
        .str.replace(r"[^a-z0-9_\-:. /]+", " ", regex=True)
        .str.strip()
    )
    processed["message_word_count"] = processed["normalized_message"].str.split().map(len)
    processed["message_word_count"] = processed["message_word_count"].fillna(0).astype(int)

    processed["has_timestamp"] = processed["timestamp"].notna()
    processed["event_date"] = processed["timestamp"].dt.date
    processed["event_hour"] = processed["timestamp"].dt.hour.fillna(-1).astype(int)
    processed["event_dayofweek"] = processed["timestamp"].dt.day_of_week.fillna(-1).astype(int)
    processed["is_business_hours"] = processed["event_hour"].between(8, 18, inclusive="both").astype(int)
    processed["is_weekend"] = processed["event_dayofweek"].isin([5, 6]).astype(int)

    if "line_number" not in processed.columns:
        processed["line_number"] = range(1, len(processed) + 1)

    processed = processed.drop_duplicates(subset=["source_path", "line_number", "raw_line"], keep="first")
    processed = processed.sort_values(by=["timestamp", "source_file", "line_number"], na_position="last").reset_index(drop=True)
    return processed

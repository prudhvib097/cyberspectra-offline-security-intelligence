from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import pandas as pd

SUPPORTED_EXTENSIONS = {".csv", ".txt", ".log", ".json", ".jsonl"}
DEFAULT_TEXT_COLUMNS = ["timestamp", "level", "message", "source", "component"]
MAX_SINGLE_FILE_BYTES = 200 * 1024 * 1024
TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

COLUMN_ALIASES = {
    "time": "timestamp",
    "date": "timestamp",
    "datetime": "timestamp",
    "log_time": "timestamp",
    "severity": "level",
    "log_level": "level",
    "status": "level",
    "msg": "message",
    "log_message": "message",
    "event": "message",
    "details": "message",
    "filename": "source_file",
    "file": "source_file",
}


def _normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    renamed = frame.copy()
    renamed.columns = [str(column).strip() for column in renamed.columns]
    rename_map = {
        column: COLUMN_ALIASES.get(column.lower(), column)
        for column in renamed.columns
    }
    renamed = renamed.rename(columns=rename_map)
    return renamed


def _build_text_frame(lines: Sequence[str], source_name: str, source_path: str) -> pd.DataFrame:
    records = []
    for index, raw_line in enumerate(lines, start=1):
        text = raw_line.strip()
        if not text:
            continue
        timestamp = None
        message = text
        level = None
        source = source_name
        component = None

        match = TIMESTAMP_PATTERN.match(text)
        if match:
            timestamp = match.group("timestamp")
            message = text[len(timestamp):].lstrip(" -|,")

        upper_text = text.upper()
        for candidate_level in ["CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE"]:
            if candidate_level in upper_text:
                level = "WARNING" if candidate_level == "WARN" else candidate_level
                break

        records.append(
            {
                "timestamp": timestamp,
                "level": level,
                "message": message,
                "source": source,
                "component": component,
                "raw_line": text,
                "line_number": index,
                "source_file": source_name,
                "source_path": source_path,
            }
        )

    frame = pd.DataFrame.from_records(records)
    if frame.empty:
        frame = pd.DataFrame(columns=[*DEFAULT_TEXT_COLUMNS, "raw_line", "line_number", "source_file", "source_path"])
    return frame


def _load_json_lines(path: str) -> pd.DataFrame:
    """Load a JSON Lines (.jsonl/.json) file where each line is a JSON object."""
    records: List[dict] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for index, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = {"parse_status": "unparsed", "raw": text}
            if not isinstance(parsed, dict):
                parsed = {"parse_status": "unparsed", "raw": text}
            parsed.setdefault("parse_status", "ok")
            parsed["line_number"] = index
            records.append(parsed)

    if not records:
        return pd.DataFrame(columns=[*DEFAULT_TEXT_COLUMNS, "raw_line", "line_number", "source_file", "source_path"])

    frame = pd.DataFrame.from_records(records)
    frame = _normalize_columns(frame)
    if "message" not in frame.columns:
        object_columns = [column for column in frame.columns if frame[column].dtype == object and column not in ("parse_status", "line_number")]
        if object_columns:
            frame["message"] = frame[object_columns].astype(str).agg(" | ".join, axis=1)
        else:
            frame["message"] = frame.get("raw", frame["line_number"].astype(str))
    if "timestamp" not in frame.columns:
        frame["timestamp"] = pd.NaT
    if "level" not in frame.columns:
        frame["level"] = "INFO"
    if "source" not in frame.columns:
        frame["source"] = Path(path).name
    if "component" not in frame.columns:
        frame["component"] = None
    frame["raw_line"] = frame.get("raw", frame["message"].astype(str))
    frame["source_file"] = Path(path).name
    frame["source_path"] = path
    return frame


def _load_csv_file(path: str) -> pd.DataFrame:
    frame = pd.read_csv(path, engine="python")
    frame = _normalize_columns(frame)
    if frame.empty:
        return pd.DataFrame(columns=[*DEFAULT_TEXT_COLUMNS, "raw_line", "line_number", "source_file", "source_path"])

    if "message" not in frame.columns:
        candidate_columns = [column for column in frame.columns if frame[column].dtype == object]
        if candidate_columns:
            frame["message"] = frame[candidate_columns].apply(lambda row: " | ".join(row.fillna("").astype(str)), axis=1).str.strip(" |")
        else:
            first_column = frame.columns[0]
            frame["message"] = frame[first_column].astype(str)

    if "timestamp" not in frame.columns:
        frame["timestamp"] = pd.NaT
    if "level" not in frame.columns:
        frame["level"] = "INFO"
    if "source" not in frame.columns:
        frame["source"] = Path(path).name
    if "component" not in frame.columns:
        frame["component"] = None

    raw_columns = [column for column in frame.columns if column not in {"raw_line", "source_path"}]
    frame["raw_line"] = frame[raw_columns].apply(lambda row: " | ".join(row.fillna("").astype(str)), axis=1).str.strip(" |")
    frame["line_number"] = range(1, len(frame) + 1)
    frame["source_file"] = Path(path).name
    frame["source_path"] = path
    return frame


def _load_text_file(path: str) -> pd.DataFrame:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()
    return _build_text_frame(lines, Path(path).name, path)


def load_log_file(path: str) -> pd.DataFrame:
    """Load a single CSV/TXT/LOG/JSON/JSONL file from the local system.

    Files larger than ``MAX_SINGLE_FILE_BYTES`` are rejected without reading so
    oversized inputs can neither exhaust memory nor hang the analysis run.
    """
    path_obj = Path(path)
    suffix = path_obj.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file extension for {path}. Expected CSV, TXT, LOG, JSON, or JSONL.")

    if not path_obj.exists() or not path_obj.is_file():
        raise FileNotFoundError(f"Log file does not exist: {path}")
    if path_obj.stat().st_size > MAX_SINGLE_FILE_BYTES:
        raise ValueError(f"File too large to process safely ({path_obj.stat().st_size} bytes).")

    if suffix == ".csv":
        frame = _load_csv_file(path)
    elif suffix in (".json", ".jsonl"):
        frame = _load_json_lines(path)
    else:
        frame = _load_text_file(path)

    if "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")

    return frame


def _iter_directory_files(directory: str, recursive: bool = False) -> List[str]:
    directory_path = Path(directory)
    if not directory_path.exists():
        return []

    patterns = ["**/*" if recursive else "*"]
    matches: List[str] = []
    for pattern in patterns:
        for file_path in directory_path.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                matches.append(str(file_path))
    return sorted(set(matches))


def list_available_log_files(directory: str, recursive: bool = False) -> List[str]:
    return _iter_directory_files(directory, recursive=recursive)


def load_logs_from_directory(directory: str, recursive: bool = False) -> pd.DataFrame:
    """Read every supported log file from a local folder on the user's laptop.

    Each file is isolated: a corrupt or oversized file is skipped and reported
    instead of aborting the remaining files.
    """
    file_paths = _iter_directory_files(directory, recursive=recursive)
    frames: List[pd.DataFrame] = []
    for file_path in file_paths:
        try:
            frame = load_log_file(file_path)
        except Exception:
            continue
        if not frame.empty:
            frames.append(frame)
    if not frames:
        return pd.DataFrame(columns=[*DEFAULT_TEXT_COLUMNS, "raw_line", "line_number", "source_file", "source_path"])
    return pd.concat(frames, ignore_index=True, sort=False)


def load_uploaded_files(uploaded_files: Iterable[object]) -> Tuple[pd.DataFrame, List[str]]:
    """Read one or many uploaded files from Streamlit's file uploader."""
    frames: List[pd.DataFrame] = []
    file_names: List[str] = []

    for uploaded_file in uploaded_files:
        file_name = getattr(uploaded_file, "name", "uploaded_file")
        file_names.append(file_name)
        suffix = Path(file_name).suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            raise ValueError(f"Unsupported uploaded file extension for {file_name}. Expected CSV, TXT, LOG, JSON, or JSONL.")

        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
        payload = uploaded_file.read()
        if isinstance(payload, str):
            text_payload = payload
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = bytes(payload)
            text_payload = payload_bytes.decode("utf-8", errors="ignore")
        if len(payload_bytes) > MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"Uploaded file is too large to process safely: {file_name}")

        if suffix == ".csv":
            if not payload_bytes.strip():
                frame = pd.DataFrame()
            else:
                frame = pd.read_csv(io.BytesIO(payload_bytes), engine="python")
            frame = _normalize_columns(frame)
            if frame.empty and not frame.columns.tolist():
                frame = pd.DataFrame(columns=DEFAULT_TEXT_COLUMNS)
            if "message" not in frame.columns and not frame.empty:
                object_columns = [column for column in frame.columns if frame[column].dtype == object]
                if object_columns:
                    frame["message"] = frame[object_columns].astype(str).agg(" | ".join, axis=1)
                else:
                    frame["message"] = frame.iloc[:, 0].astype(str)
            if "timestamp" not in frame.columns:
                frame["timestamp"] = pd.NaT
            if "level" not in frame.columns:
                frame["level"] = "INFO"
            if "source" not in frame.columns:
                frame["source"] = file_name
            if "component" not in frame.columns:
                frame["component"] = None
            frame["raw_line"] = frame["message"].astype(str)
            frame["line_number"] = range(1, len(frame) + 1)
            frame["source_file"] = file_name
            frame["source_path"] = file_name
        else:
            if suffix in (".json", ".jsonl"):
                records = []
                for index, line in enumerate(text_payload.splitlines(), start=1):
                    if not line.strip():
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        parsed = {"parse_status": "unparsed", "raw": line}
                    if not isinstance(parsed, dict):
                        parsed = {"parse_status": "unparsed", "raw": line}
                    parsed["line_number"] = index
                    records.append(parsed)
                frame = pd.DataFrame.from_records(records)
                if frame.empty:
                    frame = pd.DataFrame(columns=DEFAULT_TEXT_COLUMNS)
                frame = _normalize_columns(frame)
                if "message" not in frame.columns:
                    frame["message"] = frame["raw"].astype(str) if "raw" in frame.columns else ""
                frame["timestamp"] = frame.get("timestamp", pd.NaT)
                frame["level"] = frame.get("level", "INFO")
                frame["source"] = frame.get("source", file_name)
                frame["component"] = frame.get("component", None)
                frame["raw_line"] = frame["raw"].astype(str) if "raw" in frame.columns else frame["message"].astype(str)
                frame["source_file"] = file_name
                frame["source_path"] = file_name
            else:
                frame = _build_text_frame(text_payload.splitlines(), file_name, file_name)

        if "timestamp" in frame.columns:
            frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        frames.append(frame)

    if not frames:
        empty = pd.DataFrame(columns=[*DEFAULT_TEXT_COLUMNS, "raw_line", "line_number", "source_file", "source_path"])
        return empty, file_names

    combined = pd.concat(frames, ignore_index=True, sort=False)
    return combined, file_names


def scan_for_new_files(directory: str, seen_files: Iterable[str] | None = None, recursive: bool = False) -> List[str]:
    """Return files that are present on disk but not in the known file set."""
    known = set(seen_files or [])
    current_files = set(_iter_directory_files(directory, recursive=recursive))
    return sorted(current_files - known)


def directory_snapshot(directory: str, recursive: bool = False) -> pd.DataFrame:
    """Create a lightweight file inventory for monitoring and dashboard display."""
    paths = _iter_directory_files(directory, recursive=recursive)
    records = []
    for file_path in paths:
        stat = os.stat(file_path)
        records.append(
            {
                "file_path": file_path,
                "file_name": Path(file_path).name,
                "size_bytes": stat.st_size,
                "modified_time": pd.to_datetime(stat.st_mtime, unit="s"),
            }
        )
    return pd.DataFrame(records)

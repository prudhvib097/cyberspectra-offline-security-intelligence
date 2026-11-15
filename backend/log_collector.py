from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

import pandas as pd

from src.ingestion import directory_snapshot, list_available_log_files, load_log_file, load_logs_from_directory, load_uploaded_files, scan_for_new_files


def collect_from_paths(paths: Iterable[str], recursive: bool = False) -> pd.DataFrame:
    """Collect logs from a mixed set of files and directories on the local machine."""
    frames: List[pd.DataFrame] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            frame = load_logs_from_directory(str(path), recursive=recursive)
        elif path.is_file():
            frame = load_log_file(str(path))
        else:
            continue
        if not frame.empty:
            frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True, sort=False)


def collect_from_directory(directory: str, recursive: bool = False) -> pd.DataFrame:
    return load_logs_from_directory(directory, recursive=recursive)


def collect_from_uploaded_files(uploaded_files: Iterable[object]) -> tuple[pd.DataFrame, List[str]]:
    return load_uploaded_files(uploaded_files)


def inventory_directory(directory: str, recursive: bool = False) -> pd.DataFrame:
    return directory_snapshot(directory, recursive=recursive)


def discover_log_files(directory: str, recursive: bool = False) -> List[str]:
    return list_available_log_files(directory, recursive=recursive)


def detect_new_files(directory: str, seen_files: Iterable[str] | None = None, recursive: bool = False) -> List[str]:
    return scan_for_new_files(directory, seen_files=seen_files, recursive=recursive)

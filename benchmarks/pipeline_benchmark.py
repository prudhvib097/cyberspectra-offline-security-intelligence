"""Measure canonical pipeline scalability on representative synthetic logs.

Run with:
    python benchmarks/pipeline_benchmark.py --sizes 10000 50000 100000 200000
    python benchmarks/pipeline_benchmark.py --algorithm one_class_svm

Reports measured wall-clock seconds per pipeline stage (from the pipeline's own
stage timers), including SQLite persistence into a throw-away database so the
application database is never touched. Peak RSS is the process high-water mark.
"""

from __future__ import annotations

import argparse
import resource
import sys
import tempfile
from pathlib import Path
from time import perf_counter

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import SQLiteStore
from backend.pipeline import run_pipeline

STAGES = ["parsing", "normalization", "aggregation", "features", "detection", "risk", "persistence", "alerts"]


def build_input(size: int) -> pd.DataFrame:
    messages = [
        "Accepted password for analyst from 192.168.1.20",
        "Failed password for admin from 203.0.113.9",
        "GET /health 200 request completed",
        "Connection timeout from 198.51.100.4",
    ]
    return pd.DataFrame(
        {
            "timestamp": pd.date_range("2026-01-01", periods=size, freq="s"),
            "message": [messages[index % len(messages)] for index in range(size)],
            "source_file": ["benchmark.log"] * size,
            "source": ["benchmark"] * size,
            "line_number": range(size),
        }
    )


def peak_rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024


def measure(size: int, algorithm: str) -> dict[str, float]:
    frame = build_input(size)
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteStore(str(Path(tmp) / "bench.db"))
        started = perf_counter()
        bundle = run_pipeline(frame, algorithm=algorithm, persist=True, store=store)
        total = perf_counter() - started
    row: dict[str, float] = {"records": size, "alert_feed": len(bundle.alert_feed)}
    row.update({stage: round(bundle.timings.get(stage, 0.0), 2) for stage in STAGES})
    row["total_s"] = round(total, 2)
    row["peak_rss_mb"] = round(peak_rss_mb())
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark CyberSpectra pipeline scalability.")
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000, 200_000])
    parser.add_argument("--algorithm", choices=["isolation_forest", "one_class_svm"], default="isolation_forest")
    args = parser.parse_args()
    print(f"algorithm={args.algorithm}")
    rows = [measure(size, args.algorithm) for size in args.sizes]
    print(pd.DataFrame(rows).to_string(index=False))


if __name__ == "__main__":
    main()

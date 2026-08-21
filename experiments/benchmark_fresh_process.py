#!/usr/bin/env python3
"""Paired fresh-process timings of stock ripgrep versus --engine=fre."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / "artifacts/bin/rg-stock-f9c05a9"
FRE = ROOT / "target/release/rg"
GENERATED = ROOT / "experiments/bench-data/mixed-logs-64m.log"
REAL_SOURCE_REPO = Path("/Users/danluu/dev/ripgrep")
REAL_SOURCE = ROOT / "experiments/bench-data/ripgrep-source-concat.log"
SHAPES = ROOT / "experiments/bench-data/shapes"
PAIRS = 31
WARMUP_PAIRS = 3

ORDERED = r"(?:ab|a)"
OVERLAP = r"(?:aaaaaaaaab|aaaaaaaab|aaaaaaab|aaaaaab|aaaaab|aaaab|aaab|aab|ab)"
TRACE = r"ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT"
AMBIGUOUS = r"(?:a|aa)*b"
BOUNDED = r"a{0,100}b"


CELLS = [
    {
        "id": "ordered_generated_count_lines",
        "class": "registered-winner",
        "args": ["--count", ORDERED, str(GENERATED)],
    },
    {
        "id": "overlap_generated_count_matches",
        "class": "registered-winner",
        "args": ["--count-matches", OVERLAP, str(GENERATED)],
    },
    {
        "id": "trace_generated_count_lines",
        "class": "trace-shaped-registered",
        "args": ["--count", TRACE, str(GENERATED)],
    },
    {
        "id": "ordered_real_ripgrep_source",
        "class": "real-corpus-registered",
        "args": ["--count", ORDERED, str(REAL_SOURCE)],
    },
    {
        "id": "trace_real_ripgrep_source",
        "class": "real-corpus-trace-registered",
        "args": ["--count", TRACE, str(REAL_SOURCE)],
    },
    {
        "id": "registry_miss_generated",
        "class": "registry-miss-control",
        "args": ["--count", "worker=(?:alpha|omega)", str(GENERATED)],
    },
    {
        "id": "unsupported_ignore_case_generated",
        "class": "unsupported-profile-control",
        "args": ["--ignore-case", "--count", TRACE, str(GENERATED)],
    },
    {
        "id": "registered_small_startup",
        "class": "fresh-process-startup-control",
        "args": ["--count", ORDERED, "experiments/correctness-input.txt"],
    },
]

for pattern_id, pattern in (("ambiguous_star", AMBIGUOUS), ("bounded_repeat", BOUNDED)):
    for size_id in ("64k", "1m", "64m"):
        for scenario_id, filename in (
            ("negative", f"a-run-negative-{size_id}.log"),
            ("sparse_final_b", f"a-run-sparse-final-b-{size_id}.log"),
        ):
            CELLS.append(
                {
                    "id": f"{pattern_id}_{scenario_id}_{size_id}",
                    "class": "retained-aot-winning-shape",
                    "args": ["--count", pattern, str(SHAPES / filename)],
                }
            )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_once(engine: str, args: list[str]) -> dict:
    binary = STOCK if engine == "stock" else FRE
    choice = "default" if engine == "stock" else "fre"
    command = [str(binary), f"--engine={choice}", *args]
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.perf_counter_ns() - started
    return {
        "engine": engine,
        "elapsed_ns": elapsed,
        "status": completed.returncode,
        "stdout_hex": completed.stdout.hex(),
        "stderr_hex": completed.stderr.hex(),
    }


def assert_equivalent(stock: dict, fre: dict, cell_id: str) -> None:
    keys = ("status", "stdout_hex", "stderr_hex")
    if any(stock[key] != fre[key] for key in keys):
        details = {
            engine: {
                "status": result["status"],
                "stdout_bytes": len(bytes.fromhex(result["stdout_hex"])),
                "stdout_sha256": hashlib.sha256(
                    bytes.fromhex(result["stdout_hex"])
                ).hexdigest(),
                "stderr_bytes": len(bytes.fromhex(result["stderr_hex"])),
                "stderr_sha256": hashlib.sha256(
                    bytes.fromhex(result["stderr_hex"])
                ).hexdigest(),
            }
            for engine, result in (("stock", stock), ("fre", fre))
        }
        raise RuntimeError(f"non-equivalent outputs in {cell_id}: {details!r}")


def percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def summarize(samples: list[dict]) -> dict:
    stock = [sample["stock"]["elapsed_ns"] for sample in samples]
    fre = [sample["fre"]["elapsed_ns"] for sample in samples]
    ratios = [left / right for left, right in zip(stock, fre)]
    return {
        "pairs": len(samples),
        "stock_median_ns": int(statistics.median(stock)),
        "fre_median_ns": int(statistics.median(fre)),
        "ratio_of_medians_stock_over_fre": statistics.median(stock)
        / statistics.median(fre),
        "paired_ratio_median_stock_over_fre": statistics.median(ratios),
        "paired_ratio_p10_stock_over_fre": percentile(ratios, 0.10),
        "paired_ratio_p90_stock_over_fre": percentile(ratios, 0.90),
        "stock_min_ns": min(stock),
        "fre_min_ns": min(fre),
    }


def main() -> None:
    if GENERATED.stat().st_size != 64 * 1024 * 1024:
        raise RuntimeError("generate the 64 MiB corpus first")

    results = []
    partial_destination = ROOT / "artifacts/raw/fresh-process-benchmark.partial.json"
    for cell_index, cell in enumerate(CELLS):
        args = cell["args"]
        for warmup in range(WARMUP_PAIRS):
            order = ("stock", "fre") if warmup % 2 == 0 else ("fre", "stock")
            pair = {engine: run_once(engine, args) for engine in order}
            assert_equivalent(pair["stock"], pair["fre"], cell["id"])

        samples = []
        for pair_index in range(PAIRS):
            # Rotate the starting order between cells too, avoiding a fixed
            # association between one engine and first/second position.
            stock_first = (pair_index + cell_index) % 2 == 0
            order = ("stock", "fre") if stock_first else ("fre", "stock")
            pair = {engine: run_once(engine, args) for engine in order}
            assert_equivalent(pair["stock"], pair["fre"], cell["id"])
            samples.append(
                {
                    "pair_index": pair_index,
                    "order": list(order),
                    "stock": pair["stock"],
                    "fre": pair["fre"],
                }
            )
        row = {**cell, "summary": summarize(samples), "samples": samples}
        results.append(row)
        partial_destination.write_text(
            json.dumps(
                {
                    "schema": "rg-fre-aot-fresh-process-partial-v1",
                    "pairs_per_cell": PAIRS,
                    "completed_cells": results,
                },
                indent=2,
            )
            + "\n"
        )
        summary = row["summary"]
        print(
            f"{cell['id']}: stock={summary['stock_median_ns'] / 1e6:.3f}ms "
            f"fre={summary['fre_median_ns'] / 1e6:.3f}ms "
            f"stock/fre={summary['ratio_of_medians_stock_over_fre']:.3f}x",
            flush=True,
        )

    record = {
        "schema": "rg-fre-aot-fresh-process-v1",
        "timestamp_unix": time.time(),
        "method": {
            "unit": "one normal ripgrep query in one newly launched process",
            "pairs_per_cell": PAIRS,
            "warmup_pairs_per_cell": WARMUP_PAIRS,
            "order": "alternating AB/BA, phase rotated by cell",
            "clock": "time.perf_counter_ns around subprocess.run",
            "stdout_stderr": "captured identically and equality-checked on every pair",
            "application_cache": "none",
            "filesystem_cache": "warm OS cache after unrecorded warmups",
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "binaries": {
            "stock": {"path": str(STOCK), "sha256": sha256(STOCK)},
            "fre": {"path": str(FRE), "sha256": sha256(FRE)},
        },
        "corpora": {
            "generated": {
                "path": str(GENERATED),
                "bytes": GENERATED.stat().st_size,
                "sha256": sha256(GENERATED),
            },
            "real_source": {
                "path": str(REAL_SOURCE),
                "bytes": REAL_SOURCE.stat().st_size,
                "sha256": sha256(REAL_SOURCE),
                "generator": "concatenate non-NUL tracked files in git ls-files order",
            },
            "real_source_repo": {
                "path": str(REAL_SOURCE_REPO),
                "commit": subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=REAL_SOURCE_REPO,
                    text=True,
                    stdout=subprocess.PIPE,
                    check=True,
                ).stdout.strip(),
            },
            "shape_files": {
                path.name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
                for path in sorted(SHAPES.glob("*.log"))
            },
        },
        "cells": results,
    }
    destination = ROOT / "artifacts/raw/fresh-process-benchmark.json"
    destination.write_text(json.dumps(record, indent=2) + "\n")
    print(f"wrote {destination}", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Paired fresh-process benchmark of normal rg versus background FRE AOT."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from common import (
    DEFAULT_MANIFEST,
    REPO,
    Cell,
    benchmark_cells,
    load_manifest,
    sha256,
    verify_manifest_files,
)
from runner import assert_exact_output, run_once


def median(values: Sequence[int | float]) -> float:
    if not values:
        raise ValueError("median of empty values")
    return float(statistics.median(values))


def relative_mad(values: Sequence[int]) -> float:
    center = median(values)
    if center == 0:
        return 0.0 if all(value == 0 for value in values) else math.inf
    return median([abs(value - center) for value in values]) / center


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def bootstrap_median_interval(
    values: Sequence[float], *, resamples: int, seed: int
) -> tuple[float, float]:
    generator = random.Random(seed)
    count = len(values)
    bootstrapped = [
        median([values[generator.randrange(count)] for _ in range(count)])
        for _ in range(resamples)
    ]
    return percentile(bootstrapped, 0.025), percentile(bootstrapped, 0.975)


def pair_summary(
    samples: list[dict[str, Any]],
    numerator: str,
    denominator: str,
    *,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    left = [sample[numerator]["elapsed_ns"] for sample in samples]
    right = [sample[denominator]["elapsed_ns"] for sample in samples]
    ratios = [left_ns / right_ns for left_ns, right_ns in zip(left, right)]
    low, high = bootstrap_median_interval(ratios, resamples=resamples, seed=seed)
    by_order: dict[str, list[float]] = {}
    for sample, ratio in zip(samples, ratios):
        key = "-then-".join(sample["order"])
        by_order.setdefault(key, []).append(ratio)
    order_medians = {key: median(group) for key, group in sorted(by_order.items())}
    order_effect = None
    if len(order_medians) == 2:
        values = list(order_medians.values())
        order_effect = abs(values[0] - values[1]) / median(values)
    left_rmad = relative_mad(left)
    right_rmad = relative_mad(right)
    stable = (
        left_rmad <= 0.15
        and right_rmad <= 0.15
        and (order_effect is None or order_effect <= 0.15)
    )
    return {
        "pairs": len(samples),
        "ratio_definition": f"{numerator} elapsed / {denominator} elapsed",
        f"{numerator}_median_ns": round(median(left)),
        f"{denominator}_median_ns": round(median(right)),
        f"{numerator}_relative_mad": left_rmad,
        f"{denominator}_relative_mad": right_rmad,
        "ratio_of_medians": median(left) / median(right),
        "paired_ratio_median": median(ratios),
        "paired_ratio_bootstrap_95_low": low,
        "paired_ratio_bootstrap_95_high": high,
        "paired_ratio_p10": percentile(ratios, 0.10),
        "paired_ratio_p90": percentile(ratios, 0.90),
        "order_ratio_medians": order_medians,
        "relative_order_effect": order_effect,
        "stability_limit": 0.15,
        "stable": stable,
        f"{numerator}_median_user_cpu_ns": round(
            median([sample[numerator]["user_cpu_ns"] for sample in samples])
        ),
        f"{denominator}_median_user_cpu_ns": round(
            median([sample[denominator]["user_cpu_ns"] for sample in samples])
        ),
        f"{numerator}_median_system_cpu_ns": round(
            median([sample[numerator]["system_cpu_ns"] for sample in samples])
        ),
        f"{denominator}_median_system_cpu_ns": round(
            median([sample[denominator]["system_cpu_ns"] for sample in samples])
        ),
    }


def receipt_summary(samples: list[dict[str, Any]]) -> dict[str, Any]:
    receipts = [sample["background"]["receipt"] for sample in samples]
    outcomes = Counter(receipt["outcome"] for receipt in receipts)
    mixed = [
        receipt
        for receipt in receipts
        if receipt["stock_files"] > 0 and receipt["fre_aot_files"] > 0
    ]
    ready = [receipt for receipt in receipts if receipt["outcome"] == "ready"]
    cutover = [receipt for receipt in receipts if receipt["fre_aot_files"] > 0]
    return {
        "outcomes": dict(sorted(outcomes.items())),
        "mixed_stock_then_fre_samples": len(mixed),
        "any_fre_samples": len(cutover),
        "ready_but_no_fre_samples": sum(
            receipt["outcome"] == "ready" and receipt["fre_aot_files"] == 0
            for receipt in receipts
        ),
        "median_compile_ns": round(median([receipt["compile_ns"] for receipt in receipts])),
        "median_prepare_ns": round(median([receipt["prepare_ns"] for receipt in receipts])),
        "median_ready_ns_since_start": (
            round(median([receipt["ready_ns_since_start"] for receipt in ready]))
            if ready
            else None
        ),
        "median_first_cutover_ns_since_start": (
            round(
                median(
                    [receipt["first_cutover_ns_since_start"] for receipt in cutover]
                )
            )
            if cutover
            else None
        ),
        "median_first_cutover_file_ordinal": (
            median([receipt["first_cutover_file_ordinal"] for receipt in cutover])
            if cutover
            else None
        ),
        "median_stock_files": median([receipt["stock_files"] for receipt in receipts]),
        "median_fre_aot_files": median(
            [receipt["fre_aot_files"] for receipt in receipts]
        ),
        "median_total_file_attempts": median(
            [receipt["total_file_attempts"] for receipt in receipts]
        ),
    }


def invoke_arm(
    arm: str,
    *,
    binary: Path,
    stock_binary: Path,
    cell: Cell,
    cwd: Path,
    temp_root: Path | None,
) -> dict[str, Any]:
    if arm == "background":
        result = run_once(
            binary=binary,
            args=cell.args,
            cwd=cwd,
            background=True,
            receipt_policy=cell.receipt_policy,
            temp_root=temp_root,
        )
        if result["receipt"]["total_file_attempts"] != cell.file_count:
            raise RuntimeError(
                f"{cell.id}: receipt counted "
                f"{result['receipt']['total_file_attempts']} file attempts, "
                f"expected {cell.file_count}"
            )
        return result
    if arm == "normal":
        return run_once(
            binary=binary,
            args=cell.args,
            cwd=cwd,
            background=False,
            temp_root=temp_root,
        )
    if arm == "stock":
        return run_once(
            binary=stock_binary,
            args=cell.args,
            cwd=cwd,
            background=False,
            temp_root=temp_root,
        )
    raise ValueError(f"unknown arm {arm!r}")


def run_pair(
    left: str,
    right: str,
    *,
    pair_index: int,
    phase: int,
    binary: Path,
    stock_binary: Path,
    cell: Cell,
    cwd: Path,
    temp_root: Path | None,
) -> dict[str, Any]:
    order = (left, right) if (pair_index + phase) % 2 == 0 else (right, left)
    results = {
        arm: invoke_arm(
            arm,
            binary=binary,
            stock_binary=stock_binary,
            cell=cell,
            cwd=cwd,
            temp_root=temp_root,
        )
        for arm in order
    }
    assert_exact_output(results[left], results[right], f"{cell.id}: {left}/{right}")
    return {"pair_index": pair_index, "order": list(order), **results}


def git_record(repo: Path) -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--short"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    return {"commit": commit, "status_short": status, "dirty": bool(status)}


def version(binary: Path) -> str:
    return subprocess.run(
        [str(binary), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout.strip()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--stock-binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, default=REPO)
    parser.add_argument("--pairs", type=int, default=31)
    parser.add_argument("--warmup-pairs", type=int, default=3)
    parser.add_argument("--stock-pairs", type=int, default=11)
    parser.add_argument("--stock-warmup-pairs", type=int, default=1)
    parser.add_argument("--bootstrap-resamples", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=20260820)
    parser.add_argument(
        "--cell",
        action="append",
        dest="cells",
        help="run only this cell ID; may be repeated",
    )
    parser.add_argument("--no-verify-corpus", action="store_true")
    parser.add_argument("--allow-hardlinks", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--temp-root", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    for name in ("pairs", "warmup_pairs", "bootstrap_resamples"):
        if getattr(args, name) <= 0:
            raise SystemExit(f"--{name.replace('_', '-')} must be positive")
    if args.stock_pairs < 0 or args.stock_warmup_pairs < 0:
        raise SystemExit("stock pair counts must be non-negative")
    binary = args.binary.resolve(strict=True)
    stock_binary = args.stock_binary.resolve(strict=True)
    manifest_path = args.manifest.resolve(strict=True)
    output = args.output.resolve()
    partial = output.with_suffix(output.suffix + ".partial")
    for path in (output, partial):
        if path.exists():
            raise SystemExit(f"refusing to replace existing result: {path}")

    manifest = load_manifest(manifest_path)
    if manifest["storage"] != "copy" and not args.allow_hardlinks:
        raise SystemExit(
            "primary timings require independently materialized copies; "
            "pass --allow-hardlinks only for a labeled pilot"
        )
    if not args.no_verify_corpus:
        verify_manifest_files(manifest_path, manifest)
    source = git_record(args.cwd)
    if args.require_clean and source["dirty"]:
        raise SystemExit("--require-clean requested but the source worktree is dirty")

    cells = benchmark_cells(manifest_path, manifest)
    if args.cells:
        requested = set(args.cells)
        known = {cell.id for cell in cells}
        missing = requested - known
        if missing:
            raise SystemExit(f"unknown cells: {', '.join(sorted(missing))}")
        cells = [cell for cell in cells if cell.id in requested]

    method = {
        "unit": "one ordinary query in one newly launched ripgrep process",
        "primary_comparison": "same binary flag off versus --fre-aot-background",
        "secondary_comparison": "preserved upstream binary versus same candidate binary flag off",
        "pairs_per_cell": args.pairs,
        "warmup_pairs_per_cell": args.warmup_pairs,
        "secondary_stock_pairs": args.stock_pairs,
        "secondary_stock_warmup_pairs": args.stock_warmup_pairs,
        "order": "adjacent alternating AB/BA, phase rotated by cell",
        "clock": "time.perf_counter_ns around subprocess.run through child exit and pipe drain",
        "correctness": "status and literal stdout/stderr bytes checked on every pair",
        "application_aot_cache": "none; every flagged sample recompiles in its fresh process",
        "filesystem_cache": "warm OS cache after unrecorded warmup pairs",
        "tmpdir": "unique per invocation; unexpected persistent files are fatal",
        "receipt": "unique create-new sidecar written before child exit; parsing is outside timer",
        "receipt_timings": {
            "compile_ns": "FRE compile(request) only",
            "prepare_ns": "compile plus object write, clang link, dlopen/dlsym",
            "ready_ns_since_start": "publication readiness relative to coordinator start",
            "first_cutover_ns_since_start": "first FRE-selected file boundary",
        },
        "bootstrap": {
            "unit": "paired elapsed ratio",
            "statistic": "median",
            "resamples": args.bootstrap_resamples,
            "seed": args.seed,
            "interval": "percentile 95%",
        },
    }
    header = {
        "schema": "ripgrep.fre-aot-background.benchmark.v1",
        "started_unix": time.time(),
        "method": method,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
            "load_average_started": list(os.getloadavg()),
        },
        "source": source,
        "binaries": {
            "candidate": {
                "path": str(binary),
                "sha256": sha256(binary),
                "version": version(binary),
            },
            "stock": {
                "path": str(stock_binary),
                "sha256": sha256(stock_binary),
                "version": version(stock_binary),
            },
        },
        "corpus": {
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "storage": manifest["storage"],
            "shard_bytes": manifest["shard_bytes"],
            "shards_per_scenario": manifest["shards_per_scenario"],
            "semantic_files": manifest.get("semantic_files"),
        },
    }
    completed_cells: list[dict[str, Any]] = []

    for cell_index, cell in enumerate(cells):
        print(f"{cell.id}: warmup", flush=True)
        for warmup in range(args.warmup_pairs):
            run_pair(
                "normal",
                "background",
                pair_index=warmup,
                phase=cell_index,
                binary=binary,
                stock_binary=stock_binary,
                cell=cell,
                cwd=args.cwd,
                temp_root=args.temp_root,
            )

        primary_samples = []
        for pair_index in range(args.pairs):
            sample = run_pair(
                "normal",
                "background",
                pair_index=pair_index,
                phase=cell_index,
                binary=binary,
                stock_binary=stock_binary,
                cell=cell,
                cwd=args.cwd,
                temp_root=args.temp_root,
            )
            primary_samples.append(sample)

        secondary_samples = []
        if cell.secondary_stock and args.stock_pairs:
            print(f"{cell.id}: upstream/normal secondary", flush=True)
            for warmup in range(args.stock_warmup_pairs):
                run_pair(
                    "stock",
                    "normal",
                    pair_index=warmup,
                    phase=cell_index + 1,
                    binary=binary,
                    stock_binary=stock_binary,
                    cell=cell,
                    cwd=args.cwd,
                    temp_root=args.temp_root,
                )
            for pair_index in range(args.stock_pairs):
                secondary_samples.append(
                    run_pair(
                        "stock",
                        "normal",
                        pair_index=pair_index,
                        phase=cell_index + 1,
                        binary=binary,
                        stock_binary=stock_binary,
                        cell=cell,
                        cwd=args.cwd,
                        temp_root=args.temp_root,
                    )
                )

        primary_summary = pair_summary(
            primary_samples,
            "normal",
            "background",
            resamples=args.bootstrap_resamples,
            seed=args.seed + cell_index,
        )
        row: dict[str, Any] = {
            "id": cell.id,
            "class": cell.class_name,
            "scenario": cell.scenario,
            "pattern": cell.pattern,
            "args": list(cell.args),
            "logical_bytes": cell.logical_bytes,
            "file_count": cell.file_count,
            "receipt_policy": cell.receipt_policy,
            "primary_summary": primary_summary,
            "receipt_summary": receipt_summary(primary_samples),
            "primary_samples": primary_samples,
            "secondary_stock_summary": (
                pair_summary(
                    secondary_samples,
                    "stock",
                    "normal",
                    resamples=args.bootstrap_resamples,
                    seed=args.seed + 10_000 + cell_index,
                )
                if secondary_samples
                else None
            ),
            "secondary_stock_samples": secondary_samples,
        }
        completed_cells.append(row)
        write_json(
            partial,
            {
                **header,
                "schema": "ripgrep.fre-aot-background.benchmark.partial.v1",
                "completed_cells": completed_cells,
                "active_cell": None,
            },
        )
        print(
            f"{cell.id}: normal={primary_summary['normal_median_ns'] / 1e6:.3f}ms "
            f"background={primary_summary['background_median_ns'] / 1e6:.3f}ms "
            f"normal/background={primary_summary['ratio_of_medians']:.3f}x",
            flush=True,
        )

    scaling = [
        row
        for row in completed_cells
        if row["class"] == "break-even-scaling"
        and row["primary_summary"]["stable"]
        and row["receipt_summary"]["mixed_stock_then_fre_samples"]
        == row["primary_summary"]["pairs"]
    ]
    significant = [
        row
        for row in scaling
        if row["primary_summary"]["paired_ratio_bootstrap_95_low"] > 1.0
    ]
    break_even = min(significant, key=lambda row: row["logical_bytes"]) if significant else None
    if not args.no_verify_corpus:
        verify_manifest_files(manifest_path, manifest)
    record = {
        **header,
        "finished_unix": time.time(),
        "load_average_finished": list(os.getloadavg()),
        "predeclared_discrete_break_even": (
            {
                "cell": break_even["id"],
                "logical_bytes": break_even["logical_bytes"],
                "definition": "smallest stable tested scaling cell with cutover in every pair and paired 95% lower bound > 1",
            }
            if break_even is not None
            else None
        ),
        "post_run_corpus_verified": not args.no_verify_corpus,
        "cells": completed_cells,
    }
    write_json(output, record)
    partial.unlink()
    print(f"wrote {output}")


if __name__ == "__main__":
    main()

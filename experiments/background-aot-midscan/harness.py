#!/usr/bin/env python3
"""Verify and benchmark fresh-query background FRE AOT mid-scan promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import re
import resource
import statistics
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_MANIFEST = HERE / "data" / "manifest.json"
CORPUS_SCHEMA = "ripgrep.fre-aot-background-midscan-corpus.v1"
RESULT_SCHEMA = "ripgrep.fre-aot-background-midscan"
RECEIPT_SCHEMA = "ripgrep.fre-aot-background.v2"
RECEIPT_ENV = "RG_FRE_AOT_BACKGROUND_RECEIPT"
CORRECTNESS_GATE_ENV = "RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES"
BACKGROUND_FLAG = "--fre-aot-background"
PATTERN = r"a{0,99}b"
MIB = 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def output_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex": data.hex(),
    }


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != CORPUS_SCHEMA:
        raise ValueError(f"unsupported corpus schema in {path}")
    if manifest.get("pattern") != PATTERN:
        raise ValueError("corpus pattern is not the predeclared unregistered query")
    return manifest


def fixed_registry_record() -> dict[str, Any]:
    path = REPO / "experiments" / "fre-patterns.tsv"
    registered = []
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t", 2)
        if len(fields) != 3:
            raise ValueError(f"malformed fixed-registry row in {path}")
        registered.append(fields[2])
    if PATTERN in registered:
        raise ValueError(f"benchmark query unexpectedly appears in {path}")
    return {
        "path": str(path),
        "sha256": sha256(path),
        "query_registered": False,
    }


def corpus_path(manifest_path: Path, row: Mapping[str, Any]) -> Path:
    return manifest_path.parent / str(row["path"])


def all_rows(manifest: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [manifest["correctness"], *manifest["singles"], *manifest["tree"]["files"]]


def verify_corpus(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    seen: set[Path] = set()
    for row in all_rows(manifest):
        path = corpus_path(manifest_path, row)
        if path in seen:
            continue
        seen.add(path)
        if path.stat().st_size != row["bytes"]:
            raise ValueError(f"size mismatch for {path}")
        if sha256(path) != row["sha256"]:
            raise ValueError(f"digest mismatch for {path}")


def nonnegative_int(receipt: Mapping[str, Any], key: str) -> int:
    value = receipt.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"receipt {key!r} is not a non-negative integer")
    return value


def optional_nonnegative_int(receipt: Mapping[str, Any], key: str) -> int | None:
    value = receipt.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"receipt {key!r} is not null or a non-negative integer")
    return value


def validate_receipt(
    receipt: Mapping[str, Any], *, expected_file_count: int,
    expected_gate_bytes: int | None = None
) -> None:
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ValueError(f"expected receipt {RECEIPT_SCHEMA!r}")
    if receipt.get("direct_native_only") is not True:
        raise ValueError("receipt does not attest direct in-process publication")
    if receipt.get("external_linker_invocations") != 0:
        raise ValueError("receipt reports an external-linker invocation")
    outcome = receipt.get("outcome")
    if outcome not in {"ready", "declined", "unfinished"}:
        raise ValueError(f"unknown receipt outcome {outcome!r}")
    if outcome == "declined":
        raise ValueError("eligible benchmark query unexpectedly declined AOT")

    compile_ns = nonnegative_int(receipt, "compile_ns")
    publish_ns = nonnegative_int(receipt, "publish_ns")
    prepare_ns = nonnegative_int(receipt, "prepare_ns")
    if prepare_ns and prepare_ns < max(compile_ns, publish_ns):
        raise ValueError("preparation is shorter than a measured sub-phase")
    ready_ns = optional_nonnegative_int(receipt, "ready_ns_since_start")
    total = nonnegative_int(receipt, "total_file_attempts")
    if total != expected_file_count:
        raise ValueError(
            f"receipt attempted {total} files, expected {expected_file_count}"
        )
    stock_files = nonnegative_int(receipt, "stock_files")
    aot_files = nonnegative_int(receipt, "fre_aot_files")
    mixed_files = nonnegative_int(receipt, "mixed_engine_files")
    stock_windows = nonnegative_int(receipt, "stock_windows")
    aot_windows = nonnegative_int(receipt, "fre_aot_windows")
    nonnegative_int(receipt, "stock_window_bytes")
    nonnegative_int(receipt, "fre_aot_window_bytes")
    stock_committed_bytes = nonnegative_int(receipt, "stock_committed_bytes")
    if nonnegative_int(receipt, "native_call_failures") != 0:
        raise ValueError("receipt reports a native AOT call failure")
    test_min_stock_bytes = nonnegative_int(receipt, "test_min_stock_bytes")
    if test_min_stock_bytes != (expected_gate_bytes or 0):
        raise ValueError(
            "receipt test publication gate does not match the invocation"
        )
    if stock_files > total or aot_files > total:
        raise ValueError("overlapping route file counts exceed attempted files")
    if mixed_files > min(stock_files, aot_files):
        raise ValueError("mixed file count exceeds a route file count")
    if stock_files + aot_files - mixed_files > total:
        raise ValueError("route file accounting exceeds attempted files")
    if bool(stock_files) != bool(stock_windows):
        raise ValueError("stock file/window accounting disagrees")
    if bool(aot_files) != bool(aot_windows):
        raise ValueError("AOT file/window accounting disagrees")
    if aot_windows and outcome != "ready":
        raise ValueError("AOT windows require a ready publication")
    if outcome == "ready" and ready_ns is None:
        raise ValueError("ready outcome is missing its timestamp")
    if outcome != "ready" and ready_ns is not None:
        raise ValueError("non-ready outcome has a ready timestamp")

    cutover_ordinal = optional_nonnegative_int(
        receipt, "first_cutover_file_ordinal"
    )
    cutover_ns = optional_nonnegative_int(
        receipt, "first_cutover_ns_since_start"
    )
    cutover_stock_bytes = optional_nonnegative_int(
        receipt, "first_cutover_stock_committed_bytes"
    )
    cutover_values = (cutover_ordinal, cutover_ns, cutover_stock_bytes)
    if any(value is None for value in cutover_values) != all(
        value is None for value in cutover_values
    ):
        raise ValueError("first-cutover fields must be all null or all populated")
    if mixed_files and cutover_ordinal is None:
        raise ValueError("mixed route file has no first-cutover telemetry")
    if cutover_ordinal is not None:
        if not 1 <= cutover_ordinal <= total:
            raise ValueError("first-cutover ordinal lies outside attempted files")
        if ready_ns is None or cutover_ns is None or ready_ns > cutover_ns:
            raise ValueError("first cutover precedes publication")
        if cutover_stock_bytes > stock_committed_bytes:
            raise ValueError("first cutover exceeds total committed stock bytes")

    if expected_gate_bytes is not None:
        if outcome != "ready" or mixed_files < 1:
            raise ValueError("correctness gate did not produce same-file promotion")
        if stock_windows < 1 or aot_windows < 1:
            raise ValueError("same-file promotion lacks both stock and AOT windows")
        if stock_committed_bytes < expected_gate_bytes:
            raise ValueError("publication occurred before the committed-byte gate")


def child_cpu_ns(
    before: resource.struct_rusage,
    after: resource.struct_rusage,
    key: str,
) -> int:
    return round((getattr(after, key) - getattr(before, key)) * 1_000_000_000)


def run_once(
    *,
    binary: Path,
    args: Sequence[str],
    cwd: Path,
    background: bool,
    expected_file_count: int,
    correctness_gate_bytes: int | None = None,
) -> dict[str, Any]:
    if correctness_gate_bytes is not None and not background:
        raise ValueError("the correctness publication gate applies only to AOT")
    command = [str(binary)]
    if background:
        command.append(BACKGROUND_FLAG)
    command.extend(args)
    with tempfile.TemporaryDirectory(prefix="rg-aot-midscan-") as temporary_text:
        temporary = Path(temporary_text)
        receipt_path = temporary / "receipt.json"
        environment = os.environ.copy()
        environment.pop(RECEIPT_ENV, None)
        environment.pop(CORRECTNESS_GATE_ENV, None)
        environment["TMPDIR"] = str(temporary)
        if correctness_gate_bytes is not None:
            environment[CORRECTNESS_GATE_ENV] = str(correctness_gate_bytes)
        if background:
            environment[RECEIPT_ENV] = str(receipt_path)

        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter_ns()
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        elapsed_ns = time.perf_counter_ns() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        receipt = None
        if background:
            if not receipt_path.is_file():
                raise RuntimeError("background invocation did not write a receipt")
            receipt = json.loads(receipt_path.read_text())
            validate_receipt(
                receipt,
                expected_file_count=expected_file_count,
                expected_gate_bytes=correctness_gate_bytes,
            )
        expected_entries = {"receipt.json"} if background else set()
        actual_entries = {path.name for path in temporary.iterdir()}
        if actual_entries != expected_entries:
            raise RuntimeError(
                "unexpected isolated TMPDIR entries: "
                f"{sorted(actual_entries - expected_entries)}"
            )
    return {
        "command": command,
        "elapsed_ns": elapsed_ns,
        "user_cpu_ns": child_cpu_ns(before, after, "ru_utime"),
        "system_cpu_ns": child_cpu_ns(before, after, "ru_stime"),
        "status": completed.returncode,
        "stdout": output_record(completed.stdout),
        "stderr": output_record(completed.stderr),
        "receipt": receipt,
    }


def assert_equal(left: Mapping[str, Any], right: Mapping[str, Any], label: str) -> None:
    for key in ("status", "stdout", "stderr"):
        if left[key] != right[key]:
            raise RuntimeError(f"{label}: {key} differs")


def compact(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": result["status"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "receipt": result["receipt"],
    }


def query_args(
    paths: Sequence[Path], *, threads: int | None, output: str,
    mmap: bool = False,
) -> tuple[str, ...]:
    args = [
        "--no-config", "--engine=default", "--no-ignore", "--text",
        "--color=never",
    ]
    if mmap:
        args.append("--mmap")
    if threads is not None:
        args.append(f"--threads={threads}")
    if output == "count":
        args.append("--count")
    elif output == "quiet":
        args.append("--quiet")
    elif output == "spans":
        args.extend(("--only-matching", "--byte-offset", "--line-number"))
    else:
        raise ValueError(f"unknown output mode {output!r}")
    args.extend(("--", PATTERN, *(str(path) for path in paths)))
    return tuple(args)


def git_record(path: Path) -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--short"],
        cwd=path,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    return {"commit": commit, "dirty": bool(status), "status_short": status}


def command_record(command: Sequence[str]) -> str:
    return subprocess.run(
        list(command),
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout.strip()


def fre_dependency_record() -> dict[str, Any]:
    cargo_toml = REPO / "Cargo.toml"
    matcher = re.compile(
        r'^fre-[^= ]+\s*=\s*\{[^}]*git\s*=\s*"([^"]+)"'
        r'[^}]*rev\s*=\s*"([0-9a-f]+)"[^}]*\}\s*$'
    )
    dependencies = []
    for line in cargo_toml.read_text().splitlines():
        match = matcher.match(line)
        if match:
            dependencies.append({"line": line, "git": match[1], "rev": match[2]})
    if len(dependencies) != 4:
        raise ValueError("expected four commit-pinned FRE dependencies")
    if len({(row["git"], row["rev"]) for row in dependencies}) != 1:
        raise ValueError("FRE dependencies do not use one coherent revision")
    return {
        "dependencies": dependencies,
        "cargo_toml_sha256": sha256(cargo_toml),
        "cargo_lock_sha256": sha256(REPO / "Cargo.lock"),
        "cargo_config_sha256": sha256(REPO / ".cargo" / "config.toml"),
    }


def binary_record(path: Path) -> dict[str, Any]:
    version = subprocess.run(
        [str(path), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout.strip()
    return {"path": str(path), "sha256": sha256(path), "version": version}


def write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ValueError(f"refusing to replace result: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def write_json_checkpoint(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise ValueError(f"temporary checkpoint already exists: {temporary}")
    try:
        with temporary.open("x") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def common_header(
    args: argparse.Namespace,
    manifest_path: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "source": git_record(args.cwd),
        "fre_dependency": fre_dependency_record(),
        "toolchain": {
            "rustc": command_record(("rustc", "+1.96.0", "-Vv")),
            "cargo": command_record(("cargo", "+1.96.0", "-Vv")),
        },
        "fixed_pattern_registry": fixed_registry_record(),
        "binaries": {
            "candidate": binary_record(args.binary),
            "stock": binary_record(args.stock_binary),
        },
        "corpus": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "pattern": manifest["pattern"],
            "line_bytes": manifest["line_bytes"],
        },
    }


def run_correctness(args: argparse.Namespace) -> None:
    manifest_path = args.manifest
    manifest = load_manifest(manifest_path)
    verify_corpus(manifest_path, manifest)
    provenance = common_header(args, manifest_path, manifest)
    if provenance["source"]["dirty"]:
        raise SystemExit("refusing formal correctness from a dirty source tree")
    gate_bytes = int(manifest["publication_gate_bytes"])
    correctness_path = corpus_path(manifest_path, manifest["correctness"])
    tree_paths = [
        corpus_path(manifest_path, row)
        for row in manifest["tree"]["files"][:8]
    ]
    cases = (
        (
            "same-file-two-witnesses",
            query_args((correctness_path,), threads=1, output="count"),
            1,
        ),
        (
            "same-file-exact-spans",
            query_args((correctness_path,), threads=1, output="spans"),
            1,
        ),
        (
            "default-thread-tree",
            query_args(tuple(tree_paths), threads=None, output="quiet"),
            len(tree_paths),
        ),
    )
    rows = []
    for name, invocation_args, expected_file_count in cases:
        normal = run_once(
            binary=args.binary,
            args=invocation_args,
            cwd=args.cwd,
            background=False,
            expected_file_count=expected_file_count,
        )
        background = run_once(
            binary=args.binary,
            args=invocation_args,
            cwd=args.cwd,
            background=True,
            expected_file_count=expected_file_count,
            correctness_gate_bytes=gate_bytes,
        )
        stock = run_once(
            binary=args.stock_binary,
            args=invocation_args,
            cwd=args.cwd,
            background=False,
            expected_file_count=expected_file_count,
        )
        assert_equal(normal, background, f"{name}: normal/background")
        assert_equal(stock, normal, f"{name}: stock/normal")
        receipt = background["receipt"]
        if name.startswith("same-file-"):
            if receipt["total_file_attempts"] != 1:
                raise RuntimeError("same-file case did not attempt exactly one file")
            if receipt["first_cutover_file_ordinal"] != 1:
                raise RuntimeError("same-file cutover was not recorded in file one")
            if receipt["first_cutover_stock_committed_bytes"] < gate_bytes:
                raise RuntimeError("same-file cutover preceded the publication gate")
        rows.append(
            {
                "name": name,
                "args": list(invocation_args),
                "normal": compact(normal),
                "background": compact(background),
                "stock": compact(stock),
            }
        )
        print(f"{name}: ok", flush=True)
    verify_corpus(manifest_path, manifest)
    post_provenance = common_header(args, manifest_path, manifest)
    if post_provenance != provenance:
        raise RuntimeError("source, dependency, binary, or corpus changed during correctness")
    write_json_new(
        args.output,
        {
            "schema": f"{RESULT_SCHEMA}.correctness.v1",
            "comparison": "identical status and literal stdout/stderr bytes",
            "correctness_gate": {
                "environment": CORRECTNESS_GATE_ENV,
                "bytes": gate_bytes,
                "timed": False,
            },
            **provenance,
            "cases": rows,
            "post_run_corpus_verified": True,
            "post_run_provenance_verified": True,
        },
    )


def median(values: Sequence[int | float]) -> float:
    return float(statistics.median(values))


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def relative_mad(values: Sequence[int]) -> float:
    center = median(values)
    if center == 0:
        return 0.0 if all(value == 0 for value in values) else math.inf
    return median([abs(value - center) for value in values]) / center


def bootstrap_median_interval(values: Sequence[float]) -> tuple[float, float]:
    rng = random.Random(0xA07B0A7)
    draws = []
    for _ in range(10_000):
        draws.append(median([rng.choice(values) for _ in values]))
    return percentile(draws, 0.025), percentile(draws, 0.975)


def pair_summary(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    normal = [sample["normal"]["elapsed_ns"] for sample in samples]
    background = [sample["background"]["elapsed_ns"] for sample in samples]
    stock = [sample["stock"]["elapsed_ns"] for sample in samples]
    ratios = [left / right for left, right in zip(normal, background)]
    stock_background_ratios = [
        left / right for left, right in zip(stock, background)
    ]
    stock_normal_ratios = [left / right for left, right in zip(stock, normal)]
    by_order: dict[str, list[float]] = {}
    for sample, ratio in zip(samples, ratios):
        order = sample["order"]
        key = (
            "normal-before-background"
            if order.index("normal") < order.index("background")
            else "background-before-normal"
        )
        by_order.setdefault(key, []).append(ratio)
    order_medians = {
        key: median(values) for key, values in sorted(by_order.items())
    }
    order_effect = (
        abs(max(order_medians.values()) - min(order_medians.values()))
        / median(ratios)
    )
    ci_low, ci_high = bootstrap_median_interval(ratios)
    normal_rmad = relative_mad(normal)
    background_rmad = relative_mad(background)
    stable = normal_rmad <= 0.10 and background_rmad <= 0.10 and order_effect <= 0.15
    return {
        "ratio_definition": "normal elapsed / background elapsed (>1 is AOT faster)",
        "pairs": len(samples),
        "normal_median_ns": round(median(normal)),
        "background_median_ns": round(median(background)),
        "stock_median_ns": round(median(stock)),
        "ratio_of_medians": median(normal) / median(background),
        "paired_ratio_median": median(ratios),
        "paired_ratio_descriptive_95pct_interval": [ci_low, ci_high],
        "paired_ratio_p10": percentile(ratios, 0.10),
        "paired_ratio_p90": percentile(ratios, 0.90),
        "stock_over_background_paired_ratio_median": median(
            stock_background_ratios
        ),
        "stock_over_normal_paired_ratio_median": median(stock_normal_ratios),
        "normal_relative_mad": normal_rmad,
        "background_relative_mad": background_rmad,
        "order_ratio_medians": order_medians,
        "relative_order_effect": order_effect,
        "stable": stable,
        "descriptive_speedup_supported": stable and ci_low > 1.0,
        "multiple_comparison_adjustment": None,
    }


def receipt_summary(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    receipts = [sample["background"]["receipt"] for sample in samples]
    ready = [receipt for receipt in receipts if receipt["outcome"] == "ready"]
    categories = Counter()
    for receipt in receipts:
        has_stock = receipt["stock_windows"] > 0
        has_aot = receipt["fre_aot_windows"] > 0
        if receipt["mixed_engine_files"] > 0:
            categories["same_file_mixed"] += 1
        elif has_stock and has_aot:
            categories["cross_file_split_without_midfile"] += 1
        elif has_aot:
            categories["all_aot"] += 1
        elif has_stock:
            categories[f"stock_only_{receipt['outcome']}"] += 1
        else:
            categories["no_matcher_windows"] += 1
    if sum(categories.values()) != len(receipts):
        raise AssertionError("receipt routing categories are not exhaustive")
    cutovers = [
        receipt for receipt in receipts
        if receipt["first_cutover_ns_since_start"] is not None
    ]
    return {
        "outcomes": dict(
            sorted(Counter(receipt["outcome"] for receipt in receipts).items())
        ),
        "routing_categories": dict(sorted(categories.items())),
        "median_compile_attempt_ns": round(median([
            receipt["compile_ns"] for receipt in receipts
        ])),
        "median_ready_compile_ns": (
            round(median([receipt["compile_ns"] for receipt in ready]))
            if ready else None
        ),
        "median_ready_publish_ns": (
            round(median([receipt["publish_ns"] for receipt in ready]))
            if ready else None
        ),
        "median_ready_prepare_ns": (
            round(median([receipt["prepare_ns"] for receipt in ready]))
            if ready else None
        ),
        "median_ready_ns_since_start": (
            round(median([receipt["ready_ns_since_start"] for receipt in ready]))
            if ready
            else None
        ),
        "median_stock_window_bytes": round(
            median([receipt["stock_window_bytes"] for receipt in receipts])
        ),
        "median_stock_committed_bytes": round(
            median([receipt["stock_committed_bytes"] for receipt in receipts])
        ),
        "median_fre_aot_window_bytes": round(
            median([receipt["fre_aot_window_bytes"] for receipt in receipts])
        ),
        "external_linker_invocations": sorted(
            {receipt["external_linker_invocations"] for receipt in receipts}
        ),
        "native_call_failures": sorted(
            {receipt["native_call_failures"] for receipt in receipts}
        ),
        "samples_with_same_file_cutover": len(cutovers),
        "median_first_cutover_ns_since_start": (
            round(median([
                receipt["first_cutover_ns_since_start"] for receipt in cutovers
            ])) if cutovers else None
        ),
        "median_first_cutover_stock_committed_bytes": (
            round(median([
                receipt["first_cutover_stock_committed_bytes"]
                for receipt in cutovers
            ])) if cutovers else None
        ),
    }


def benchmark_cells(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    cells = []
    for row in manifest["singles"]:
        path = corpus_path(manifest_path, row)
        size_mib = row["bytes"] // MIB
        cells.append(
            {
                "id": f"single-{size_mib}m-threads1",
                "logical_bytes": row["bytes"],
                "file_count": 1,
                "args": query_args((path,), threads=1, output="quiet"),
            }
        )
        if size_mib == 256:
            cells.append(
                {
                    "id": "single-256m-mmap-threads1-control",
                    "logical_bytes": row["bytes"],
                    "file_count": 1,
                    "args": query_args(
                        (path,), threads=1, output="quiet", mmap=True
                    ),
                }
            )
    tree_paths = [corpus_path(manifest_path, row) for row in manifest["tree"]["files"]]
    per_file = int(manifest["tree"]["file_bytes"])
    for count in (8, 16):
        if len(tree_paths) < count:
            raise ValueError(f"tree corpus has fewer than {count} files")
        cells.append(
            {
                "id": f"tree-{count}x{per_file // MIB}m-default-threads",
                "logical_bytes": count * per_file,
                "file_count": count,
                "args": query_args(
                    tuple(tree_paths[:count]), threads=None, output="quiet"
                ),
            }
        )
    return cells


def run_pair(
    *,
    pair_index: int,
    phase: int,
    binary: Path,
    stock_binary: Path,
    invocation_args: Sequence[str],
    expected_file_count: int,
    cwd: Path,
) -> dict[str, Any]:
    orders = (
        ("normal", "background", "stock"),
        ("background", "stock", "normal"),
        ("stock", "normal", "background"),
        ("background", "normal", "stock"),
        ("normal", "stock", "background"),
        ("stock", "background", "normal"),
    )
    order = orders[(pair_index + phase) % len(orders)]
    results = {}
    for arm in order:
        results[arm] = run_once(
            binary=stock_binary if arm == "stock" else binary,
            args=invocation_args,
            cwd=cwd,
            background=arm == "background",
            expected_file_count=expected_file_count,
        )
    assert_equal(results["normal"], results["background"], "timed pair")
    assert_equal(results["stock"], results["normal"], "timed upstream control")
    return {"pair_index": pair_index, "order": list(order), **results}


def run_benchmark(args: argparse.Namespace) -> None:
    if CORRECTNESS_GATE_ENV in os.environ:
        raise SystemExit(
            f"refusing timing with {CORRECTNESS_GATE_ENV} present; unset it first"
        )
    manifest_path = args.manifest
    manifest = load_manifest(manifest_path)
    verify_corpus(manifest_path, manifest)
    provenance = common_header(args, manifest_path, manifest)
    if provenance["source"]["dirty"]:
        raise SystemExit("refusing formal timing from a dirty source tree")
    checkpoint_path = args.output.with_name(args.output.name + ".partial")
    if checkpoint_path.exists():
        raise SystemExit(f"refusing to replace checkpoint: {checkpoint_path}")
    cells = benchmark_cells(manifest_path, manifest)
    if args.cell:
        requested = set(args.cell)
        known = {cell["id"] for cell in cells}
        if requested - known:
            raise SystemExit(
                "unknown cells: " + ", ".join(sorted(requested - known))
            )
        cells = [cell for cell in cells if cell["id"] in requested]

    rows = []
    for phase, cell in enumerate(cells):
        print(f"{cell['id']}: warmup", flush=True)
        for pair_index in range(args.warmup_pairs):
            run_pair(
                pair_index=pair_index,
                phase=phase,
                binary=args.binary,
                stock_binary=args.stock_binary,
                invocation_args=cell["args"],
                expected_file_count=cell["file_count"],
                cwd=args.cwd,
            )
        samples = [
            run_pair(
                pair_index=pair_index,
                phase=phase,
                binary=args.binary,
                stock_binary=args.stock_binary,
                invocation_args=cell["args"],
                expected_file_count=cell["file_count"],
                cwd=args.cwd,
            )
            for pair_index in range(args.pairs)
        ]
        summary = pair_summary(samples)
        rows.append(
            {
                **cell,
                "args": list(cell["args"]),
                "summary": summary,
                "receipt_summary": receipt_summary(samples),
                "samples": samples,
            }
        )
        write_json_checkpoint(
            checkpoint_path,
            {
                "schema": f"{RESULT_SCHEMA}.benchmark.partial.v1",
                **provenance,
                "started_unix": args.started_unix,
                "completed_cells": rows,
            },
        )
        print(
            f"{cell['id']}: paired normal/background="
            f"{summary['paired_ratio_median']:.3f}x \
             {summary['paired_ratio_descriptive_95pct_interval']}",
            flush=True,
        )

    verify_corpus(manifest_path, manifest)
    post_provenance = common_header(args, manifest_path, manifest)
    if post_provenance != provenance:
        raise RuntimeError("source, dependency, binary, or corpus changed during timing")
    write_json_new(
        args.output,
        {
            "schema": f"{RESULT_SCHEMA}.benchmark.v1",
            "method": {
                "unit": "one ordinary query in one new ripgrep process",
                "pattern": PATTERN,
                "primary": "same candidate flag off versus --fre-aot-background",
                "order": "adjacent alternating AB/BA pairs",
                "pairs": args.pairs,
                "warmup_pairs": args.warmup_pairs,
                "clock": "perf_counter_ns around subprocess through exit and pipe drain",
                "correctness": "literal status/stdout/stderr equality in every pair",
                "aot_cache": "none; every flagged sample compiles in its fresh process",
                "filesystem_cache": "warm OS cache after unrecorded warmup pairs",
                "correctness_gate": "forbidden and scrubbed from child environments",
            },
            **provenance,
            "started_unix": args.started_unix,
            "finished_unix": time.time(),
            "post_run_corpus_verified": True,
            "post_run_provenance_verified": True,
            "cells": rows,
        },
    )
    checkpoint_path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("correctness", "benchmark"):
        child = subparsers.add_parser(mode)
        child.add_argument("--binary", type=Path, required=True)
        child.add_argument("--stock-binary", type=Path, required=True)
        child.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        child.add_argument("--output", type=Path, required=True)
        child.add_argument("--cwd", type=Path, default=REPO)
    benchmark = subparsers.choices["benchmark"]
    benchmark.add_argument("--pairs", type=int, default=15)
    benchmark.add_argument("--warmup-pairs", type=int, default=3)
    benchmark.add_argument("--cell", action="append")
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    args.stock_binary = args.stock_binary.resolve(strict=True)
    args.manifest = args.manifest.resolve(strict=True)
    args.cwd = args.cwd.resolve(strict=True)
    args.output = args.output.resolve()
    args.started_unix = time.time()
    if args.mode == "benchmark" and (args.pairs <= 0 or args.warmup_pairs < 0):
        parser.error("pair counts must be positive/non-negative")
    return args


def main() -> None:
    args = parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to replace result: {args.output}")
    if args.mode == "correctness":
        run_correctness(args)
    else:
        run_benchmark(args)


if __name__ == "__main__":
    main()

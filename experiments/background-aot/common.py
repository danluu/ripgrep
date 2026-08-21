"""Shared workload and receipt definitions for the background FRE AOT experiment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_DATA = HERE / "data"
DEFAULT_MANIFEST = DEFAULT_DATA / "manifest.json"
RECEIPT_ENV = "RG_FRE_AOT_BACKGROUND_RECEIPT"
BACKGROUND_FLAG = "--fre-aot-background"

ORDERED = r"(?:ab|a)"
OVERLAP = (
    r"(?:aaaaaaaaab|aaaaaaaab|aaaaaaab|aaaaaab|aaaaab|aaaab|aaab|aab|ab)"
)
TRACE = r"ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT"
AMBIGUOUS = r"(?:a|aa)*b"
BOUNDED = r"a{0,100}b"

RECEIPT_SCHEMA = "ripgrep.fre-aot-background.v1"
RECEIPT_OUTCOMES = {"ready", "declined", "unfinished"}
RECEIPT_POLICIES = {"observe", "cutover", "declined", "stock-only"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != "ripgrep.fre-aot-background-corpus.v1":
        raise ValueError(f"unsupported corpus manifest schema in {path}")
    return manifest


def corpus_path(manifest_path: Path, relative: str) -> Path:
    return manifest_path.parent / relative


def scenario_paths(
    manifest_path: Path, manifest: dict[str, Any], scenario: str, count: int
) -> list[Path]:
    try:
        rows = manifest["scenarios"][scenario]["files"]
    except KeyError as error:
        raise ValueError(f"manifest has no scenario {scenario!r}") from error
    if count > len(rows):
        raise ValueError(
            f"scenario {scenario!r} has {len(rows)} files, need {count}"
        )
    return [corpus_path(manifest_path, row["path"]) for row in rows[:count]]


def verify_manifest_files(manifest_path: Path, manifest: dict[str, Any]) -> None:
    """Verify every generated file before any benchmark clock starts."""
    seen: set[Path] = set()
    groups: list[dict[str, Any]] = list(manifest["scenarios"].values())
    groups.append(manifest["correctness"])
    for group in groups:
        for row in group["files"]:
            path = corpus_path(manifest_path, row["path"])
            if path in seen:
                continue
            seen.add(path)
            stat = path.stat()
            if stat.st_size != row["bytes"]:
                raise ValueError(
                    f"corpus size mismatch for {path}: {stat.st_size} != {row['bytes']}"
                )
            actual = sha256(path)
            if actual != row["sha256"]:
                raise ValueError(
                    f"corpus digest mismatch for {path}: {actual} != {row['sha256']}"
                )


@dataclass(frozen=True)
class Cell:
    id: str
    class_name: str
    args: tuple[str, ...]
    receipt_policy: str
    logical_bytes: int
    file_count: int
    pattern: str
    scenario: str
    secondary_stock: bool = False


def _count_args(pattern: str, paths: Iterable[Path]) -> tuple[str, ...]:
    return (
        "--no-config",
        "--color=never",
        "--sort=path",
        "--threads=1",
        "--count",
        "--include-zero",
        "--with-filename",
        "--",
        pattern,
        *(str(path) for path in paths),
    )


def _count_matches_args(pattern: str, paths: Iterable[Path]) -> tuple[str, ...]:
    return (
        "--no-config",
        "--color=never",
        "--sort=path",
        "--threads=1",
        "--count-matches",
        "--include-zero",
        "--with-filename",
        "--",
        pattern,
        *(str(path) for path in paths),
    )


def benchmark_cells(manifest_path: Path, manifest: dict[str, Any]) -> list[Cell]:
    """Return the predeclared timing matrix.

    Promotion occurs only between files. The 64 MiB shard is therefore both a
    useful scan unit and the cutover granularity. The one- and two-file
    scaling rows observe publication timing. Whether preparation finishes in
    time to cut over is an experimental result, not a harness precondition.
    """
    shard_bytes = int(manifest["shard_bytes"])
    if shard_bytes % (1024 * 1024) != 0:
        raise ValueError("benchmark shard size must be an integral number of MiB")
    shard_label = f"{shard_bytes // (1024 * 1024)}m"
    cells: list[Cell] = []
    small_row = next(
        row
        for row in manifest["correctness"]["files"]
        if Path(row["path"]).name == "input.txt"
    )
    small_path = corpus_path(manifest_path, small_row["path"])
    cells.append(
        Cell(
            id="tiny-fresh-process-control",
            class_name="startup-and-cancellation-control",
            args=("--no-config", "--count", "--", ORDERED, str(small_path)),
            receipt_policy="observe",
            logical_bytes=int(small_row["bytes"]),
            file_count=1,
            pattern=ORDERED,
            scenario="correctness",
            secondary_stock=True,
        )
    )
    for count in (1, 2, 4, 8, 16):
        paths = scenario_paths(manifest_path, manifest, "a_negative", count)
        cells.append(
            Cell(
                id=f"bounded-negative-{count}x{shard_label}",
                class_name="break-even-scaling",
                args=_count_args(BOUNDED, paths),
                receipt_policy="observe",
                logical_bytes=count * shard_bytes,
                file_count=count,
                pattern=BOUNDED,
                scenario="a_negative",
                secondary_stock=count in (1, 8),
            )
        )

    for cell_id, class_name, scenario, pattern, argument_builder in (
        (
            f"ambiguous-negative-8x{shard_label}",
            "selected-favorable-shape",
            "a_negative",
            AMBIGUOUS,
            _count_args,
        ),
        (
            f"ambiguous-positive-8x{shard_label}",
            "known-sign-reversal-control",
            "a_positive",
            AMBIGUOUS,
            _count_args,
        ),
        (
            f"overlap-mixed-log-8x{shard_label}",
            "modest-fixed-aot-winner",
            "mixed_log",
            OVERLAP,
            _count_matches_args,
        ),
        (
            f"trace-mixed-log-8x{shard_label}",
            "trace-shaped-regression-control",
            "mixed_log",
            TRACE,
            _count_args,
        ),
    ):
        count = 8
        paths = scenario_paths(manifest_path, manifest, scenario, count)
        cells.append(
            Cell(
                id=cell_id,
                class_name=class_name,
                args=argument_builder(pattern, paths),
                receipt_policy="observe",
                logical_bytes=count * shard_bytes,
                file_count=count,
                pattern=pattern,
                scenario=scenario,
                secondary_stock=True,
            )
        )

    default_paths = scenario_paths(manifest_path, manifest, "a_negative", 8)
    cells.append(
        Cell(
            id=f"bounded-negative-default-output-8x{shard_label}",
            class_name="ordinary-default-output-control",
            args=(
                "--no-config",
                "--color=never",
                "--sort=path",
                "--threads=1",
                "--",
                BOUNDED,
                *(str(path) for path in default_paths),
            ),
            receipt_policy="observe",
            logical_bytes=8 * shard_bytes,
            file_count=8,
            pattern=BOUNDED,
            scenario="a_negative",
            secondary_stock=True,
        )
    )

    ignore_case_paths = scenario_paths(manifest_path, manifest, "mixed_log", 8)
    cells.append(
        Cell(
            id=f"ignore-case-declined-8x{shard_label}",
            class_name="synchronous-decline-overhead-control",
            args=(
                "--no-config",
                "--ignore-case",
                "--color=never",
                "--sort=path",
                "--threads=1",
                "--count",
                "--include-zero",
                "--with-filename",
                "--",
                TRACE,
                *(str(path) for path in ignore_case_paths),
            ),
            receipt_policy="declined",
            logical_bytes=8 * shard_bytes,
            file_count=8,
            pattern=TRACE,
            scenario="mixed_log",
            secondary_stock=True,
        )
    )
    if "source_shaped" in manifest["scenarios"]:
        source_paths = scenario_paths(manifest_path, manifest, "source_shaped", 8)
        cells.append(
            Cell(
                id=f"ordered-source-shaped-8x{shard_label}",
                class_name="source-shaped-regression-control",
                args=_count_args(ORDERED, source_paths),
                receipt_policy="observe",
                logical_bytes=8 * shard_bytes,
                file_count=8,
                pattern=ORDERED,
                scenario="source_shaped",
                secondary_stock=True,
            )
        )
    return cells


def _nonnegative_int(receipt: dict[str, Any], name: str) -> int:
    value = receipt.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"receipt field {name!r} is not a non-negative integer")
    return value


def validate_receipt(receipt: dict[str, Any], policy: str = "observe") -> None:
    if policy not in RECEIPT_POLICIES:
        raise ValueError(f"unknown receipt policy {policy!r}")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ValueError(
            f"unexpected receipt schema {receipt.get('schema')!r}; expected {RECEIPT_SCHEMA!r}"
        )
    if receipt.get("direct_native_only") is not True:
        raise ValueError("receipt does not attest the direct-native-only policy")
    outcome = receipt.get("outcome")
    if outcome not in RECEIPT_OUTCOMES:
        raise ValueError(f"unexpected receipt outcome {outcome!r}")

    compile_ns = _nonnegative_int(receipt, "compile_ns")
    prepare_ns = _nonnegative_int(receipt, "prepare_ns")
    if prepare_ns != 0 and prepare_ns < compile_ns:
        raise ValueError("full preparation duration is shorter than FRE compilation")
    ready_ns = receipt.get("ready_ns_since_start")
    if ready_ns is not None and (
        not isinstance(ready_ns, int)
        or isinstance(ready_ns, bool)
        or ready_ns < 0
    ):
        raise ValueError("ready_ns_since_start must be null or non-negative")
    stock_files = _nonnegative_int(receipt, "stock_files")
    fre_files = _nonnegative_int(receipt, "fre_aot_files")
    total = _nonnegative_int(receipt, "total_file_attempts")
    if stock_files + fre_files != total:
        raise ValueError(
            "receipt file accounting does not close: "
            f"{stock_files} stock + {fre_files} FRE != {total} total"
        )

    ordinal = receipt.get("first_cutover_file_ordinal")
    cutover_ns = receipt.get("first_cutover_ns_since_start")
    if fre_files:
        if outcome != "ready":
            raise ValueError("FRE files were reported without a ready outcome")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
            raise ValueError("FRE files require a first cutover file ordinal")
        if ordinal == 0 or ordinal > total:
            raise ValueError("first cutover file ordinal lies outside attempted files")
        if not isinstance(cutover_ns, int) or isinstance(cutover_ns, bool) or cutover_ns < 0:
            raise ValueError("FRE files require a first cutover timestamp")
        if ready_ns is None or ready_ns > cutover_ns:
            raise ValueError("cutover precedes publication readiness")
    elif ordinal is not None or cutover_ns is not None:
        raise ValueError("cutover fields must be null when no file used FRE AOT")

    if outcome == "ready":
        if ready_ns is None:
            raise ValueError("ready outcome has no ready timestamp")
        if prepare_ns == 0:
            raise ValueError("ready outcome has no completed preparation duration")
        if ready_ns < prepare_ns:
            raise ValueError("ready timestamp is shorter than full preparation duration")
    elif ready_ns is not None:
        raise ValueError(f"{outcome} outcome unexpectedly has a ready timestamp")
    if outcome in {"declined", "unfinished"} and fre_files:
        raise ValueError(f"{outcome} outcome cannot report FRE files")

    if policy == "cutover" and not (
        outcome == "ready" and stock_files > 0 and fre_files > 0
    ):
        raise ValueError(
            "cutover cell requires ready outcome and nonzero stock/FRE file counts"
        )
    if policy == "declined" and not (
        outcome == "declined" and stock_files > 0 and fre_files == 0
    ):
        raise ValueError("decline cell did not stay entirely on stock matching")
    if policy == "stock-only" and not (stock_files > 0 and fre_files == 0):
        raise ValueError("stock-only cell reported an FRE AOT file")


def read_receipt(path: Path, policy: str = "observe") -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"background AOT receipt was not published at {path}")
    receipt = json.loads(path.read_text())
    if not isinstance(receipt, dict):
        raise ValueError("background AOT receipt must be a JSON object")
    validate_receipt(receipt, policy)
    return receipt

#!/usr/bin/env python3
"""Probe and benchmark background FRE AOT on frozen actual-query cohorts.

The primary cohort is a result-blind set of 84 out-of-time ripgrep queries
that predates this integration. Public JSON is aggregate-only. Exact patterns
and per-pattern observations are written only to the explicitly ignored
private result.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import resource
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PRIVATE_CORPUS_RELATIVE = Path(
    "private-pattern-corpora/codex-rg-patterns-through-2026-08-21.jsonl"
)
FREEZE_RELATIVE = Path(
    "private-pattern-corpora/training-freeze-receipt-v1.json"
)
BACKGROUND_FLAG = "--fre-aot-background"
RECEIPT_ENV = "RG_FRE_AOT_BACKGROUND_RECEIPT"
CORRECTNESS_GATE_ENV = "RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES"
CPU_PROFILE_ENV = "RG_FRE_AOT_BACKGROUND_CPU_PROFILE"
RECEIPT_SCHEMA = "ripgrep.fre-aot-background.v4"
RESULT_SCHEMA = "ripgrep.fre-aot-representative"
COMPILED_OUTPUT_CONTRACT = "selected_end"
COMPILED_ENTRY_ABI = "selected_end_search_v1"
COMPILED_STATE_SOURCES = frozenset((
    "semantic_dfa", "context_determinization", "slow_aot",
    "compiler_k0_aot", "slow_context_aot", "ordered_finite_language",
))
DFA_COMPILER_ENGINES = frozenset(("ordered_dfa", "ordered_context_dfa"))
NON_DFA_COMPILER_ENGINES = frozenset(("ordered_nfa",))
KNOWN_COMPILER_ENGINES = DFA_COMPILER_ENGINES | NON_DFA_COMPILER_ENGINES
CANDIDATE_DISCOVERY_COUNTER_FIELDS = (
    "candidate_stock_files",
    "candidate_fre_aot_files",
    "candidate_mixed_engine_files",
    "candidate_midscan_cutover_files",
    "candidate_stock_windows",
    "candidate_fre_aot_windows",
    "candidate_stock_window_bytes",
    "candidate_stock_committed_bytes",
    "candidate_fre_aot_window_bytes",
)
FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS = (
    "first_candidate_midscan_cutover_file_ordinal",
    "first_candidate_midscan_cutover_ns_since_start",
    "first_candidate_midscan_cutover_stock_committed_bytes",
)
STOCK_WORK_COUNTER_FIELDS = (
    "stock_span_calls",
    "stock_span_bytes",
    "stock_capture_calls",
    "stock_capture_bytes",
)
FORCED_MIDSCAN_LINE_BYTES = 4096
FORCED_MIDSCAN_FILE_BYTES = 16 * 1024 * 1024
FORCED_MIDSCAN_STOCK_BYTES = 4 * 1024 * 1024
FORCED_MIDSCAN_PATTERN = r"a{0,99}b"
FORCED_MIDSCAN_MARKER_LINES = (
    128,
    FORCED_MIDSCAN_FILE_BYTES // FORCED_MIDSCAN_LINE_BYTES - 1,
)
FORCED_MIDSCAN_CORPUS_SHA256 = (
    "c9e3251528b667620ac9610fce1b4689f3a3cf0d7a0a9d2e6808fe77c8acafaa"
)

EXPECTED_OOT = {
    "window_actions": 161,
    "excluded_threads": 7,
    "excluded_actions": 51,
    "eligible_occurrences": 85,
    "unique_patterns": 84,
    "suffix_patterns": 8,
}
EXPECTED_PRIVATE = {
    "search_command_occurrences": 184_522,
    "static_expression_occurrences": 185_094,
    "unique_exact_expressions": 157_704,
    "unique_expressions_with_nul": 0,
    "source_sha256": (
        "b27818c59a0148a8e3909c2896c6dc1723b9cf880d571ccf0e92cfe6e00c5f15"
    ),
}
OOT_END_UNIX = 1_787_260_642
CPU_PROFILES = ("auto", "asimd", "sve", "sve2")
PANELS = (
    "ripgrep-default-output",
    "fre-count-default-threads",
    "fre-count-thread1",
)


class HarnessError(RuntimeError):
    """A failure whose details must not accidentally print raw history."""


@dataclass(frozen=True)
class QueryCase:
    private_id: str
    cohort: str
    pattern: str
    occurrence_weight: int
    suffix: str | None
    semantics: Mapping[str, Any]
    target_kind: str | None = None
    extension_class: str | None = None


@dataclass(frozen=True)
class Panel:
    id: str
    root: Path
    output_comparison: str
    expected_file_count: int | None
    count_mode: bool
    threads: int | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_module(path: Path, name: str) -> Any:
    scripts = str(path.parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessError("private inventory helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_private_freeze(inventory_root: Path) -> tuple[Path, Mapping[str, Any]]:
    corpus = (inventory_root / PRIVATE_CORPUS_RELATIVE).resolve(strict=True)
    freeze_path = (inventory_root / FREEZE_RELATIVE).resolve(strict=True)
    freeze = json.loads(freeze_path.read_text())
    if (
        freeze.get("schema") != "rg_aot_private_training_freeze"
        or freeze.get("schema_version") != 1
        or freeze.get("source_sha256") != EXPECTED_PRIVATE["source_sha256"]
        or freeze.get("counts", {}).get("search_command_occurrences")
        != EXPECTED_PRIVATE["search_command_occurrences"]
        or freeze.get("counts", {}).get("static_expression_occurrences")
        != EXPECTED_PRIVATE["static_expression_occurrences"]
        or freeze.get("counts", {}).get("unique_exact_expressions")
        != EXPECTED_PRIVATE["unique_exact_expressions"]
        or sha256_file(corpus) != EXPECTED_PRIVATE["source_sha256"]
    ):
        raise HarnessError("private inventory does not match its frozen receipt")
    return corpus, freeze


def load_oot_cases(inventory_root: Path, database: Path) -> list[QueryCase]:
    helper = load_module(
        inventory_root / "scripts" / "benchmark_holdout.py",
        "rg_aot_representative_oot",
    )
    seen, raw = helper.load_history_window(database, end_unix=OOT_END_UNIX)
    selected, exclusions, excluded_threads = helper.select_base_actions(
        raw,
        seen,
        project_root=inventory_root,
        strict_targets=False,
    )
    if (
        len(raw) != EXPECTED_OOT["window_actions"]
        or excluded_threads != EXPECTED_OOT["excluded_threads"]
        or exclusions["task_associated_thread"]
        != EXPECTED_OOT["excluded_actions"]
        or len(selected) != EXPECTED_OOT["eligible_occurrences"]
    ):
        raise HarnessError("frozen OOT selection counts do not reconcile")
    weights = Counter(action.query for action in selected)
    unique = helper.deduplicate_chronologically(selected, exclusions)
    if (
        len(unique) != EXPECTED_OOT["unique_patterns"]
        or sum(action.include_suffix is not None for action in unique)
        != EXPECTED_OOT["suffix_patterns"]
    ):
        raise HarnessError("frozen OOT unique cohort does not reconcile")
    semantics = {
        "matcher_mode": "regex",
        "regex_engine_request": "default",
        "case": "case_sensitive",
        "multiline": False,
        "multiline_dotall": False,
        "word_regexp": False,
        "invert_match": False,
        "unicode": True,
        "crlf": False,
        "command_flag_parse_fallback": False,
    }
    return [
        QueryCase(
            private_id=f"oot-{index:04d}",
            cohort="frozen-oot-84",
            pattern=action.query,
            occurrence_weight=weights[action.query],
            suffix=action.include_suffix,
            semantics=semantics,
        )
        for index, action in enumerate(unique, 1)
    ]


def load_wider_sample(
    inventory_root: Path,
    corpus: Path,
    *,
    excluded_patterns: set[str],
    sample_size: int,
    seed: int,
) -> list[QueryCase]:
    if sample_size == 0:
        return []
    helper = load_module(
        inventory_root / "scripts" / "private_pattern_corpus.py",
        "rg_aot_representative_private_corpus",
    )
    rows: dict[str, list[Any]] = {}
    expression_count = 0
    for occurrence in helper._read_occurrences(corpus):
        semantics = occurrence.get("semantics")
        if not isinstance(semantics, Mapping):
            semantics = {}
        for expression in occurrence["expressions"]:
            expression_count += 1
            pattern = expression["pattern"]
            prior = rows.get(pattern)
            if prior is None:
                rows[pattern] = [
                    1,
                    dict(semantics),
                    occurrence.get("target_kind"),
                    occurrence.get("extension_class"),
                ]
            else:
                prior[0] += 1
    if (
        expression_count != EXPECTED_PRIVATE["static_expression_occurrences"]
        or len(rows) != EXPECTED_PRIVATE["unique_exact_expressions"]
    ):
        raise HarnessError("wider private inventory counts do not reconcile")
    if (
        sum("\x00" in pattern for pattern in rows)
        != EXPECTED_PRIVATE["unique_expressions_with_nul"]
    ):
        raise HarnessError("frozen inventory argv transport audit changed")
    pool = [pattern for pattern in rows if pattern not in excluded_patterns]
    if sample_size > len(pool):
        raise HarnessError("wider sample exceeds the frozen unique-pattern pool")
    indices = sorted(random.Random(seed).sample(range(len(pool)), sample_size))
    result = []
    for ordinal, index in enumerate(indices, 1):
        pattern = pool[index]
        weight, semantics, target_kind, extension_class = rows[pattern]
        result.append(
            QueryCase(
                private_id=f"wider-{ordinal:04d}",
                cohort=f"frozen-unique-sample-{sample_size}",
                pattern=pattern,
                occurrence_weight=int(weight),
                suffix=None,
                semantics=semantics,
                target_kind=(
                    str(target_kind) if target_kind is not None else None
                ),
                extension_class=(
                    str(extension_class)
                    if extension_class is not None else None
                ),
            )
        )
    return result


def git_text(repo: Path, args: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessError("git provenance check failed")
    return completed.stdout.strip()


def git_record(repo: Path) -> dict[str, Any]:
    commit = git_text(repo, ("rev-parse", "HEAD"))
    tree = git_text(repo, ("rev-parse", "HEAD^{tree}"))
    status = git_text(repo, ("status", "--short"))
    return {
        "commit": commit,
        "tree": tree,
        "clean": not status,
    }


def binary_record(path: Path) -> dict[str, str]:
    completed = subprocess.run(
        [str(path), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessError("binary provenance check failed")
    return {
        "sha256": sha256_file(path),
        "version": completed.stdout.strip(),
    }


def command_version(command: str) -> str:
    completed = subprocess.run(
        [command, "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessError("toolchain provenance check failed")
    return completed.stdout.strip()


def load_snapshot() -> dict[str, Any]:
    try:
        load = list(os.getloadavg())
    except OSError:
        load = None
    return {
        "utc": datetime.now(timezone.utc).isoformat(),
        "unix_ns": time.time_ns(),
        "load_average_1m_5m_15m": load,
    }


def sve_vector_length_bytes() -> int | None:
    if platform.system() != "Linux" or platform.machine() not in (
        "aarch64", "arm64",
    ):
        return None
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        value = int(libc.prctl(51, 0, 0, 0, 0))  # PR_SVE_GET_VL
        if value < 0:
            return None
        return value & 0xFFFF  # PR_SVE_VL_LEN_MASK
    except (AttributeError, OSError, ValueError):
        return None


def verify_binary_source(binary: Mapping[str, str], source: Mapping[str, Any]) -> None:
    if not source["clean"]:
        raise HarnessError("formal source worktree is dirty")
    revision = str(source["commit"])[:10]
    if f"(rev {revision})" not in binary["version"]:
        raise HarnessError("binary revision does not match source")


def fre_dependency_record(candidate_source: Path) -> dict[str, Any]:
    manifest = candidate_source / "Cargo.toml"
    lockfile = candidate_source / "Cargo.lock"
    manifest_text = manifest.read_text()
    lock_text = lockfile.read_text()
    manifest_revisions = set(re.findall(
        r'^fre-[A-Za-z0-9_-]+\s*=\s*\{[^\n]*\brev\s*=\s*"([0-9a-f]{40})"',
        manifest_text,
        flags=re.MULTILINE,
    ))
    locked_revisions = re.findall(
        r'^source = "git\+https://github\.com/danluu/fre\.git[^"#]*#([0-9a-f]{40})"$',
        lock_text,
        flags=re.MULTILINE,
    )
    if len(manifest_revisions) != 1 or not locked_revisions:
        raise HarnessError("candidate FRE dependency provenance is ambiguous")
    locked_unique = set(locked_revisions)
    if locked_unique != manifest_revisions:
        raise HarnessError("candidate FRE manifest and lock revisions differ")
    revision = next(iter(manifest_revisions))
    return {
        "source": "https://github.com/danluu/fre.git",
        "manifest_revision": revision,
        "locked_revision": revision,
        "locked_package_count": len(locked_revisions),
        "cargo_toml_sha256": sha256_file(manifest),
        "cargo_lock_sha256": sha256_file(lockfile),
    }


def materialize_git_archive(repo: Path, commit: str, destination: Path) -> dict[str, Any]:
    resolved = git_text(repo, ("rev-parse", f"{commit}^{{commit}}"))
    tree = git_text(repo, ("rev-parse", f"{commit}^{{tree}}"))
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryFile() as archive:
        completed = subprocess.run(
            ["git", "archive", "--format=tar", resolved],
            cwd=repo,
            stdout=archive,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode != 0:
            raise HarnessError("could not materialize frozen source corpus")
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as source:
            source.extractall(destination, filter="data")
    files = [path for path in destination.rglob("*") if path.is_file()]
    return {
        "commit": resolved,
        "tree": tree,
        "file_count": len(files),
        "total_file_bytes": sum(path.stat().st_size for path in files),
    }


def query_shape(pattern: str) -> dict[str, Any]:
    escaped = False
    in_class = False
    alternations = 0
    features = {
        "anchored": False,
        "dotstar": False,
        "grouped": False,
        "escaped": False,
        "character_class": False,
        "plainish": True,
    }
    index = 0
    has_syntax = False
    while index < len(pattern):
        char = pattern[index]
        if escaped:
            features["escaped"] = True
            escaped = False
        elif char == "\\":
            escaped = True
            has_syntax = True
        elif in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
            features["character_class"] = True
            has_syntax = True
        elif char == "|":
            alternations += 1
            has_syntax = True
        elif char in "^$":
            features["anchored"] = True
            has_syntax = True
        elif char == "(":
            features["grouped"] = True
            has_syntax = True
        elif char == "." and index + 1 < len(pattern) and pattern[index + 1] == "*":
            features["dotstar"] = True
            has_syntax = True
        elif char in ".*+?{}":
            has_syntax = True
        index += 1
    features["plainish"] = not has_syntax
    return {"length": len(pattern), "alternations": alternations, **features}


def length_bucket(length: int) -> str:
    if length < 32:
        return "short_lt_32"
    if length < 128:
        return "medium_32_127"
    return "long_ge_128"


def arm_bucket(alternations: int) -> str:
    arms = alternations + 1
    if arms == 1:
        return "1_arm"
    if arms == 2:
        return "2_arms"
    if arms <= 5:
        return "3_5_arms"
    if arms <= 16:
        return "6_16_arms"
    return "gt_16_arms"


def cohort_profile(cases: Sequence[QueryCase]) -> dict[str, Any]:
    lengths = Counter()
    arms = Counter()
    features = Counter()
    semantics: dict[str, Counter[str]] = {
        "matcher_mode": Counter(),
        "regex_engine_request": Counter(),
        "case": Counter(),
    }
    booleans = (
        "multiline",
        "multiline_dotall",
        "word_regexp",
        "invert_match",
        "unicode",
        "crlf",
        "command_flag_parse_fallback",
    )
    boolean_counts = {field: Counter() for field in booleans}
    target_kinds = Counter()
    extension_classes = Counter()
    normalization_counts = Counter()
    for case in cases:
        shape = query_shape(case.pattern)
        lengths[length_bucket(shape["length"])] += 1
        arms[arm_bucket(shape["alternations"])] += 1
        for field in (
            "anchored", "dotstar", "grouped", "escaped",
            "character_class", "plainish",
        ):
            features[field] += int(shape[field])
        for field in semantics:
            value = case.semantics.get(field, "unknown")
            semantics[field][str(value)] += 1
        for field in booleans:
            value = case.semantics.get(field)
            key = "true" if value is True else "false" if value is False else "unknown"
            boolean_counts[field][key] += 1
        target_kinds[str(case.target_kind or "unavailable")] += 1
        extension_classes[str(case.extension_class or "unavailable")] += 1
        _, notes = profile_flags(case)
        if notes:
            normalization_counts.update(notes)
            normalization_counts["patterns_with_normalization"] += 1
        else:
            normalization_counts["patterns_without_normalization"] += 1
    return {
        "unique_patterns": len(cases),
        "occurrence_weight": sum(case.occurrence_weight for case in cases),
        "suffix_filtered_patterns": sum(case.suffix is not None for case in cases),
        "length_buckets": dict(sorted(lengths.items())),
        "alternation_arms": dict(sorted(arms.items())),
        "syntax_feature_counts": dict(sorted(features.items())),
        "target_kinds": dict(sorted(target_kinds.items())),
        "extension_classes": dict(sorted(extension_classes.items())),
        "normalization_counts": dict(sorted(normalization_counts.items())),
        "semantics": {
            **{field: dict(sorted(values.items())) for field, values in semantics.items()},
            **{field: dict(sorted(values.items())) for field, values in boolean_counts.items()},
        },
    }


def profile_flags(case: QueryCase) -> tuple[list[str], list[str]]:
    """Return normalized CLI flags and raw-free normalization labels."""
    semantics = case.semantics
    flags: list[str] = []
    notes: list[str] = []
    if semantics.get("matcher_mode") == "fixed_strings":
        flags.append("--fixed-strings")
    engine = semantics.get("regex_engine_request")
    if engine not in (None, "ripgrep_default", "default"):
        notes.append("engine_request_normalized_to_default")
    case_mode = semantics.get("case")
    if case_mode == "ignore_case":
        flags.append("--ignore-case")
    elif case_mode == "smart_case":
        flags.append("--smart-case")
    elif case_mode == "multiple_case_flags":
        notes.append("multiple_case_flags_normalized_to_default")
    if semantics.get("multiline") is True:
        flags.append("--multiline")
    if semantics.get("multiline_dotall") is True:
        flags.append("--multiline-dotall")
    if semantics.get("word_regexp") is True:
        flags.append("--word-regexp")
    if semantics.get("invert_match") is True:
        flags.append("--invert-match")
    if semantics.get("unicode") is False:
        flags.append("--no-unicode")
    if semantics.get("crlf") is True:
        flags.append("--crlf")
    if semantics.get("command_flag_parse_fallback") is True:
        notes.append("historical_flag_parse_fallback")
    return flags, notes


def query_args(case: QueryCase, panel: Panel) -> tuple[list[str], list[str]]:
    flags, notes = profile_flags(case)
    args = [
        "--no-config", "--engine=default", "--hidden", "--no-ignore",
        "--text", "--color=never", "--no-heading", "--with-filename",
    ]
    if panel.count_mode:
        args.extend(("--count", "--include-zero"))
    else:
        args.append("--line-number")
    if panel.threads is not None:
        args.append(f"--threads={panel.threads}")
    args.extend(flags)
    if case.suffix is not None:
        args.extend(("--glob", f"*{case.suffix}"))
    args.extend(("--", case.pattern, str(panel.root)))
    return args, notes


def output_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def lf_records(data: bytes) -> list[bytes]:
    return sorted(data.splitlines(keepends=True))


def semantic_stdout_sha256(data: bytes, mode: str) -> str:
    if mode == "literal":
        return hashlib.sha256(data).hexdigest()
    if mode != "unordered_lf_records":
        raise HarnessError("unknown output comparison mode")
    digest = hashlib.sha256()
    for record in lf_records(data):
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return digest.hexdigest()


def comparison_record(result: Mapping[str, Any], mode: str) -> dict[str, Any]:
    return {
        "status": result["status"],
        "stderr_sha256": result["stderr"]["sha256"],
        "semantic_stdout_sha256": semantic_stdout_sha256(
            result["stdout_raw"], mode
        ),
    }


def comparison_records_equal(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> bool:
    return left == right


def outputs_equal(left: Mapping[str, Any], right: Mapping[str, Any], mode: str) -> bool:
    if left["status"] != right["status"] or left["stderr_raw"] != right["stderr_raw"]:
        return False
    if mode == "literal":
        return left["stdout_raw"] == right["stdout_raw"]
    if mode == "unordered_lf_records":
        return lf_records(left["stdout_raw"]) == lf_records(right["stdout_raw"])
    raise HarnessError("unknown output comparison mode")


def elapsed_child_cpu(before: resource.struct_rusage, after: resource.struct_rusage) -> dict[str, int]:
    return {
        "user_ns": round((after.ru_utime - before.ru_utime) * 1_000_000_000),
        "system_ns": round((after.ru_stime - before.ru_stime) * 1_000_000_000),
    }


def run_once(
    *,
    binary: Path,
    args: Sequence[str],
    cwd: Path,
    background: bool,
    capture_receipt: bool,
    cpu_profile: str,
    timeout_seconds: float,
    test_min_stock_bytes: int = 0,
) -> dict[str, Any]:
    command = [str(binary)]
    if background:
        command.append(BACKGROUND_FLAG)
    command.extend(args)
    with tempfile.TemporaryDirectory(prefix="rg-fre-representative-run-") as text:
        temporary = Path(text)
        receipt_path = temporary / "receipt.json"
        environment = os.environ.copy()
        environment.pop(RECEIPT_ENV, None)
        environment.pop(CORRECTNESS_GATE_ENV, None)
        environment.pop(CPU_PROFILE_ENV, None)
        environment.pop("RIPGREP_CONFIG_PATH", None)
        environment["LC_ALL"] = "C"
        environment["TMPDIR"] = str(temporary)
        if background:
            environment[CPU_PROFILE_ENV] = cpu_profile
            if capture_receipt:
                environment[RECEIPT_ENV] = str(receipt_path)
            if test_min_stock_bytes > 0:
                environment[CORRECTNESS_GATE_ENV] = str(
                    test_min_stock_bytes
                )
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter_ns()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout_seconds,
            )
            timed_out = False
            stdout = completed.stdout
            stderr = completed.stderr
            status = completed.returncode
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            status = None
        elapsed_ns = time.perf_counter_ns() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        receipt = None
        receipt_parse_error = False
        if receipt_path.is_file():
            try:
                parsed_receipt = json.loads(receipt_path.read_text())
                if isinstance(parsed_receipt, Mapping):
                    receipt = parsed_receipt
                else:
                    receipt_parse_error = True
            except (OSError, UnicodeError, json.JSONDecodeError):
                receipt_parse_error = True
        entries = {path.name for path in temporary.iterdir()}
        allowed = {"receipt.json"} if receipt is not None else set()
        unexpected_artifacts = entries - allowed
        if unexpected_artifacts and not timed_out and not receipt_parse_error:
            raise HarnessError("child left an unexpected temporary artifact")
    return {
        "elapsed_ns": elapsed_ns,
        **elapsed_child_cpu(before, after),
        "timed_out": timed_out,
        "status": status,
        "stdout": output_record(stdout),
        "stderr": output_record(stderr),
        "stdout_raw": stdout,
        "stderr_raw": stderr,
        "receipt": receipt,
        "receipt_parse_error": receipt_parse_error,
        "unexpected_temporary_artifacts": len(unexpected_artifacts),
    }


def receipt_decline_class(receipt: Mapping[str, Any] | None) -> str:
    if receipt is None:
        return "no_receipt"
    outcome = receipt.get("outcome")
    if outcome != "declined":
        return str(outcome) if outcome in ("ready", "unfinished") else "invalid"
    refusal = receipt.get("publication_refusal_class")
    stage = receipt.get("publication_stage")
    if isinstance(refusal, str) and refusal:
        stable_stage = (
            re.sub(r"[^a-z0-9]+", "_", stage.lower()).strip("_")
            if isinstance(stage, str) and stage else "unknown_stage"
        )
        stable_refusal = re.sub(
            r"[^a-z0-9]+", "_", refusal.lower()
        ).strip("_")
        return f"{stable_stage}__{stable_refusal}"
    reason = receipt.get("decline_reason")
    if not isinstance(reason, str):
        return "declined_unknown"
    profile_reasons = {
        "multiple patterns", "case mode other than case-sensitive",
        "word or line boundary mode", "fixed-string rewriting",
        "multiline mode", "CRLF mode", "NUL line terminators",
        "Unicode-disabled syntax",
    }
    if reason in profile_reasons:
        return "profile_" + re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")
    lowered = reason.lower()
    if "runtime helper" in lowered:
        return "publication_runtime_helper_required"
    if reason.startswith("FRE optimizing-AOT compile:"):
        return "compiler_declined"
    if reason.startswith("publish FRE AOT in process:"):
        return "publication_refused"
    if "spawn" in lowered and "compiler thread" in lowered:
        return "compiler_thread_spawn_failed"
    if "cancelled" in lowered:
        return "cancelled"
    return "declined_other_redacted"


def validate_receipt(
    receipt: Mapping[str, Any] | None,
    requested_cpu_profile: str,
    expected_test_min_stock_bytes: int = 0,
) -> list[str]:
    failures = []
    if receipt is None:
        return ["missing_receipt"]
    if not isinstance(receipt, Mapping):
        return ["receipt_not_object"]
    if receipt.get("schema") != RECEIPT_SCHEMA:
        failures.append("schema")
    if receipt.get("direct_native_only") is not True:
        failures.append("not_direct_native")
    if receipt.get("outcome") not in ("ready", "declined", "unfinished"):
        failures.append("invalid_outcome")
    for field in (
        "compile_ns", "publish_ns", "prepare_ns", "total_file_attempts",
        "native_call_failures", "external_linker_invocations",
        "test_min_stock_bytes", *CANDIDATE_DISCOVERY_COUNTER_FIELDS,
        *STOCK_WORK_COUNTER_FIELDS,
    ):
        value = receipt.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            failures.append(f"invalid_{field}")
    if receipt.get("external_linker_invocations") != 0:
        failures.append("external_linker")
    if receipt.get("test_min_stock_bytes") != expected_test_min_stock_bytes:
        failures.append("test_gate_mismatch")
    if receipt.get("native_call_failures") != 0:
        failures.append("native_call_failure")
    cutover_values = []
    for field in FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS:
        if field not in receipt:
            failures.append(f"missing_{field}")
            continue
        value = receipt.get(field)
        cutover_values.append(value)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            failures.append(f"invalid_{field}")
    if len(cutover_values) == len(FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS):
        reported = [value is not None for value in cutover_values]
        if any(reported) and not all(reported):
            failures.append("incomplete_first_candidate_midscan_cutover")
    counters = {
        field: receipt.get(field)
        for field in (*CANDIDATE_DISCOVERY_COUNTER_FIELDS, "total_file_attempts")
    }
    if all(
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        for value in counters.values()
    ):
        total_files = counters["total_file_attempts"]
        stock_files = counters["candidate_stock_files"]
        aot_files = counters["candidate_fre_aot_files"]
        mixed_files = counters["candidate_mixed_engine_files"]
        midscan_files = counters["candidate_midscan_cutover_files"]
        stock_windows = counters["candidate_stock_windows"]
        aot_windows = counters["candidate_fre_aot_windows"]
        stock_window_bytes = counters["candidate_stock_window_bytes"]
        stock_committed_bytes = counters["candidate_stock_committed_bytes"]
        aot_window_bytes = counters["candidate_fre_aot_window_bytes"]
        if stock_files > total_files or aot_files > total_files:
            failures.append("candidate_file_count_exceeds_attempts")
        if mixed_files > min(stock_files, aot_files):
            failures.append("candidate_mixed_file_count_impossible")
        minimum_mixed = max(0, stock_files + aot_files - total_files)
        if mixed_files < minimum_mixed:
            failures.append("candidate_mixed_file_count_below_intersection")
        if midscan_files > mixed_files:
            failures.append("candidate_midscan_file_count_impossible")
        if (stock_files == 0) != (stock_windows == 0):
            failures.append("candidate_stock_file_window_mismatch")
        if (aot_files == 0) != (aot_windows == 0):
            failures.append("candidate_aot_file_window_mismatch")
        if stock_files > stock_windows or aot_files > aot_windows:
            failures.append("candidate_file_count_exceeds_windows")
        if (stock_windows == 0) != (stock_window_bytes == 0):
            failures.append("candidate_stock_window_byte_mismatch")
        if (aot_windows == 0) != (aot_window_bytes == 0):
            failures.append("candidate_aot_window_byte_mismatch")
        if mixed_files > 0 and (stock_windows == 0 or aot_windows == 0):
            failures.append("candidate_mixed_without_both_window_families")
        if stock_committed_bytes > stock_window_bytes:
            failures.append("candidate_committed_bytes_exceed_stock_windows")
        first_reported = (
            len(cutover_values)
            == len(FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS)
            and all(value is not None for value in cutover_values)
        )
        if (midscan_files > 0) != first_reported:
            failures.append("candidate_midscan_first_witness_mismatch")
        if first_reported:
            ordinal, cutover_ns, committed_before = cutover_values
            if ordinal == 0 or ordinal > total_files:
                failures.append("candidate_midscan_file_ordinal_out_of_range")
            if committed_before == 0 or committed_before > stock_committed_bytes:
                failures.append("candidate_midscan_committed_bytes_out_of_range")
            ready_ns = receipt.get("ready_ns_since_start")
            if isinstance(ready_ns, int) and cutover_ns < ready_ns:
                failures.append("candidate_midscan_precedes_publication")
    selected_profile = receipt.get("target_feature_profile")
    if selected_profile != requested_cpu_profile:
        failures.append("target_profile_mismatch")
    if not isinstance(receipt.get("publication_stage"), str):
        failures.append("invalid_publication_stage")
    if not isinstance(receipt.get("runtime_helper_required"), bool):
        failures.append("invalid_runtime_helper_required")
    compiled_fields = (
        "compiled_output_contract", "compiled_entry_abi",
        "compiled_state_source",
        "compiled_forward_states", "compiled_reverse_states",
        "compiled_reverse_start_recovery",
    )
    for field in compiled_fields:
        if field not in receipt:
            failures.append(f"missing_{field}")
    compiled_output_contract = receipt.get("compiled_output_contract")
    compiled_entry_abi = receipt.get("compiled_entry_abi")
    compiled_state_source = receipt.get("compiled_state_source")
    compiled_forward_states = receipt.get("compiled_forward_states")
    compiled_reverse_states = receipt.get("compiled_reverse_states")
    compiled_reverse_start_recovery = receipt.get(
        "compiled_reverse_start_recovery"
    )
    if (
        compiled_output_contract is not None
        and compiled_output_contract != COMPILED_OUTPUT_CONTRACT
    ):
        failures.append("invalid_compiled_output_contract")
    if (
        compiled_entry_abi is not None
        and compiled_entry_abi != COMPILED_ENTRY_ABI
    ):
        failures.append("invalid_compiled_entry_abi")
    if (
        compiled_state_source is not None
        and compiled_state_source not in COMPILED_STATE_SOURCES
    ):
        failures.append("invalid_compiled_state_source")
    for field, value in (
        ("compiled_forward_states", compiled_forward_states),
        ("compiled_reverse_states", compiled_reverse_states),
    ):
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            failures.append(f"invalid_{field}")
    if compiled_reverse_start_recovery is not None and not isinstance(
        compiled_reverse_start_recovery, bool
    ):
        failures.append("invalid_compiled_reverse_start_recovery")
    compiler_engine = receipt.get("compiler_engine")
    if (
        compiler_engine is not None
        and compiler_engine not in KNOWN_COMPILER_ENGINES
    ):
        failures.append("invalid_compiler_engine")
    if compiler_engine is None:
        if any(receipt.get(field) is not None for field in compiled_fields):
            failures.append("compiled_metadata_without_compiler_engine")
    elif compiler_engine in KNOWN_COMPILER_ENGINES:
        if compiled_output_contract != COMPILED_OUTPUT_CONTRACT:
            failures.append("compiled_output_contract_not_selected_end")
        if compiled_entry_abi != COMPILED_ENTRY_ABI:
            failures.append("compiled_entry_abi_not_selected_end_search_v1")
        if compiler_engine in DFA_COMPILER_ENGINES:
            if compiled_forward_states is None:
                failures.append("missing_compiled_forward_states")
            if compiled_reverse_states is None:
                failures.append("missing_compiled_reverse_states")
        # An OrderedNfa semantic program can still select a complete slow-DFA,
        # compiler-K0 or contextual-DFA native sidecar. Its selected machine
        # geometry is therefore either an integer pair or an absent pair.
        if (compiled_forward_states is None) != (
            compiled_reverse_states is None
        ):
            failures.append("incomplete_compiled_state_geometry")
        states_reported = compiled_forward_states is not None
        if states_reported != (compiled_state_source is not None):
            failures.append("compiled_state_source_geometry_mismatch")
        if compiled_forward_states == 0:
            failures.append("compiled_forward_states_zero")
        if compiled_reverse_start_recovery is not False:
            failures.append("selected_end_reverse_start_recovery_present")
    for field in (
        "requested_target_feature_bits", "host_target_feature_bits",
        "target_feature_bits", "published_code_bytes",
        "published_read_only_data_bytes", "published_total_mapped_bytes",
        "ready_ns_since_start",
    ):
        value = receipt.get(field)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            failures.append(f"invalid_{field}")
    requested_bits = receipt.get("requested_target_feature_bits")
    host_bits = receipt.get("host_target_feature_bits")
    target_bits = receipt.get("target_feature_bits")
    stage = receipt.get("publication_stage")
    outcome = receipt.get("outcome")
    expected_fixed_bits = {
        "asimd": 1 << 32,
        "sve": 1 << 33,
        "sve2": (1 << 33) | (1 << 34),
    }.get(requested_cpu_profile)
    if expected_fixed_bits is not None and requested_bits != expected_fixed_bits:
        failures.append("requested_target_feature_bits_mismatch")
    allow_pre_detection = stage == "profile_gate" or (
        outcome == "unfinished"
        and stage in ("not_started", "target_detection")
    )
    host_is_int = isinstance(host_bits, int) and not isinstance(host_bits, bool)
    requested_is_int = (
        isinstance(requested_bits, int)
        and not isinstance(requested_bits, bool)
    )
    target_is_int = (
        isinstance(target_bits, int) and not isinstance(target_bits, bool)
    )
    if not allow_pre_detection:
        if not host_is_int:
            failures.append("missing_host_target_feature_bits")
        if not requested_is_int:
            failures.append("missing_requested_target_feature_bits")
        if not target_is_int:
            failures.append("missing_effective_target_feature_bits")
    if requested_cpu_profile == "auto":
        if host_is_int and requested_bits != host_bits:
            failures.append("auto_target_feature_bits_mismatch")
        elif requested_bits is not None and not host_is_int:
            failures.append("auto_target_feature_bits_without_host")
    if host_is_int and requested_is_int and host_bits & requested_bits != requested_bits:
        failures.append("requested_target_features_unavailable")
    if target_bits is not None and target_bits != requested_bits:
        failures.append("effective_target_feature_bits_mismatch")
    if receipt.get("outcome") == "ready":
        for field in (
            "target_feature_bits", "compiler_engine",
            "engine_selection_reason", "start_accelerator",
            "compiled_output_contract", "compiled_entry_abi",
            "published_code_bytes", "published_read_only_data_bytes",
            "published_total_mapped_bytes", "ready_ns_since_start",
        ):
            if receipt.get(field) is None:
                failures.append(f"ready_missing_{field}")
        if receipt.get("publication_stage") != "published":
            failures.append("ready_not_published")
        if receipt.get("publication_refusal_class") is not None:
            failures.append("ready_with_publication_refusal")
    if receipt.get("outcome") == "declined" and not isinstance(
        receipt.get("publication_refusal_class"), str
    ):
        failures.append("declined_without_publication_refusal_class")
    return failures


def target_receipt_qualification(
    receipt: Mapping[str, Any] | None,
    requested_cpu_profile: str,
) -> tuple[bool, int | None]:
    if receipt is None or receipt.get("target_feature_profile") != requested_cpu_profile:
        return False, None
    requested = receipt.get("requested_target_feature_bits")
    host = receipt.get("host_target_feature_bits")
    target = receipt.get("target_feature_bits")
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in (requested, host, target)
    ):
        return False, None
    expected = {
        "asimd": 1 << 32,
        "sve": 1 << 33,
        "sve2": (1 << 33) | (1 << 34),
    }.get(requested_cpu_profile)
    if expected is not None and requested != expected:
        return False, None
    if requested_cpu_profile == "auto" and requested != host:
        return False, None
    if host & requested != requested or target != requested:
        return False, None
    refusal = receipt.get("publication_refusal_class")
    if refusal in (
        "target_profile_unavailable", "target_profile_invalid",
        "target_profile_architecture_mismatch", "unsupported_host",
        "target_mismatch", "cpu_feature_unavailable",
    ):
        return False, None
    return True, host


def target_validation_matrix(
    rows: Sequence[Mapping[str, Any]],
    requested_profiles: Sequence[str],
) -> dict[str, Any]:
    per_profile: dict[str, Any] = {}
    all_hosts: set[int] = set()
    for profile in requested_profiles:
        receipts = [
            row["background"].get("receipt")
            for row in rows
            if row.get("cpu_profile") == profile
        ]
        qualified_hosts = []
        for receipt in receipts:
            qualified, host = target_receipt_qualification(receipt, profile)
            if qualified and host is not None:
                qualified_hosts.append(host)
                all_hosts.add(host)
        per_profile[profile] = {
            "receipt_count": sum(receipt is not None for receipt in receipts),
            "fully_target_validated_receipts": len(qualified_hosts),
            "qualified_host_feature_bits": sorted(
                f"0x{value:x}" for value in set(qualified_hosts)
            ),
            "qualified": bool(qualified_hosts),
        }
    return {
        "per_profile": per_profile,
        "global_qualified_host_feature_bits": sorted(
            f"0x{value:x}" for value in all_hosts
        ),
        "qualified": (
            all(entry["qualified"] for entry in per_profile.values())
            and len(all_hosts) == 1
        ),
    }


def route_class(receipt: Mapping[str, Any] | None) -> str:
    if receipt is None:
        return "no_receipt"
    stock_windows = receipt.get("candidate_stock_windows")
    aot_windows = receipt.get("candidate_fre_aot_windows")
    mixed_files = receipt.get("candidate_mixed_engine_files")
    midscan_files = receipt.get("candidate_midscan_cutover_files")
    stock = (
        isinstance(stock_windows, int)
        and not isinstance(stock_windows, bool)
        and stock_windows > 0
    )
    aot = (
        isinstance(aot_windows, int)
        and not isinstance(aot_windows, bool)
        and aot_windows > 0
    )
    if (
        isinstance(midscan_files, int)
        and not isinstance(midscan_files, bool)
        and midscan_files > 0
    ):
        return "same_file_midscan_cutover"
    if (
        isinstance(mixed_files, int)
        and not isinstance(mixed_files, bool)
        and mixed_files > 0
    ):
        return "same_file_operation_mix"
    if stock and aot:
        return "cross_file_split"
    if aot:
        return "aot_only"
    if stock:
        return "stock_only"
    return "no_candidate_windows"


def compact_private(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: result[key]
        for key in (
            "elapsed_ns", "user_ns", "system_ns", "timed_out", "status",
            "stdout", "stderr", "receipt",
            "receipt_parse_error", "unexpected_temporary_artifacts",
        )
    }


def probe_one(
    case: QueryCase,
    panel: Panel,
    *,
    candidate: Path,
    stock: Path,
    cwd: Path,
    cpu_profile: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    args, normalization = query_args(case, panel)
    normal = run_once(
        binary=candidate, args=args, cwd=cwd, background=False,
        capture_receipt=False,
        cpu_profile=cpu_profile, timeout_seconds=timeout_seconds,
    )
    background = run_once(
        binary=candidate, args=args, cwd=cwd, background=True,
        capture_receipt=True,
        cpu_profile=cpu_profile, timeout_seconds=timeout_seconds,
    )
    stock_result = run_once(
        binary=stock, args=args, cwd=cwd, background=False,
        capture_receipt=False,
        cpu_profile=cpu_profile, timeout_seconds=timeout_seconds,
    )
    exact_normal_background = outputs_equal(normal, background, panel.output_comparison)
    exact_stock_normal = outputs_equal(stock_result, normal, panel.output_comparison)
    failures = probe_receipt_failures(normal, background, cpu_profile)
    return {
        "query_argv_after_binary": list(args),
        "normalization": normalization,
        "exact_normal_background": exact_normal_background,
        "exact_stock_normal": exact_stock_normal,
        "receipt_failures": failures,
        "comparison_records": {
            "normal": comparison_record(normal, panel.output_comparison),
            "background": comparison_record(
                background, panel.output_comparison
            ),
            "stock": comparison_record(
                stock_result, panel.output_comparison
            ),
        },
        "normal": compact_private(normal),
        "background": compact_private(background),
        "stock": compact_private(stock_result),
    }


def create_forced_midscan_corpus(path: Path) -> None:
    line_count = FORCED_MIDSCAN_FILE_BYTES // FORCED_MIDSCAN_LINE_BYTES
    marker_lines = set(FORCED_MIDSCAN_MARKER_LINES)
    ordinary = b"a" * (FORCED_MIDSCAN_LINE_BYTES - 1) + b"\n"
    marker = (
        b"a" * (FORCED_MIDSCAN_LINE_BYTES - 2) + b"b\n"
    )
    with path.open("xb") as output:
        for line in range(line_count):
            output.write(marker if line in marker_lines else ordinary)
    if path.stat().st_size != FORCED_MIDSCAN_FILE_BYTES:
        raise HarnessError("forced mid-scan corpus size mismatch")
    if sha256_file(path) != FORCED_MIDSCAN_CORPUS_SHA256:
        raise HarnessError("forced mid-scan corpus digest mismatch")


def forced_midscan_expected_stdout() -> bytes:
    matched = b"a" * 99 + b"b"
    records = []
    for line in FORCED_MIDSCAN_MARKER_LINES:
        byte_offset = (
            line * FORCED_MIDSCAN_LINE_BYTES
            + FORCED_MIDSCAN_LINE_BYTES - 2 - 99
        )
        records.append(
            f"{line + 1}:{byte_offset}:".encode() + matched + b"\n"
        )
    return b"".join(records)


def run_forced_midscan_gate(
    *,
    corpus: Path,
    candidate: Path,
    stock: Path,
    cwd: Path,
    cpu_profile: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    args = [
        "--engine=default", "--no-config", "--no-ignore", "--text",
        "--color=never", "--no-heading", "--no-filename",
        "--threads=1", "--only-matching", "--byte-offset",
        "--line-number", FORCED_MIDSCAN_PATTERN, str(corpus),
    ]
    normal = run_once(
        binary=candidate, args=args, cwd=cwd, background=False,
        capture_receipt=False, cpu_profile=cpu_profile,
        timeout_seconds=timeout_seconds,
    )
    background = run_once(
        binary=candidate, args=args, cwd=cwd, background=True,
        capture_receipt=True, cpu_profile=cpu_profile,
        timeout_seconds=timeout_seconds,
        test_min_stock_bytes=FORCED_MIDSCAN_STOCK_BYTES,
    )
    stock_result = run_once(
        binary=stock, args=args, cwd=cwd, background=False,
        capture_receipt=False, cpu_profile=cpu_profile,
        timeout_seconds=timeout_seconds,
    )
    exact_normal_background = outputs_equal(
        normal, background, "literal"
    )
    exact_stock_normal = outputs_equal(stock_result, normal, "literal")
    gate = {
        "cpu_profile": cpu_profile,
        "exact_normal_background": exact_normal_background,
        "exact_stock_normal": exact_stock_normal,
        "failures": [],
        "comparison_records": {
            "normal": comparison_record(normal, "literal"),
            "background": comparison_record(background, "literal"),
            "stock": comparison_record(stock_result, "literal"),
        },
        "normal": compact_private(normal),
        "background": compact_private(background),
        "stock": compact_private(stock_result),
    }
    gate["failures"] = validate_forced_midscan_gate_record(
        gate, cpu_profile
    )
    return gate


def forced_midscan_gate_summary(
    gates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "profiles": len(gates),
        "passed": sum(not gate.get("failures") for gate in gates),
        "all_passed": bool(gates) and all(
            not gate.get("failures") for gate in gates
        ),
        "failures": dict(sorted(Counter(
            failure
            for gate in gates
            for failure in gate.get("failures", [])
        ).items())),
        "routes": dict(sorted(Counter(
            route_class(gate.get("background", {}).get("receipt"))
            for gate in gates
        ).items())),
    }


def validate_forced_midscan_gate_record(
    gate: Mapping[str, Any], cpu_profile: str
) -> list[str]:
    failures = []
    normal = gate.get("normal")
    background = gate.get("background")
    stock = gate.get("stock")
    comparisons = gate.get("comparison_records")
    if not all(
        isinstance(value, Mapping)
        for value in (normal, background, stock, comparisons)
    ) or not all(
        isinstance(comparisons.get(arm), Mapping)
        for arm in ("normal", "background", "stock")
    ):
        return ["forced_midscan_evidence_missing"]
    receipt = background.get("receipt")
    failures.extend(validate_receipt(
        receipt, cpu_profile, FORCED_MIDSCAN_STOCK_BYTES
    ))
    if background.get("receipt_parse_error") is not False:
        failures.append("malformed_receipt")
    if background.get("unexpected_temporary_artifacts") != 0:
        failures.append("unexpected_temporary_artifacts")
    normal_background = comparisons["normal"] == comparisons["background"]
    stock_normal = comparisons["stock"] == comparisons["normal"]
    expected_stdout = output_record(forced_midscan_expected_stdout())
    expected_stderr = output_record(b"")
    for arm, result in (
        ("normal", normal),
        ("background", background),
        ("stock", stock),
    ):
        comparison = comparisons[arm]
        stdout = result.get("stdout")
        stderr = result.get("stderr")
        if (
            not isinstance(stdout, Mapping)
            or not isinstance(stderr, Mapping)
            or comparison.get("status") != result.get("status")
            or comparison.get("stderr_sha256") != stderr.get("sha256")
            or comparison.get("semantic_stdout_sha256")
            != stdout.get("sha256")
        ):
            failures.append(f"forced_midscan_{arm}_evidence_mismatch")
        if result.get("status") != 0:
            failures.append(f"forced_midscan_{arm}_did_not_match")
        if stdout != expected_stdout:
            failures.append(f"forced_midscan_{arm}_unexpected_stdout")
        if stderr != expected_stderr:
            failures.append(f"forced_midscan_{arm}_unexpected_stderr")
    if gate.get("exact_normal_background") != normal_background:
        failures.append("forced_midscan_normal_background_evidence_mismatch")
    if gate.get("exact_stock_normal") != stock_normal:
        failures.append("forced_midscan_stock_normal_evidence_mismatch")
    if not normal_background:
        failures.append("normal_background_output_mismatch")
    if not stock_normal:
        failures.append("stock_normal_output_mismatch")
    if isinstance(receipt, Mapping):
        expected = {
            "outcome": "ready",
            "total_file_attempts": 1,
            "candidate_stock_files": 1,
            "candidate_fre_aot_files": 1,
            "candidate_mixed_engine_files": 1,
            "candidate_midscan_cutover_files": 1,
            "first_candidate_midscan_cutover_file_ordinal": 1,
        }
        for field, value in expected.items():
            if receipt.get(field) != value:
                failures.append(f"forced_midscan_{field}_mismatch")
        for field in (
            "candidate_stock_windows",
            "candidate_fre_aot_windows",
            "candidate_stock_window_bytes",
            "candidate_fre_aot_window_bytes",
        ):
            value = receipt.get(field)
            if not isinstance(value, int) or value <= 0:
                failures.append(f"forced_midscan_{field}_not_positive")
        committed = receipt.get(
            "first_candidate_midscan_cutover_stock_committed_bytes"
        )
        if not isinstance(committed, int) or not (
            FORCED_MIDSCAN_STOCK_BYTES
            <= committed
            < FORCED_MIDSCAN_FILE_BYTES
        ):
            failures.append("forced_midscan_committed_prefix_out_of_range")
    return sorted(set(failures))


def probe_receipt_failures(
    normal: Mapping[str, Any],
    background: Mapping[str, Any],
    cpu_profile: str,
) -> list[str]:
    failures = validate_receipt(background.get("receipt"), cpu_profile)
    if background.get("receipt") is None and normal.get("status") not in (0, 1):
        failures = [
            failure for failure in failures if failure != "missing_receipt"
        ]
    if background.get("receipt_parse_error"):
        failures.append("malformed_receipt")
    if background.get("unexpected_temporary_artifacts"):
        failures.append("unexpected_temporary_artifacts")
    return failures


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty percentile")
    return ordered[round((len(ordered) - 1) * fraction)]


def median(values: Sequence[int | float]) -> float:
    return float(statistics.median(values))


def relative_mad(values: Sequence[int]) -> float:
    center = median(values)
    if center == 0:
        return 0.0 if all(value == 0 for value in values) else math.inf
    return median([abs(value - center) for value in values]) / center


def pair_case_summary(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    configured = len(pairs)
    usable = [
        pair for pair in pairs
        if not pair["normal"]["timed_out"]
        and not pair["background"]["timed_out"]
        and not pair["stock"]["timed_out"]
        and pair["normal"]["status"] in (0, 1)
        and pair["background"]["status"] in (0, 1)
        and pair["stock"]["status"] in (0, 1)
        and pair["exact_normal_background"]
        and pair["exact_stock_normal"]
    ]
    censor_reasons = Counter()
    for pair in pairs:
        for arm in ("normal", "background", "stock"):
            if pair[arm]["timed_out"]:
                censor_reasons[f"{arm}_timeout"] += 1
            elif pair[arm]["status"] not in (0, 1):
                censor_reasons[f"{arm}_error"] += 1
        if not pair["exact_normal_background"]:
            censor_reasons["normal_background_mismatch"] += 1
        if not pair["exact_stock_normal"]:
            censor_reasons["stock_normal_mismatch"] += 1
    if len(usable) != configured or configured == 0:
        return {
            "configured_pairs": configured,
            "usable_pairs": len(usable),
            "complete": False,
            "censor_reasons": dict(sorted(censor_reasons.items())),
            "paired_ratio_median": None,
            "stock_background_ratio_median": None,
            "stable": False,
        }
    normal = [int(pair["normal"]["elapsed_ns"]) for pair in usable]
    background = [int(pair["background"]["elapsed_ns"]) for pair in usable]
    stock = [int(pair["stock"]["elapsed_ns"]) for pair in usable]
    ratios = [left / right for left, right in zip(normal, background)]
    stock_ratios = [left / right for left, right in zip(stock, background)]
    order_ratios: dict[str, list[float]] = {
        "normal_then_background": [],
        "background_then_normal": [],
    }
    for pair, ratio in zip(usable, ratios):
        order = pair["order"]
        key = (
            "normal_then_background"
            if order.index("normal") < order.index("background")
            else "background_then_normal"
        )
        order_ratios[key].append(ratio)
    order_medians = {
        key: median(values) if values else None
        for key, values in order_ratios.items()
    }
    first = order_medians["normal_then_background"]
    second = order_medians["background_then_normal"]
    order_effect = (
        first / second
        if first is not None and second is not None and second != 0
        else None
    )
    timing_stable = (
        relative_mad(normal) <= 0.15
        and relative_mad(background) <= 0.15
        and order_effect is not None
        and 0.90 <= order_effect <= 1.10
    )
    return {
        "configured_pairs": configured,
        "usable_pairs": len(usable),
        "complete": True,
        "censor_reasons": {},
        "paired_ratio_median": median(ratios),
        "stock_background_ratio_median": median(stock_ratios),
        "normal_median_ns": round(median(normal)),
        "background_median_ns": round(median(background)),
        "stock_median_ns": round(median(stock)),
        "normal_relative_mad": relative_mad(normal),
        "background_relative_mad": relative_mad(background),
        "stock_relative_mad": relative_mad(stock),
        "order_ratio_medians": order_medians,
        "order_effect_normal_first_over_background_first": order_effect,
        "order_effect_stability_limit": [0.90, 1.10],
        "stable": timing_stable,
    }


def distribution(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {
        "min": min(values),
        "p10": percentile(values, 0.10),
        "p25": percentile(values, 0.25),
        "median": median(values),
        "p75": percentile(values, 0.75),
        "p90": percentile(values, 0.90),
        "max": max(values),
        "geometric_mean": math.exp(sum(math.log(value) for value in values) / len(values)),
    }


def nonnegative_integer_distribution(
    values: Sequence[int],
) -> dict[str, int | float] | None:
    if not values:
        return None
    as_float = [float(value) for value in values]
    return {
        "count": len(values),
        "total": sum(values),
        "min": min(values),
        "p10": percentile(as_float, 0.10),
        "p25": percentile(as_float, 0.25),
        "median": median(values),
        "p75": percentile(as_float, 0.75),
        "p90": percentile(as_float, 0.90),
        "max": max(values),
    }


def aggregate_observations(
    observations: Sequence[Mapping[str, Any]],
    cases: Mapping[str, QueryCase],
) -> dict[str, Any]:
    exact = Counter()
    outcomes = Counter()
    declines = Counter()
    routes = Counter()
    receipt_failures = Counter()
    normalization = Counter()
    compiler_engines = Counter()
    engine_selection_reasons = Counter()
    accelerators = Counter()
    publication_stages = Counter()
    publication_refusals = Counter()
    target_profiles = Counter()
    requested_feature_bits = Counter()
    host_feature_bits = Counter()
    effective_feature_bits = Counter()
    runtime_helpers = Counter()
    compiled_output_contracts = Counter()
    compiled_entry_abis = Counter()
    compiled_state_sources = Counter()
    compiled_reverse_start_recovery = Counter()
    compiled_state_reporting = Counter()
    candidate_discovery_totals = {
        field: 0 for field in CANDIDATE_DISCOVERY_COUNTER_FIELDS
    }
    stock_work_totals = {field: 0 for field in STOCK_WORK_COUNTER_FIELDS}
    first_candidate_midscan_cutovers = {
        field: [] for field in FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS
    }
    compiled_forward_states = []
    compiled_reverse_states = []
    hits = Counter()
    compile_ns = []
    publish_ns = []
    for row in observations:
        exact["normal_background_exact" if row["exact_normal_background"] else "normal_background_mismatch"] += 1
        exact["stock_normal_exact" if row["exact_stock_normal"] else "stock_normal_mismatch"] += 1
        background = row["background"]
        receipt = background["receipt"]
        outcomes["timeout" if background["timed_out"] else receipt.get("outcome", "no_receipt") if receipt else "no_receipt"] += 1
        declines[receipt_decline_class(receipt)] += 1
        routes[route_class(receipt)] += 1
        receipt_failures.update(row["receipt_failures"])
        normalization.update(row["normalization"])
        if receipt:
            target_profiles[str(receipt.get("target_feature_profile", "unreported"))] += 1
            for counter, field in (
                (requested_feature_bits, "requested_target_feature_bits"),
                (host_feature_bits, "host_target_feature_bits"),
                (effective_feature_bits, "target_feature_bits"),
            ):
                value = receipt.get(field)
                counter[
                    f"0x{value:x}" if isinstance(value, int) else "unreported"
                ] += 1
            compiler_engines[str(receipt.get("compiler_engine", "unreported"))] += 1
            engine_selection_reasons[
                str(receipt.get("engine_selection_reason", "unreported"))
            ] += 1
            accelerators[str(receipt.get("start_accelerator", "unreported"))] += 1
            publication_stages[str(receipt.get("publication_stage", "unreported"))] += 1
            publication_refusals[
                str(receipt.get("publication_refusal_class", "none"))
            ] += 1
            runtime_helpers[
                "required" if receipt.get("runtime_helper_required") is True
                else "not_required" if receipt.get("runtime_helper_required") is False
                else "unreported"
            ] += 1
            compiled_output_contracts[
                str(receipt.get("compiled_output_contract", "unreported"))
            ] += 1
            compiled_entry_abis[
                str(receipt.get("compiled_entry_abi", "unreported"))
            ] += 1
            compiled_state_sources[
                str(receipt.get("compiled_state_source", "unreported"))
            ] += 1
            recovery = receipt.get("compiled_reverse_start_recovery")
            compiled_reverse_start_recovery[
                "present" if recovery is True
                else "absent" if recovery is False
                else "unreported"
            ] += 1
            for field in CANDIDATE_DISCOVERY_COUNTER_FIELDS:
                value = receipt.get(field)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                ):
                    candidate_discovery_totals[field] += value
            for field in STOCK_WORK_COUNTER_FIELDS:
                value = receipt.get(field)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                ):
                    stock_work_totals[field] += value
            for field in FIRST_CANDIDATE_MIDSCAN_CUTOVER_FIELDS:
                value = receipt.get(field)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                ):
                    first_candidate_midscan_cutovers[field].append(value)
            forward_states = receipt.get("compiled_forward_states")
            reverse_states = receipt.get("compiled_reverse_states")
            if (
                isinstance(forward_states, int)
                and not isinstance(forward_states, bool)
                and forward_states >= 0
            ):
                compiled_forward_states.append(forward_states)
            if (
                isinstance(reverse_states, int)
                and not isinstance(reverse_states, bool)
                and reverse_states >= 0
            ):
                compiled_reverse_states.append(reverse_states)
            compiler_engine = receipt.get("compiler_engine")
            if isinstance(forward_states, int) and isinstance(
                reverse_states, int
            ):
                compiled_state_reporting["complete_machine_reported"] += 1
            elif compiler_engine in KNOWN_COMPILER_ENGINES:
                compiled_state_reporting["no_complete_machine_report"] += 1
            else:
                compiled_state_reporting["not_compiled"] += 1
        normal = row["normal"]
        hits["matched" if normal["status"] == 0 else "no_match" if normal["status"] == 1 else "error"] += 1
        if receipt and receipt.get("outcome") == "ready":
            if isinstance(receipt.get("compile_ns"), int):
                compile_ns.append(int(receipt["compile_ns"]))
            if isinstance(receipt.get("publish_ns"), int):
                publish_ns.append(int(receipt["publish_ns"]))
    return {
        "cases": len(observations),
        "occurrence_weight": sum(cases[row["private_id"]].occurrence_weight for row in observations),
        "correctness": dict(sorted(exact.items())),
        "normal_outcomes": dict(sorted(hits.items())),
        "background_outcomes": dict(sorted(outcomes.items())),
        "decline_classes": dict(sorted(declines.items())),
        "routing": dict(sorted(routes.items())),
        "candidate_discovery_accounting": {
            **candidate_discovery_totals,
            "receipts_with_first_candidate_midscan_cutover": len(
                first_candidate_midscan_cutovers[
                    "first_candidate_midscan_cutover_file_ordinal"
                ]
            ),
            **{
                field: nonnegative_integer_distribution(values)
                for field, values in first_candidate_midscan_cutovers.items()
            },
        },
        "stock_matcher_work_accounting": stock_work_totals,
        "receipt_validation_failures": dict(sorted(receipt_failures.items())),
        "semantic_normalizations": dict(sorted(normalization.items())),
        "receipt_classification": {
            "target_feature_profiles": dict(sorted(target_profiles.items())),
            "requested_target_feature_bits": dict(
                sorted(requested_feature_bits.items())
            ),
            "host_target_feature_bits": dict(sorted(host_feature_bits.items())),
            "effective_target_feature_bits": dict(
                sorted(effective_feature_bits.items())
            ),
            "compiler_engines": dict(sorted(compiler_engines.items())),
            "engine_selection_reasons": dict(sorted(engine_selection_reasons.items())),
            "start_accelerators": dict(sorted(accelerators.items())),
            "compiled_output_contracts": dict(
                sorted(compiled_output_contracts.items())
            ),
            "compiled_entry_abis": dict(sorted(compiled_entry_abis.items())),
            "compiled_state_sources": dict(
                sorted(compiled_state_sources.items())
            ),
            "compiled_reverse_start_recovery": dict(
                sorted(compiled_reverse_start_recovery.items())
            ),
            "compiled_state_reporting": dict(
                sorted(compiled_state_reporting.items())
            ),
            "compiled_forward_states": nonnegative_integer_distribution(
                compiled_forward_states
            ),
            "compiled_reverse_states": nonnegative_integer_distribution(
                compiled_reverse_states
            ),
            "publication_stages": dict(sorted(publication_stages.items())),
            "publication_refusal_classes": dict(sorted(publication_refusals.items())),
            "runtime_helpers": dict(sorted(runtime_helpers.items())),
        },
        "ready_compile_ns": distribution([float(value) for value in compile_ns]),
        "ready_publish_ns": distribution([float(value) for value in publish_ns]),
    }


def aggregate_benchmark(
    rows: Sequence[Mapping[str, Any]], cases: Mapping[str, QueryCase]
) -> dict[str, Any]:
    summaries = []
    for row in rows:
        summary = pair_case_summary(row["pairs"])
        summaries.append((row, summary))
    measured = [summary["paired_ratio_median"] for _, summary in summaries if summary["paired_ratio_median"] is not None]
    stock_measured = [
        summary["stock_background_ratio_median"]
        for _, summary in summaries
        if summary["stock_background_ratio_median"] is not None
    ]
    stable = [summary["paired_ratio_median"] for _, summary in summaries if summary["paired_ratio_median"] is not None and summary["stable"]]
    weighted_logs = []
    for row, summary in summaries:
        ratio = summary["paired_ratio_median"]
        if ratio is not None:
            weighted_logs.append((math.log(ratio), cases[row["private_id"]].occurrence_weight))
    total_weight = sum(weight for _, weight in weighted_logs)
    selected_weight = sum(
        cases[row["private_id"]].occurrence_weight for row, _ in summaries
    )
    invocation_outcomes: dict[str, Counter[str]] = {
        arm: Counter() for arm in ("normal", "background", "stock")
    }
    exact_pairs = Counter()
    temporary_artifacts = Counter()
    for row, _ in summaries:
        for pair in row["pairs"]:
            exact_pairs[
                "normal_background_exact"
                if pair["exact_normal_background"]
                else "normal_background_mismatch"
            ] += 1
            exact_pairs[
                "stock_normal_exact"
                if pair["exact_stock_normal"]
                else "stock_normal_mismatch"
            ] += 1
            for arm in ("normal", "background", "stock"):
                result = pair[arm]
                outcome = (
                    "timeout" if result["timed_out"]
                    else "matched" if result["status"] == 0
                    else "no_match" if result["status"] == 1
                    else "error"
                )
                invocation_outcomes[arm][outcome] += 1
                temporary_artifacts[arm] += int(
                    result["unexpected_temporary_artifacts"]
                )
    return {
        "selected_patterns": len(rows),
        "patterns_with_complete_ratio": len(measured),
        "patterns_without_complete_ratio": len(rows) - len(measured),
        "selected_occurrence_weight": selected_weight,
        "measured_occurrence_weight": total_weight,
        "unmeasured_occurrence_weight": selected_weight - total_weight,
        "stable_patterns": len(stable),
        "equal_unique_pattern_speedup": distribution(measured),
        "upstream_stock_over_background_speedup_secondary": distribution(
            stock_measured
        ),
        "stable_only_diagnostic_speedup": distribution(stable),
        "occurrence_weighted_geometric_mean": (
            math.exp(sum(value * weight for value, weight in weighted_logs) / total_weight)
            if total_weight else None
        ),
        "all_timed_invocations": {
            "count": sum(
                sum(values.values()) for values in invocation_outcomes.values()
            ),
            "outcomes_by_arm": {
                arm: dict(sorted(values.items()))
                for arm, values in invocation_outcomes.items()
            },
            "paired_correctness": dict(sorted(exact_pairs.items())),
            "receipt_instrumentation": "disabled_symmetrically",
            "unexpected_temporary_artifacts_by_arm": dict(
                sorted(temporary_artifacts.items())
            ),
        },
        "threshold_counts": {
            "lt_0_80": sum(value < 0.80 for value in measured),
            "lt_0_95": sum(value < 0.95 for value in measured),
            "gt_1_00": sum(value > 1.00 for value in measured),
            "gt_1_05": sum(value > 1.05 for value in measured),
            "gt_1_20": sum(value > 1.20 for value in measured),
        },
    }


def aggregate_groups(
    rows: Sequence[Mapping[str, Any]],
    cases: Mapping[str, QueryCase],
    aggregate: Any,
) -> dict[str, Any]:
    cohorts = sorted({str(row["cohort"]) for row in rows})
    combined = aggregate(rows, cases)
    if len(cohorts) > 1:
        if "occurrence_weight" in combined:
            combined["occurrence_weight"] = None
        if "occurrence_weighted_geometric_mean" in combined:
            combined["occurrence_weighted_geometric_mean"] = None
        for field in (
            "selected_occurrence_weight", "measured_occurrence_weight",
            "unmeasured_occurrence_weight",
        ):
            if field in combined:
                combined[field] = None
        combined["cross_cohort_occurrence_weighting"] = (
            "not_computed; source windows and inclusion probabilities differ"
        )
    return {
        "all_selected": combined,
        "by_cohort": {
            cohort: aggregate(
                [row for row in rows if row["cohort"] == cohort], cases
            )
            for cohort in cohorts
        },
    }


def write_new_json(path: Path, value: Mapping[str, Any], mode: int) -> None:
    if path.exists():
        raise HarnessError("refusing to overwrite a result")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_bound_result_pair(
    private_path: Path,
    public_path: Path,
    private: Mapping[str, Any],
    public: Mapping[str, Any],
) -> None:
    """Write a private result and bind its exact bytes into the public result."""
    write_new_json(private_path, private, 0o600)
    bound_public = dict(public)
    bound_public["private_result_sha256"] = sha256_file(private_path)
    write_new_json(public_path, bound_public, 0o644)


def provenance(
    args: argparse.Namespace,
    corpora: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_source = git_record(args.candidate_source)
    stock_source = git_record(args.stock_source)
    candidate = binary_record(args.binary)
    stock = binary_record(args.stock_binary)
    verify_binary_source(candidate, candidate_source)
    verify_binary_source(stock, stock_source)
    fre_corpus_source = git_record(args.fre_corpus_repo)
    if not fre_corpus_source["clean"]:
        raise HarnessError("FRE corpus source mirror is dirty")
    frozen_fre_commit = git_text(
        args.fre_corpus_repo,
        ("rev-parse", f"{args.fre_corpus_commit}^{{commit}}"),
    )
    frozen_fre_tree = git_text(
        args.fre_corpus_repo,
        ("rev-parse", f"{args.fre_corpus_commit}^{{tree}}"),
    )
    if (
        frozen_fre_commit != corpora["fre"]["commit"]
        or frozen_fre_tree != corpora["fre"]["tree"]
    ):
        raise HarnessError("FRE source mirror does not match corpus commit")
    fre_dependency = fre_dependency_record(args.candidate_source)
    if fre_dependency["locked_revision"] != fre_corpus_source["commit"]:
        raise HarnessError("FRE source mirror does not match compiled dependency")
    sve_vl = sve_vector_length_bytes()
    if (
        args.expected_sve_vl_bytes is not None
        and sve_vl != args.expected_sve_vl_bytes
    ):
        raise HarnessError("SVE vector length does not match the requested host")
    return {
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
            "rustc": command_version("rustc"),
            "cargo": command_version("cargo"),
            "sve_vector_length_bytes": sve_vl,
        },
        "candidate_source": candidate_source,
        "stock_source": stock_source,
        "fre_dependency": fre_dependency,
        "fre_corpus_source_mirror": {
            **fre_corpus_source,
            "role": (
                "clean dependency mirror and object source for the frozen "
                "FRE corpus archive"
            ),
        },
        "binaries": {"candidate": candidate, "stock": stock},
        "corpora": corpora,
        "inventory": {
            **selection,
            "frozen_private_source_verified_locally": (
                args.selection_manifest_input is None
            ),
            "public_raw_patterns_or_per_pattern_hashes_emitted": False,
            "public_stable_cohort_manifest_digest_emitted": True,
        },
    }


def panels_for(corpora: Mapping[str, Path]) -> list[Panel]:
    return [
        Panel(
            "ripgrep-default-output", corpora["ripgrep"],
            "unordered_lf_records", None, False, None,
        ),
        Panel(
            "fre-count-default-threads", corpora["fre"],
            "unordered_lf_records", None, True, None,
        ),
        Panel(
            "fre-count-thread1", corpora["fre"],
            "literal", None, True, 1,
        ),
    ]


def create_corpora(args: argparse.Namespace, temporary: Path) -> tuple[dict[str, Path], dict[str, Any]]:
    ripgrep_path = temporary / "corpus-ripgrep"
    fre_path = temporary / "corpus-fre"
    ripgrep = materialize_git_archive(
        args.ripgrep_corpus_repo, args.ripgrep_corpus_commit, ripgrep_path
    )
    fre = materialize_git_archive(args.fre_corpus_repo, args.fre_corpus_commit, fre_path)
    return {"ripgrep": ripgrep_path, "fre": fre_path}, {"ripgrep": ripgrep, "fre": fre}


def selected_cases(args: argparse.Namespace) -> tuple[list[QueryCase], list[QueryCase]]:
    if args.selection_manifest_input is not None:
        return load_selection_manifest(
            args.selection_manifest_input,
            wider_sample_size=args.wider_sample_size,
            wider_sample_seed=args.wider_sample_seed,
        )
    corpus, _ = validate_private_freeze(args.inventory_root)
    oot = load_oot_cases(args.inventory_root, args.database)
    wider = load_wider_sample(
        args.inventory_root,
        corpus,
        excluded_patterns={case.pattern for case in oot},
        sample_size=args.wider_sample_size,
        seed=args.wider_sample_seed,
    )
    validate_case_cohorts(
        oot, wider, wider_sample_size=args.wider_sample_size
    )
    return oot, wider


def case_manifest(cases: Sequence[QueryCase]) -> list[dict[str, Any]]:
    return [
        {
            "private_id": case.private_id,
            "cohort": case.cohort,
            "pattern": case.pattern,
            "occurrence_weight": case.occurrence_weight,
            "suffix": case.suffix,
            "semantics": dict(case.semantics),
            "target_kind": case.target_kind,
            "extension_class": case.extension_class,
        }
        for case in cases
    ]


def manifest_digest(manifest: Sequence[Mapping[str, Any]]) -> str:
    encoded = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_case_cohorts(
    oot: Sequence[QueryCase],
    wider: Sequence[QueryCase],
    *,
    wider_sample_size: int,
) -> None:
    if (
        len(oot) != EXPECTED_OOT["unique_patterns"]
        or sum(case.suffix is not None for case in oot)
        != EXPECTED_OOT["suffix_patterns"]
        or sum(case.occurrence_weight for case in oot)
        != EXPECTED_OOT["eligible_occurrences"]
        or len(wider) != wider_sample_size
    ):
        raise HarnessError("selection manifest cohort counts do not reconcile")
    expected_oot_ids = {
        f"oot-{index:04d}"
        for index in range(1, EXPECTED_OOT["unique_patterns"] + 1)
    }
    expected_wider_ids = {
        f"wider-{index:04d}"
        for index in range(1, wider_sample_size + 1)
    }
    if (
        {case.private_id for case in oot} != expected_oot_ids
        or {case.private_id for case in wider} != expected_wider_ids
        or any(case.cohort != "frozen-oot-84" for case in oot)
        or any(
            case.cohort != f"frozen-unique-sample-{wider_sample_size}"
            for case in wider
        )
    ):
        raise HarnessError("selection manifest IDs or cohort labels are invalid")
    patterns = [case.pattern for case in [*oot, *wider]]
    if len(patterns) != len(set(patterns)):
        raise HarnessError("selection manifest patterns are not globally unique")


def load_selection_manifest(
    path: Path,
    *,
    wider_sample_size: int,
    wider_sample_seed: int,
) -> tuple[list[QueryCase], list[QueryCase]]:
    document = json.loads(path.read_text())
    schema = document.get("schema")
    if schema != f"{RESULT_SCHEMA}.selection.v1":
        raise HarnessError("unsupported selection manifest schema")
    if (
        document.get("oot_end_unix") != OOT_END_UNIX
        or document.get("oot_expected_counts") != EXPECTED_OOT
        or document.get("wider_sample_size") != wider_sample_size
        or document.get("wider_sample_seed") != wider_sample_seed
        or document.get("frozen_private_source_sha256")
        != EXPECTED_PRIVATE["source_sha256"]
    ):
        raise HarnessError("selection manifest provenance does not match")
    manifest = document.get("selection_manifest")
    if not isinstance(manifest, list) or (
        document.get("selection_manifest_sha256")
        != manifest_digest(manifest)
    ):
        raise HarnessError("selection manifest digest does not match")
    exact_keys = {
        "private_id", "cohort", "pattern", "occurrence_weight", "suffix",
        "semantics", "target_kind", "extension_class",
    }
    cases = []
    for row in manifest:
        if not isinstance(row, Mapping) or set(row) != exact_keys:
            raise HarnessError("selection manifest row schema is invalid")
        if (
            not isinstance(row["private_id"], str)
            or not isinstance(row["cohort"], str)
            or not isinstance(row["pattern"], str)
            or not isinstance(row["occurrence_weight"], int)
            or isinstance(row["occurrence_weight"], bool)
            or row["occurrence_weight"] <= 0
            or not isinstance(row["semantics"], Mapping)
            or row["suffix"] is not None
            and not isinstance(row["suffix"], str)
            or row["target_kind"] is not None
            and not isinstance(row["target_kind"], str)
            or row["extension_class"] is not None
            and not isinstance(row["extension_class"], str)
        ):
            raise HarnessError("selection manifest row value is invalid")
        cases.append(QueryCase(
            private_id=row["private_id"],
            cohort=row["cohort"],
            pattern=row["pattern"],
            occurrence_weight=row["occurrence_weight"],
            suffix=row["suffix"],
            semantics=dict(row["semantics"]),
            target_kind=row["target_kind"],
            extension_class=row["extension_class"],
        ))
    if case_manifest(cases) != manifest:
        raise HarnessError("selection manifest did not round trip exactly")
    oot = [case for case in cases if case.private_id.startswith("oot-")]
    wider = [case for case in cases if case.private_id.startswith("wider-")]
    if len(oot) + len(wider) != len(cases):
        raise HarnessError("selection manifest contains an unknown case ID")
    validate_case_cohorts(
        oot, wider, wider_sample_size=wider_sample_size
    )
    return oot, wider


def selection_provenance(
    args: argparse.Namespace,
    oot: Sequence[QueryCase],
    wider: Sequence[QueryCase],
) -> dict[str, Any]:
    manifest = case_manifest([*oot, *wider])
    result = {
        "mode": (
            "transported_manifest"
            if args.selection_manifest_input is not None
            else "local_frozen_inventory"
        ),
        "selection_manifest_sha256": manifest_digest(manifest),
        "oot_end_unix": OOT_END_UNIX,
        "oot_expected_counts": EXPECTED_OOT,
        "wider_sample_size": args.wider_sample_size,
        "wider_sample_seed": args.wider_sample_seed,
        "frozen_private_source_sha256": EXPECTED_PRIVATE["source_sha256"],
    }
    if args.selection_manifest_input is not None:
        result["transport_file_sha256"] = sha256_file(
            args.selection_manifest_input
        )
    return result


def revalidate_selection(
    args: argparse.Namespace,
    oot: Sequence[QueryCase],
    wider: Sequence[QueryCase],
) -> None:
    if args.selection_manifest_input is not None:
        post_oot, post_wider = load_selection_manifest(
            args.selection_manifest_input,
            wider_sample_size=args.wider_sample_size,
            wider_sample_seed=args.wider_sample_seed,
        )
        if case_manifest([*post_oot, *post_wider]) != case_manifest(
            [*oot, *wider]
        ):
            raise HarnessError("selection manifest changed during workload")
        return
    validate_private_freeze(args.inventory_root)
    if case_manifest(
        load_oot_cases(args.inventory_root, args.database)
    ) != case_manifest(oot):
        raise HarnessError("frozen OOT selection changed during workload")


def run_export_selection(args: argparse.Namespace) -> None:
    oot, wider = selected_cases(args)
    manifest = case_manifest([*oot, *wider])
    revalidate_selection(args, oot, wider)
    document = {
        "schema": f"{RESULT_SCHEMA}.selection.v1",
        "contains_raw_patterns": True,
        "oot_end_unix": OOT_END_UNIX,
        "oot_expected_counts": EXPECTED_OOT,
        "wider_sample_size": args.wider_sample_size,
        "wider_sample_seed": args.wider_sample_seed,
        "frozen_private_source_sha256": EXPECTED_PRIVATE["source_sha256"],
        "selection_manifest_sha256": manifest_digest(manifest),
        "selection_manifest": manifest,
    }
    write_new_json(args.output, document, 0o600)


def run_probe(args: argparse.Namespace) -> None:
    oot, wider = selected_cases(args)
    all_cases = [*oot, *wider]
    by_id = {case.private_id: case for case in all_cases}
    selection_manifest = case_manifest(all_cases)
    selection_record = selection_provenance(args, oot, wider)
    with tempfile.TemporaryDirectory(prefix="rg-fre-representative-") as text:
        temporary = Path(text)
        corpus_paths, corpus_records = create_corpora(args, temporary)
        forced_midscan_path = temporary / "forced-midscan-v1.txt"
        create_forced_midscan_corpus(forced_midscan_path)
        forced_midscan_config = {
            "fixture": "bounded-repeat-two-markers-v1",
            "file_bytes": FORCED_MIDSCAN_FILE_BYTES,
            "line_bytes": FORCED_MIDSCAN_LINE_BYTES,
            "marker_matches": 2,
            "test_min_stock_bytes": FORCED_MIDSCAN_STOCK_BYTES,
            "corpus_sha256": sha256_file(forced_midscan_path),
        }
        run_panels = panels_for(corpus_paths)
        prov = provenance(args, corpus_records, selection_record)
        workload_start = load_snapshot()
        private_rows = []
        forced_midscan_gates = []
        public_panels: dict[str, Any] = {}
        for cpu_profile in args.cpu_profile:
            print(f"probe {cpu_profile} forced-midscan", flush=True)
            forced_midscan_gates.append(run_forced_midscan_gate(
                corpus=forced_midscan_path,
                candidate=args.binary,
                stock=args.stock_binary,
                cwd=args.candidate_source,
                cpu_profile=cpu_profile,
                timeout_seconds=args.timeout_seconds,
            ))
            for panel in run_panels:
                cases = oot if panel.id == "ripgrep-default-output" else all_cases
                rows = []
                for index, case in enumerate(cases, 1):
                    print(
                        f"probe {cpu_profile} {panel.id} {index}/{len(cases)}",
                        flush=True,
                    )
                    result = probe_one(
                        case,
                        panel,
                        candidate=args.binary,
                        stock=args.stock_binary,
                        cwd=args.candidate_source,
                        cpu_profile=cpu_profile,
                        timeout_seconds=args.timeout_seconds,
                    )
                    row = {
                        "private_id": case.private_id,
                        "cohort": case.cohort,
                        "pattern": case.pattern,
                        "occurrence_weight": case.occurrence_weight,
                        "suffix": case.suffix,
                        "semantics": dict(case.semantics),
                        "target_kind": case.target_kind,
                        "extension_class": case.extension_class,
                        "cpu_profile": cpu_profile,
                        "panel": panel.id,
                        **result,
                    }
                    private_rows.append(row)
                    rows.append(row)
                key = f"{cpu_profile}/{panel.id}"
                public_panels[key] = aggregate_groups(
                    rows, by_id, aggregate_observations
                )
        target_matrix = target_validation_matrix(
            private_rows, args.cpu_profile
        )
        workload_end = load_snapshot()
        revalidate_selection(args, oot, wider)
        post = provenance(
            args,
            corpus_records,
            selection_provenance(args, oot, wider),
        )
        if post != prov:
            raise HarnessError("source or binaries changed during probe")
    private = {
        "schema": f"{RESULT_SCHEMA}.probe.private.v1",
        "contains_raw_patterns": True,
        "local_only_do_not_commit": True,
        "selection_manifest_sha256": manifest_digest(selection_manifest),
        "selection_manifest": selection_manifest,
        "target_validation_matrix": target_matrix,
        "cohorts": {"oot": cohort_profile(oot), "wider": cohort_profile(wider)},
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "rows": private_rows,
        "forced_midscan_config": forced_midscan_config,
        "forced_midscan_gates": forced_midscan_gates,
    }
    public = {
        "schema": f"{RESULT_SCHEMA}.probe.public.v1",
        "aggregate_only": True,
        "contains_patterns_commands_paths_or_per_pattern_rows": False,
        "method": {
            "primary_cohort": "84 actual OOT ripgrep query shapes selected before this integration and before performance results",
            "wider_cohort": "deterministic equal-unique sample from the frozen historical expression inventory",
            "query_corpus_relation": "transplant; historical targets, sizes, and match density are unavailable",
            "fresh_processes": True,
            "filesystem_cache_state": "cache-hot/uncontrolled after one archive materialization; no eviction between repeated scans",
            "timing_role": "classification/correctness probe only; not formal timing",
            "forced_midscan_gate": (
                "deterministic correctness-only publication barrier; never "
                "used by timed invocations"
            ),
            "cpu_profiles": args.cpu_profile,
            "oot_end_unix": OOT_END_UNIX,
            "oot_expected_counts": EXPECTED_OOT,
            "wider_sample_size": args.wider_sample_size,
            "wider_sample_seed": args.wider_sample_seed,
            "wider_unique_semantics": "first chronological occurrence",
            "profile_execution_order": "profile-major; do not compare profiles as paired observations",
        },
        **prov,
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "cohorts": {"oot": cohort_profile(oot), "wider": cohort_profile(wider)},
        "panels": public_panels,
        "target_validation_matrix": target_matrix,
        "forced_midscan_config": forced_midscan_config,
        "forced_midscan_gate": forced_midscan_gate_summary(
            forced_midscan_gates
        ),
        "post_run_private_freeze_verified": (
            args.selection_manifest_input is None
        ),
        "post_run_selection_verified": True,
        "post_run_provenance_verified": True,
    }
    write_bound_result_pair(
        args.private_output, args.public_output, private, public
    )


def run_pair(
    case: QueryCase,
    panel: Panel,
    *,
    pair_index: int,
    candidate: Path,
    stock: Path,
    cwd: Path,
    cpu_profile: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    args, normalization = query_args(case, panel)
    orders = (
        ("stock", "normal", "background"),
        ("normal", "background", "stock"),
        ("stock", "background", "normal"),
        ("background", "normal", "stock"),
    )
    order = orders[pair_index % len(orders)]
    results = {}
    for arm in order:
        result = run_once(
            binary=stock if arm == "stock" else candidate,
            args=args,
            cwd=cwd,
            background=arm == "background",
            capture_receipt=False,
            cpu_profile=cpu_profile,
            timeout_seconds=timeout_seconds,
        )
        results[arm] = result
    exact_normal_background = outputs_equal(
        results["normal"], results["background"], panel.output_comparison
    )
    exact_stock_normal = outputs_equal(
        results["stock"], results["normal"], panel.output_comparison
    )
    return {
        "pair_index": pair_index,
        "order": list(order),
        "normalization": normalization,
        "exact_normal_background": exact_normal_background,
        "exact_stock_normal": exact_stock_normal,
        "normal": compact_private(results["normal"]),
        "background": compact_private(results["background"]),
        "stock": compact_private(results["stock"]),
    }


def validate_and_aggregate_private_probe(
    private_probe: Mapping[str, Any],
    *,
    cpu_profiles: Sequence[str],
    oot: Sequence[QueryCase],
    wider: Sequence[QueryCase],
) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = private_probe.get("rows")
    if not isinstance(rows, list):
        raise HarnessError("private probe rows are missing")
    all_cases = [*oot, *wider]
    by_id = {case.private_id: case for case in all_cases}
    expected_keys = set()
    for profile in cpu_profiles:
        for panel in PANELS:
            cases = oot if panel == "ripgrep-default-output" else all_cases
            expected_keys.update(
                (profile, panel, case.private_id) for case in cases
            )
    observed_keys = set()
    validated_rows = []
    output_modes = {
        "ripgrep-default-output": "unordered_lf_records",
        "fre-count-default-threads": "unordered_lf_records",
        "fre-count-thread1": "literal",
    }
    identity_fields = (
        "private_id", "cohort", "pattern", "occurrence_weight", "suffix",
        "semantics", "target_kind", "extension_class",
    )
    for original in rows:
        if not isinstance(original, Mapping):
            raise HarnessError("private probe row is not an object")
        profile = original.get("cpu_profile")
        panel = original.get("panel")
        private_id = original.get("private_id")
        key = (profile, panel, private_id)
        if key not in expected_keys or key in observed_keys:
            raise HarnessError("private probe row matrix is invalid")
        observed_keys.add(key)
        case = by_id[private_id]
        expected_identity = case_manifest([case])[0]
        if any(
            original.get(field) != expected_identity[field]
            for field in identity_fields
        ):
            raise HarnessError("private probe row does not match selection")
        normal = original.get("normal")
        background = original.get("background")
        stock = original.get("stock")
        comparisons = original.get("comparison_records")
        if not all(
            isinstance(value, Mapping)
            for value in (normal, background, stock, comparisons)
        ) or not all(
            isinstance(comparisons.get(arm), Mapping)
            for arm in ("normal", "background", "stock")
        ):
            raise HarnessError("private probe comparison evidence is missing")
        mode = output_modes[panel]
        for arm, result in (
            ("normal", normal),
            ("background", background),
            ("stock", stock),
        ):
            comparison = comparisons[arm]
            stdout = result.get("stdout", {})
            stderr = result.get("stderr", {})
            semantic_digest = comparison.get("semantic_stdout_sha256")
            if (
                not isinstance(stdout, Mapping)
                or not isinstance(stderr, Mapping)
                or comparison.get("status") != result.get("status")
                or comparison.get("stderr_sha256") != stderr.get("sha256")
                or not isinstance(semantic_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", semantic_digest) is None
                or mode == "literal"
                and semantic_digest != stdout.get("sha256")
            ):
                raise HarnessError(
                    "private probe comparison evidence is invalid"
                )
        exact_normal_background = comparison_records_equal(
            comparisons["normal"], comparisons["background"]
        )
        exact_stock_normal = comparison_records_equal(
            comparisons["stock"], comparisons["normal"]
        )
        receipt_failures = probe_receipt_failures(
            normal, background, str(profile)
        )
        _, normalization = profile_flags(case)
        if (
            original.get("exact_normal_background")
            != exact_normal_background
            or original.get("exact_stock_normal") != exact_stock_normal
            or original.get("receipt_failures") != receipt_failures
            or original.get("normalization") != normalization
        ):
            raise HarnessError("private probe derived fields do not reconcile")
        row = dict(original)
        row.update({
            "exact_normal_background": exact_normal_background,
            "exact_stock_normal": exact_stock_normal,
            "receipt_failures": receipt_failures,
            "normalization": normalization,
        })
        validated_rows.append(row)
    if observed_keys != expected_keys:
        raise HarnessError("private probe row matrix is incomplete")
    panels = {}
    for profile in cpu_profiles:
        for panel in PANELS:
            panel_rows = [
                row for row in validated_rows
                if row["cpu_profile"] == profile and row["panel"] == panel
            ]
            panels[f"{profile}/{panel}"] = aggregate_groups(
                panel_rows, by_id, aggregate_observations
            )
    return panels, target_validation_matrix(validated_rows, cpu_profiles)


def validate_probe(
    args: argparse.Namespace,
    prov: Mapping[str, Any],
    *,
    oot: Sequence[QueryCase],
    wider: Sequence[QueryCase],
) -> None:
    probe = json.loads(args.probe_public.read_text())
    private_probe = json.loads(args.probe_private.read_text())
    expected_manifest = case_manifest([*oot, *wider])
    method = probe.get("method", {})
    forced_config = private_probe.get("forced_midscan_config")
    expected_forced_config = {
        "fixture": "bounded-repeat-two-markers-v1",
        "file_bytes": FORCED_MIDSCAN_FILE_BYTES,
        "line_bytes": FORCED_MIDSCAN_LINE_BYTES,
        "marker_matches": 2,
        "test_min_stock_bytes": FORCED_MIDSCAN_STOCK_BYTES,
    }
    if not isinstance(forced_config, Mapping) or any(
        forced_config.get(field) != value
        for field, value in expected_forced_config.items()
    ) or forced_config.get("corpus_sha256") != FORCED_MIDSCAN_CORPUS_SHA256:
        raise HarnessError("forced mid-scan configuration is invalid")
    private_forced_gates = private_probe.get("forced_midscan_gates")
    if not isinstance(private_forced_gates, list):
        raise HarnessError("forced mid-scan gates are missing")
    forced_by_profile = {}
    for gate in private_forced_gates:
        if not isinstance(gate, Mapping):
            raise HarnessError("forced mid-scan gate is not an object")
        profile = gate.get("cpu_profile")
        if profile not in args.cpu_profile or profile in forced_by_profile:
            raise HarnessError("forced mid-scan profile matrix is invalid")
        recomputed_failures = validate_forced_midscan_gate_record(
            gate, str(profile)
        )
        if gate.get("failures") != recomputed_failures:
            raise HarnessError("forced mid-scan gate evidence disagrees")
        forced_by_profile[profile] = gate
    if set(forced_by_profile) != set(args.cpu_profile):
        raise HarnessError("forced mid-scan profile matrix is incomplete")
    forced_summary = forced_midscan_gate_summary(private_forced_gates)
    recomputed_panels, computed_target_matrix = (
        validate_and_aggregate_private_probe(
            private_probe,
            cpu_profiles=args.cpu_profile,
            oot=oot,
            wider=wider,
        )
    )
    if (
        probe.get("schema") != f"{RESULT_SCHEMA}.probe.public.v1"
        or probe.get("aggregate_only") is not True
        or probe.get("private_result_sha256")
        != sha256_file(args.probe_private)
        or probe.get("binaries") != prov["binaries"]
        or probe.get("candidate_source") != prov["candidate_source"]
        or probe.get("stock_source") != prov["stock_source"]
        or probe.get("fre_dependency") != prov["fre_dependency"]
        or probe.get("fre_corpus_source_mirror")
        != prov["fre_corpus_source_mirror"]
        or probe.get("host") != prov["host"]
        or probe.get("inventory") != prov["inventory"]
        or probe.get("corpora") != prov["corpora"]
        or probe.get("post_run_selection_verified") is not True
        or probe.get("post_run_provenance_verified") is not True
        or method.get("cpu_profiles") != args.cpu_profile
        or method.get("oot_end_unix") != OOT_END_UNIX
        or method.get("oot_expected_counts") != EXPECTED_OOT
        or method.get("wider_sample_size") != args.wider_sample_size
        or method.get("wider_sample_seed") != args.wider_sample_seed
        or private_probe.get("schema")
        != f"{RESULT_SCHEMA}.probe.private.v1"
        or private_probe.get("selection_manifest") != expected_manifest
        or private_probe.get("selection_manifest_sha256")
        != manifest_digest(expected_manifest)
        or probe.get("panels") != recomputed_panels
        or probe.get("target_validation_matrix") != computed_target_matrix
        or private_probe.get("target_validation_matrix")
        != computed_target_matrix
        or probe.get("forced_midscan_config") != forced_config
        or probe.get("forced_midscan_gate") != forced_summary
        or forced_summary.get("all_passed") is not True
        or computed_target_matrix.get("qualified") is not True
    ):
        raise HarnessError("probe does not match the benchmark inputs")
    expected_panels = {
        f"{profile}/{panel}"
        for profile in args.cpu_profile
        for panel in PANELS
    }
    panels = probe.get("panels")
    if not isinstance(panels, Mapping) or set(panels) != expected_panels:
        raise HarnessError("probe panel matrix is incomplete")
    observed_host_feature_bits: set[str] = set()
    for key, panel in panels.items():
        aggregate = panel.get("all_selected", {})
        expected = (
            len(oot) if key.endswith("/ripgrep-default-output")
            else len(oot) + len(wider)
        )
        correctness = aggregate.get("correctness", {})
        if (
            aggregate.get("cases") != expected
            or correctness.get("normal_background_exact", 0) != expected
            or correctness.get("stock_normal_exact", 0) != expected
            or correctness.get("normal_background_mismatch", 0) != 0
            or correctness.get("stock_normal_mismatch", 0) != 0
            or aggregate.get("receipt_validation_failures")
        ):
            raise HarnessError("probe correctness or receipt validation failed")
        bit_counts = aggregate.get("receipt_classification", {}).get(
            "host_target_feature_bits", {}
        )
        observed_host_feature_bits.update(
            value for value in bit_counts if value != "unreported"
        )
    if len(observed_host_feature_bits) != 1:
        raise HarnessError("probe host feature masks are inconsistent")


def run_benchmark(args: argparse.Namespace) -> None:
    oot, wider = selected_cases(args)
    all_cases = [*oot, *wider]
    by_id = {case.private_id: case for case in all_cases}
    selection_manifest = case_manifest(all_cases)
    selection_record = selection_provenance(args, oot, wider)
    with tempfile.TemporaryDirectory(prefix="rg-fre-representative-") as text:
        temporary = Path(text)
        corpus_paths, corpus_records = create_corpora(args, temporary)
        run_panels = panels_for(corpus_paths)
        prov = provenance(args, corpus_records, selection_record)
        validate_probe(
            args,
            prov,
            oot=oot,
            wider=wider,
        )
        workload_start = load_snapshot()
        rows = []
        public_panels: dict[str, Any] = {}
        for cpu_profile in args.cpu_profile:
            for panel_index, panel in enumerate(run_panels):
                cases = oot if panel.id == "ripgrep-default-output" else all_cases
                panel_rows = []
                for case_index, case in enumerate(cases):
                    for warmup in range(args.warmup_pairs):
                        run_pair(
                            case, panel, pair_index=warmup + panel_index + case_index,
                            candidate=args.binary, stock=args.stock_binary,
                            cwd=args.candidate_source,
                            cpu_profile=cpu_profile,
                            timeout_seconds=args.timeout_seconds,
                        )
                    pairs = []
                    for pair_index in range(args.pairs):
                        print(
                            f"benchmark {cpu_profile} {panel.id} "
                            f"{case_index + 1}/{len(cases)} pair {pair_index + 1}/{args.pairs}",
                            flush=True,
                        )
                        pairs.append(
                            run_pair(
                                case, panel,
                                pair_index=pair_index + panel_index + case_index,
                                candidate=args.binary, stock=args.stock_binary,
                                cwd=args.candidate_source,
                                cpu_profile=cpu_profile,
                                timeout_seconds=args.timeout_seconds,
                            )
                        )
                    row = {
                        "private_id": case.private_id,
                        "cohort": case.cohort,
                        "pattern": case.pattern,
                        "occurrence_weight": case.occurrence_weight,
                        "suffix": case.suffix,
                        "semantics": dict(case.semantics),
                        "target_kind": case.target_kind,
                        "extension_class": case.extension_class,
                        "query_argv_after_binary": query_args(case, panel)[0],
                        "cpu_profile": cpu_profile,
                        "panel": panel.id,
                        "pairs": pairs,
                        "summary": pair_case_summary(pairs),
                    }
                    rows.append(row)
                    panel_rows.append(row)
                public_panels[f"{cpu_profile}/{panel.id}"] = aggregate_groups(
                    panel_rows, by_id, aggregate_benchmark
                )
        workload_end = load_snapshot()
        revalidate_selection(args, oot, wider)
        post = provenance(
            args,
            corpus_records,
            selection_provenance(args, oot, wider),
        )
        if post != prov:
            raise HarnessError("source or binaries changed during benchmark")
    private = {
        "schema": f"{RESULT_SCHEMA}.benchmark.private.v1",
        "contains_raw_patterns": True,
        "local_only_do_not_commit": True,
        "selection_manifest_sha256": manifest_digest(selection_manifest),
        "selection_manifest": selection_manifest,
        "pairs": args.pairs,
        "warmup_pairs": args.warmup_pairs,
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "rows": rows,
    }
    public = {
        "schema": f"{RESULT_SCHEMA}.benchmark.public.v1",
        "aggregate_only": True,
        "contains_patterns_commands_paths_or_per_pattern_rows": False,
        "method": {
            "unit": "one actual query in one fresh ripgrep process",
            "primary": "same candidate flag off versus --fre-aot-background",
            "pairs": args.pairs,
            "warmup_pairs": args.warmup_pairs,
            "sample_order": "four-order stock/NB rotation; normal/background always adjacent",
            "primary_aggregation": "median paired ratio per exact pattern, then equal-unique-pattern distribution",
            "occurrence_weighted_aggregation": "secondary",
            "all_selected_patterns_retained": True,
            "cpu_profiles": args.cpu_profile,
            "oot_end_unix": OOT_END_UNIX,
            "oot_expected_counts": EXPECTED_OOT,
            "wider_sample_size": args.wider_sample_size,
            "wider_sample_seed": args.wider_sample_seed,
            "profile_execution_order": "profile-major; no direct cross-profile comparison",
            "timed_receipts": False,
            "filesystem_cache_state": "cache-hot/uncontrolled after one archive materialization; no eviction between warmups or samples",
            "classification_source": "mandatory matching untimed probe",
            "query_corpus_relation": "transplant, not historical command replay",
        },
        **prov,
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "cohorts": {"oot": cohort_profile(oot), "wider": cohort_profile(wider)},
        "probe_gate": {
            "public_result_sha256": sha256_file(args.probe_public),
            "private_selection_manifest_sha256": manifest_digest(
                selection_manifest
            ),
        },
        "panels": public_panels,
        "post_run_private_freeze_verified": (
            args.selection_manifest_input is None
        ),
        "post_run_selection_verified": True,
        "post_run_provenance_verified": True,
    }
    write_bound_result_pair(
        args.private_output, args.public_output, private, public
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("probe", "benchmark"):
        child = subparsers.add_parser(mode)
        child.add_argument("--binary", type=Path, required=True)
        child.add_argument("--candidate-source", type=Path, default=REPO)
        child.add_argument("--stock-binary", type=Path, required=True)
        child.add_argument("--stock-source", type=Path, required=True)
        child.add_argument("--inventory-root", type=Path)
        child.add_argument("--database", type=Path)
        child.add_argument("--selection-manifest-input", type=Path)
        child.add_argument("--ripgrep-corpus-repo", type=Path, required=True)
        child.add_argument("--ripgrep-corpus-commit", required=True)
        child.add_argument("--fre-corpus-repo", type=Path, required=True)
        child.add_argument("--fre-corpus-commit", required=True)
        child.add_argument("--wider-sample-size", type=int, default=128)
        child.add_argument("--wider-sample-seed", type=int, default=0xA07_2026)
        child.add_argument("--cpu-profile", action="append", choices=CPU_PROFILES)
        child.add_argument("--timeout-seconds", type=float, default=30.0)
        child.add_argument("--expected-sve-vl-bytes", type=int)
        child.add_argument("--private-output", type=Path, required=True)
        child.add_argument("--public-output", type=Path, required=True)
    benchmark = subparsers.choices["benchmark"]
    benchmark.add_argument("--probe-public", type=Path, required=True)
    benchmark.add_argument("--probe-private", type=Path, required=True)
    benchmark.add_argument("--pairs", type=int, default=12)
    benchmark.add_argument("--warmup-pairs", type=int, default=2)
    export = subparsers.add_parser("export-selection")
    export.add_argument("--inventory-root", type=Path, required=True)
    export.add_argument("--database", type=Path, required=True)
    export.add_argument("--wider-sample-size", type=int, default=128)
    export.add_argument("--wider-sample-seed", type=int, default=0xA07_2026)
    export.add_argument("--output", type=Path, required=True)
    export.set_defaults(selection_manifest_input=None)
    args = parser.parse_args(argv)
    if args.wider_sample_size < 0:
        parser.error("wider sample size must be non-negative")
    if args.mode == "export-selection":
        for field in ("inventory_root", "database"):
            setattr(
                args, field,
                getattr(args, field).expanduser().resolve(strict=True),
            )
        args.output = args.output.expanduser().resolve()
        if args.output.exists():
            parser.error("selection manifest destination must be new")
        return args
    for field in (
        "binary", "candidate_source", "stock_binary", "stock_source",
        "ripgrep_corpus_repo", "fre_corpus_repo",
    ):
        setattr(args, field, getattr(args, field).expanduser().resolve(strict=True))
    if args.selection_manifest_input is not None:
        if args.inventory_root is not None or args.database is not None:
            parser.error(
                "selection manifest cannot be combined with inventory/database"
            )
        args.selection_manifest_input = (
            args.selection_manifest_input.expanduser().resolve(strict=True)
        )
    else:
        if args.inventory_root is None or args.database is None:
            parser.error(
                "provide selection manifest or both inventory root and database"
            )
        args.inventory_root = args.inventory_root.expanduser().resolve(strict=True)
        args.database = args.database.expanduser().resolve(strict=True)
    args.private_output = args.private_output.expanduser().resolve()
    args.public_output = args.public_output.expanduser().resolve()
    args.cpu_profile = args.cpu_profile or ["auto"]
    if len(set(args.cpu_profile)) != len(args.cpu_profile):
        parser.error("CPU profiles must be unique")
    if args.private_output == args.public_output:
        parser.error("private and public outputs must differ")
    if args.private_output.exists() or args.public_output.exists():
        parser.error("result destinations must be new")
    if args.timeout_seconds <= 0:
        parser.error("timeout must be positive")
    if args.expected_sve_vl_bytes is not None and args.expected_sve_vl_bytes <= 0:
        parser.error("expected SVE vector length must be positive")
    if args.mode == "benchmark":
        args.probe_public = args.probe_public.expanduser().resolve(strict=True)
        args.probe_private = args.probe_private.expanduser().resolve(strict=True)
        if args.pairs < 8 or args.pairs % 4:
            parser.error("formal pairs must be at least 8 and divisible by 4")
        if args.warmup_pairs < 0:
            parser.error("warmup pairs must be non-negative")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.mode == "export-selection":
            run_export_selection(args)
        elif args.mode == "probe":
            run_probe(args)
        else:
            run_benchmark(args)
        return 0
    except (HarnessError, OSError, ValueError, json.JSONDecodeError):
        print('{"error":"representative_harness_failed_safely"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

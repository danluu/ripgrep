#!/usr/bin/env python3
"""Check exact stock/normal/background equivalence and cutover receipts."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common import (
    AMBIGUOUS,
    BOUNDED,
    DEFAULT_MANIFEST,
    ORDERED,
    OVERLAP,
    REPO,
    TRACE,
    corpus_path,
    load_manifest,
    scenario_paths,
    sha256,
    verify_manifest_files,
)
from runner import assert_exact_output, run_once


@dataclass(frozen=True)
class Case:
    name: str
    args: tuple[str, ...]
    stdin: bytes | None = None
    receipt_policy: str = "observe"
    receipt_required: bool = True
    slow: bool = False


def correctness_file(
    manifest_path: Path, manifest: dict[str, Any], filename: str
) -> Path:
    for row in manifest["correctness"]["files"]:
        if Path(row["path"]).name == filename:
            return corpus_path(manifest_path, row["path"])
    raise ValueError(f"correctness fixture {filename!r} is absent")


def cases(manifest_path: Path, manifest: dict[str, Any]) -> list[Case]:
    source = correctness_file(manifest_path, manifest, "input.txt")
    no_match = correctness_file(manifest_path, manifest, "no-match.txt")
    second = correctness_file(manifest_path, manifest, "second.txt")
    negative16 = scenario_paths(manifest_path, manifest, "a_negative", 16)
    parallel_negative = negative16 * 4
    positive8 = scenario_paths(manifest_path, manifest, "a_positive", 8)
    nullable_many = [
        corpus_path(manifest_path, row["path"])
        for row in manifest["correctness"]["files"]
        if Path(row["path"]).parent.name == "nullable-many"
    ]
    if len(nullable_many) < 1024:
        raise ValueError("nullable cutover fixture requires at least 1024 files")
    base = ("--no-config",)
    return [
        Case("line-output", (*base, "--line-number", "--", ORDERED, str(source))),
        Case("only-matching", (*base, "--only-matching", "--", OVERLAP, str(source))),
        Case(
            "replacement-captures",
            (*base, "--replace=<$0>", "--", ORDERED, str(source)),
        ),
        Case(
            "forced-color",
            (*base, "--color=always", "--line-number", "--", ORDERED, str(source)),
        ),
        Case("no-match-status", (*base, "--", TRACE, str(no_match))),
        Case(
            "files-with-matches",
            (
                *base,
                "--sort=path",
                "--files-with-matches",
                "--",
                TRACE,
                str(source),
                str(second),
            ),
        ),
        Case("empty-and-anchor", (*base, "--line-number", "--", r"^$", str(source))),
        Case(
            "stdin",
            (*base, "--line-number", "--", ORDERED),
            stdin=source.read_bytes(),
        ),
        Case(
            "ignore-case-decline",
            (*base, "--ignore-case", "--line-number", "--", TRACE, str(source)),
            receipt_policy="declined",
        ),
        Case(
            "multiple-patterns-decline",
            (
                *base,
                "--line-number",
                "--regexp",
                ORDERED,
                "--regexp",
                TRACE,
                str(source),
            ),
            receipt_policy="declined",
        ),
        Case(
            "invalid-regex-before-coordinator",
            (*base, "--", "(", str(source)),
            receipt_required=False,
        ),
        Case(
            "single-file-publication-without-guaranteed-cutover",
            (
                *base,
                "--sort=path",
                "--threads=1",
                "--count",
                "--include-zero",
                "--",
                BOUNDED,
                str(negative16[0]),
            ),
            slow=True,
        ),
        Case(
            "sequential-negative-real-cutover",
            (
                *base,
                "--sort=path",
                "--threads=1",
                "--count",
                "--include-zero",
                "--",
                BOUNDED,
                *(str(path) for path in negative16),
            ),
            receipt_policy="cutover",
            slow=True,
        ),
        Case(
            "sequential-positive-capture-replacement-cutover",
            (
                *base,
                "--sort=path",
                "--threads=1",
                "--only-matching",
                "--replace=<$run>",
                "--with-filename",
                "--line-number",
                "--",
                r"(?P<run>a{0,100})b",
                *(str(path) for path in positive8),
            ),
            receipt_policy="cutover",
            slow=True,
        ),
        Case(
            "nullable-iterator-real-cutover",
            (
                *base,
                "--threads=1",
                "--count-matches",
                "--include-zero",
                "--with-filename",
                "--",
                r"a*",
                str(negative16[0]),
                *(str(path) for path in nullable_many),
            ),
            receipt_policy="cutover",
            slow=True,
        ),
        Case(
            "parallel-negative-real-cutover",
            (
                *base,
                "--quiet",
                "--threads=4",
                "--",
                BOUNDED,
                *(str(path) for path in parallel_negative),
            ),
            receipt_policy="cutover",
            slow=True,
        ),
        Case(
            "parallel-early-match-cancellation",
            (
                *base,
                "--quiet",
                "--threads=4",
                "--",
                AMBIGUOUS,
                *(str(path) for path in positive8),
            ),
            slow=True,
        ),
    ]


def compact(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": result["status"],
        "stdout": {
            "bytes": result["stdout"]["bytes"],
            "sha256": result["stdout"]["sha256"],
        },
        "stderr": {
            "bytes": result["stderr"]["bytes"],
            "sha256": result["stderr"]["sha256"],
        },
        "receipt": result["receipt"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--stock-binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, default=REPO)
    parser.add_argument("--quick", action="store_true", help="skip large cutover cases")
    parser.add_argument("--no-verify-corpus", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    binary = args.binary.resolve(strict=True)
    stock = args.stock_binary.resolve(strict=True)
    manifest_path = args.manifest.resolve(strict=True)
    if args.output.exists():
        raise SystemExit(f"refusing to replace existing result: {args.output}")
    manifest = load_manifest(manifest_path)
    if not args.no_verify_corpus:
        verify_manifest_files(manifest_path, manifest)

    rows = []
    failures = []
    selected = [case for case in cases(manifest_path, manifest) if not (args.quick and case.slow)]
    for case in selected:
        try:
            normal = run_once(
                binary=binary,
                args=case.args,
                cwd=args.cwd,
                background=False,
                stdin=case.stdin,
            )
            background = run_once(
                binary=binary,
                args=case.args,
                cwd=args.cwd,
                background=True,
                receipt_policy=case.receipt_policy,
                receipt_required=case.receipt_required,
                stdin=case.stdin,
            )
            upstream = run_once(
                binary=stock,
                args=case.args,
                cwd=args.cwd,
                background=False,
                stdin=case.stdin,
            )
            assert_exact_output(normal, background, f"{case.name}: normal/background")
            assert_exact_output(upstream, normal, f"{case.name}: upstream/normal")
            row = {
                "name": case.name,
                "args": list(case.args),
                "receipt_policy": case.receipt_policy,
                "equal": True,
                "normal": compact(normal),
                "background": compact(background),
                "upstream": compact(upstream),
            }
        except Exception as error:  # Preserve all completed evidence before failing.
            failures.append(case.name)
            row = {
                "name": case.name,
                "args": list(case.args),
                "receipt_policy": case.receipt_policy,
                "equal": False,
                "error": str(error),
            }
        rows.append(row)
        print(f"{case.name}: {'ok' if row['equal'] else 'FAILED'}", flush=True)

    record = {
        "schema": "ripgrep.fre-aot-background.correctness.v1",
        "comparison": "identical exit status and byte-identical stdout/stderr",
        "candidate_flag": "--fre-aot-background",
        "receipt_transport": "RG_FRE_AOT_BACKGROUND_RECEIPT unique create-new path",
        "quick": args.quick,
        "binary": {"path": str(binary), "sha256": sha256(binary)},
        "stock_binary": {"path": str(stock), "sha256": sha256(stock)},
        "manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
        "case_count": len(rows),
        "failed": failures,
        "cases": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"cases": len(rows), "failed": failures}, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

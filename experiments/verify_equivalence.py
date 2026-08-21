#!/usr/bin/env python3
"""Compare one-process FRE queries with the untouched upstream rg binary."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "target/release/rg"
STOCK = ROOT / "artifacts/bin/rg-stock-f9c05a9"
INPUT = "experiments/correctness-input.txt"
NO_MATCH = "experiments/no-match.txt"

ORDERED = r"(?:ab|a)"
OVERLAP = r"(?:aaaaaaaaab|aaaaaaaab|aaaaaaab|aaaaaab|aaaaab|aaaab|aaab|aab|ab)"
BOUNDED = r"a{0,100}b"
AMBIGUOUS = r"(?:a|aa)*b"
TRACE = r"ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT"


CASES = [
    ("ordered_lines", ["-n", ORDERED, INPUT], None),
    ("ordered_only_matching", ["-o", ORDERED, INPUT], None),
    ("ordered_replace", ["--replace", "<$0>", ORDERED, INPUT], None),
    ("ordered_color", ["--color=always", "-n", ORDERED, INPUT], None),
    ("overlap_lines", ["-n", OVERLAP, INPUT], None),
    ("overlap_only_matching", ["-o", OVERLAP, INPUT], None),
    ("bounded_lines", ["-n", BOUNDED, INPUT], None),
    ("bounded_only_matching", ["-o", BOUNDED, INPUT], None),
    ("ambiguous_lines", ["-n", AMBIGUOUS, INPUT], None),
    ("ambiguous_only_matching", ["-o", AMBIGUOUS, INPUT], None),
    ("trace_lines", ["-n", TRACE, INPUT], None),
    ("trace_files_with_matches", ["--files-with-matches", TRACE, INPUT], None),
    ("registered_no_match", [TRACE, NO_MATCH], None),
    ("registry_miss", ["-n", "foo|bar", INPUT], None),
    ("fallback_ignore_case", ["-i", "-n", ORDERED, INPUT], None),
    ("fallback_fixed_strings", ["-F", "-n", ORDERED, INPUT], None),
    (
        "fallback_multiple_patterns",
        ["-n", "-e", ORDERED, "-e", "foo", INPUT],
        None,
    ),
    ("stdin", ["-n", ORDERED], (ROOT / INPUT).read_bytes()),
    (
        "parallel_prepared_handles",
        ["-q", "-j4", ORDERED, "experiments/correctness-corpus"],
        None,
    ),
]

for pattern_id, pattern in (("ambiguous", AMBIGUOUS), ("bounded", BOUNDED)):
    for size_id in ("64k", "1m", "64m"):
        for scenario_id in ("negative", "sparse-final-b"):
            path = f"experiments/bench-data/shapes/a-run-{scenario_id}-{size_id}.log"
            CASES.append(
                (
                    f"{pattern_id}_{scenario_id.replace('-', '_')}_{size_id}",
                    ["--count", pattern, path],
                    None,
                )
            )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def invoke(binary: Path, args: list[str], stdin: bytes | None, fre: bool):
    command = [str(binary)]
    if fre:
        command.append("--engine=fre")
    command.extend(args)
    return subprocess.run(
        command,
        cwd=ROOT,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> None:
    results = []
    failed = []
    for name, args, stdin in CASES:
        stock = invoke(STOCK, args, stdin, fre=False)
        candidate = invoke(CANDIDATE, args, stdin, fre=True)
        equal = (
            stock.returncode == candidate.returncode
            and stock.stdout == candidate.stdout
            and stock.stderr == candidate.stderr
        )
        row = {
            "name": name,
            "args": args,
            "equal": equal,
            "stock": {
                "status": stock.returncode,
                "stdout_bytes": len(stock.stdout),
                "stdout_sha256": digest(stock.stdout),
                "stderr_bytes": len(stock.stderr),
                "stderr_sha256": digest(stock.stderr),
            },
            "fre": {
                "status": candidate.returncode,
                "stdout_bytes": len(candidate.stdout),
                "stdout_sha256": digest(candidate.stdout),
                "stderr_bytes": len(candidate.stderr),
                "stderr_sha256": digest(candidate.stderr),
            },
        }
        results.append(row)
        if not equal:
            failed.append(name)

    output = {
        "schema": "rg-fre-aot-equivalence-v1",
        "stock_binary": str(STOCK.relative_to(ROOT)),
        "candidate_binary": str(CANDIDATE.relative_to(ROOT)),
        "comparison": "byte-identical stdout+stderr and identical exit status",
        "case_count": len(results),
        "failed": failed,
        "cases": results,
    }
    destination = ROOT / "artifacts/raw/correctness.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"case_count": len(results), "failed": failed}))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

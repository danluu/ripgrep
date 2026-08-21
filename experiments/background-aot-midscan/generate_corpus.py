#!/usr/bin/env python3
"""Generate the deterministic newline-dense mid-scan benchmark corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import BinaryIO, Iterable


HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "data"
MIB = 1024 * 1024
SCHEMA = "ripgrep.fre-aot-background-midscan-corpus.v1"
PATTERN = r"a{0,99}b"


class HashingWriter:
    def __init__(self, output: BinaryIO) -> None:
        self.output = output
        self.digest = hashlib.sha256()
        self.bytes = 0

    def write(self, data: bytes) -> None:
        self.output.write(data)
        self.digest.update(data)
        self.bytes += len(data)


def write_repeated(output: HashingWriter, data: bytes, count: int) -> None:
    """Write ``data`` count times without constructing the whole file."""
    lines_per_chunk = max(1, MIB // len(data))
    chunk = data * lines_per_chunk
    while count >= lines_per_chunk:
        output.write(chunk)
        count -= lines_per_chunk
    if count:
        output.write(data * count)


def write_dense_file(
    path: Path,
    *,
    total_bytes: int,
    line_bytes: int,
    matching_lines: Iterable[int] = (),
) -> dict[str, object]:
    if total_bytes % line_bytes:
        raise ValueError("file size must be an integral number of lines")
    line_count = total_bytes // line_bytes
    selected = sorted(set(matching_lines))
    if any(index < 0 or index >= line_count for index in selected):
        raise ValueError("matching line index lies outside the file")
    negative = b"a" * (line_bytes - 2) + b"c\n"
    positive = b"a" * (line_bytes - 2) + b"b\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as raw:
        output = HashingWriter(raw)
        cursor = 0
        for index in selected:
            write_repeated(output, negative, index - cursor)
            output.write(positive)
            cursor = index + 1
        write_repeated(output, negative, line_count - cursor)
    if output.bytes != total_bytes:
        raise RuntimeError(
            f"wrote {output.bytes} bytes to {path}, expected {total_bytes}"
        )
    return {
        "path": str(path),
        "bytes": output.bytes,
        "sha256": output.digest.hexdigest(),
        "line_bytes": line_bytes,
        "matching_lines": selected,
    }


def copy_dense_file(
    source: Path, destination: Path, template: dict[str, object]
) -> dict[str, object]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return {
        **template,
        "path": str(destination),
        "matching_lines": [],
    }


def relative_row(row: dict[str, object], root: Path) -> dict[str, object]:
    return {**row, "path": str(Path(str(row["path"])).relative_to(root))}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--single-mib",
        type=int,
        action="append",
        help="single-file size; repeat for a matrix (default: 64, 256, 1024)",
    )
    parser.add_argument("--tree-files", type=int, default=16)
    parser.add_argument("--tree-file-mib", type=int, default=64)
    parser.add_argument("--correctness-mib", type=int, default=64)
    parser.add_argument("--line-bytes", type=int, default=4096)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    single_mib = sorted(set(args.single_mib or (64, 256, 1024)))
    if not single_mib or any(size <= 0 for size in single_mib):
        raise SystemExit("--single-mib values must be positive")
    if args.tree_files < 16:
        raise SystemExit("--tree-files must be at least 16")
    if args.tree_file_mib <= 0 or args.correctness_mib <= 16:
        raise SystemExit(
            "tree files must be positive and correctness must exceed 16 MiB"
        )
    if args.line_bytes < 128 or MIB % args.line_bytes:
        raise SystemExit("--line-bytes must be at least 128 and divide one MiB")

    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to replace existing corpus: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.staging-{os.getpid()}"
    if staging.exists():
        raise SystemExit(f"staging path already exists: {staging}")
    staging.mkdir()
    try:
        line_bytes = args.line_bytes
        gate_bytes = 8 * MIB
        correctness_lines = (4 * MIB // line_bytes, 16 * MIB // line_bytes)
        correctness = write_dense_file(
            staging / "correctness" / "two-matches.log",
            total_bytes=args.correctness_mib * MIB,
            line_bytes=line_bytes,
            matching_lines=correctness_lines,
        )

        singles = []
        for size_mib in single_mib:
            singles.append(
                write_dense_file(
                    staging / "single" / f"negative-{size_mib}m.log",
                    total_bytes=size_mib * MIB,
                    line_bytes=line_bytes,
                )
            )

        first = write_dense_file(
            staging / "tree" / "shard-000.log",
            total_bytes=args.tree_file_mib * MIB,
            line_bytes=line_bytes,
        )
        tree = [first]
        for index in range(1, args.tree_files):
            tree.append(
                copy_dense_file(
                    Path(str(first["path"])),
                    staging / "tree" / f"shard-{index:03}.log",
                    first,
                )
            )

        manifest = {
            "schema": SCHEMA,
            "generator": "experiments/background-aot-midscan/generate_corpus.py",
            "pattern": PATTERN,
            "line_bytes": line_bytes,
            "publication_gate_bytes": gate_bytes,
            "description": "newline-dense a...c records with no b except two correctness witnesses",
            "correctness": relative_row(correctness, staging),
            "singles": [relative_row(row, staging) for row in singles],
            "tree": {
                "file_bytes": args.tree_file_mib * MIB,
                "files": [relative_row(row, staging) for row in tree],
            },
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    print(
        json.dumps(
            {
                "output": str(output),
                "single_mib": single_mib,
                "tree_files": args.tree_files,
                "tree_file_mib": args.tree_file_mib,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

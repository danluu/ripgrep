#!/usr/bin/env python3
"""Generate deterministic multi-file corpora for background-AOT cutover tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import BinaryIO, Callable

from common import DEFAULT_DATA


MIB = 1024 * 1024
MIXED_LINES = (
    b"2026-08-20T12:00:00Z INFO worker=alpha message=ordinary payload=cccccccccccccccccccccccc status=OK\n",
    b"2026-08-20T12:00:01Z WARN worker=beta message=aaaaaaaaab payload=aaaaaaaab status=RETRY\n",
    b"2026-08-20T12:00:02Z ERROR worker=gamma event=ERR_SYS payload=ordinary status=FAILED\n",
    b"2026-08-20T12:00:03Z INFO worker=delta event=PME_TURN_OFF payload=abababab status=DONE\n",
    b"2026-08-20T12:00:04Z DEBUG worker=epsilon event=LINK_REQ_RST payload=aaaaaaaaab status=OK\n",
    b"2026-08-20T12:00:05Z INFO worker=zeta event=CFG_BME_EVT payload=ordinary status=OK\n",
)
MIXED_CHUNK = b"".join(MIXED_LINES) * 4096
COPY_CHUNK = 1024 * 1024


class HashingWriter:
    def __init__(self, destination: BinaryIO) -> None:
        self.destination = destination
        self.digest = hashlib.sha256()
        self.bytes = 0

    def write(self, data: bytes) -> None:
        self.destination.write(data)
        self.digest.update(data)
        self.bytes += len(data)


def write_repeated_a(output: HashingWriter, total_bytes: int, suffix: bytes) -> None:
    if len(suffix) >= total_bytes:
        raise ValueError("suffix must be shorter than one shard")
    remaining = total_bytes - len(suffix)
    chunk = b"a" * COPY_CHUNK
    while remaining:
        piece = chunk[:remaining]
        output.write(piece)
        remaining -= len(piece)
    output.write(suffix)


def write_mixed_log(output: HashingWriter, total_bytes: int) -> None:
    remaining = total_bytes
    while remaining:
        piece = MIXED_CHUNK[:remaining]
        output.write(piece)
        remaining -= len(piece)


def write_bytes_repeated(output: HashingWriter, total_bytes: int, data: bytes) -> None:
    if not data:
        raise ValueError("cannot repeat an empty source corpus")
    remaining = total_bytes
    while remaining:
        piece = data[:remaining]
        output.write(piece)
        remaining -= len(piece)


def write_first(
    path: Path, writer: Callable[[HashingWriter, int], None], shard_bytes: int
) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as raw:
        output = HashingWriter(raw)
        writer(output, shard_bytes)
    if output.bytes != shard_bytes:
        raise RuntimeError(f"writer produced {output.bytes} bytes, expected {shard_bytes}")
    return output.bytes, output.digest.hexdigest()


def materialize_copies(first: Path, paths: list[Path], storage: str) -> None:
    for path in paths[1:]:
        if storage == "hardlink":
            os.link(first, path)
        else:
            shutil.copyfile(first, path)


def generate_scenario(
    root: Path,
    name: str,
    shards: int,
    shard_bytes: int,
    storage: str,
    writer: Callable[[HashingWriter, int], None],
    description: str,
) -> dict:
    paths = [root / "scenarios" / name / f"shard-{index:03}.log" for index in range(shards)]
    size, digest = write_first(paths[0], writer, shard_bytes)
    materialize_copies(paths[0], paths, storage)
    return {
        "description": description,
        "storage": storage,
        "files": [
            {
                "path": str(path.relative_to(root)),
                "bytes": size,
                "sha256": digest,
            }
            for path in paths
        ],
    }


def write_small(root: Path, relative: str, data: bytes) -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
    return {
        "path": relative,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def tracked_text(repo: Path) -> tuple[bytes, str, int]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    names = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.split(b"\0")
    chunks: list[bytes] = []
    included = 0
    for encoded in names:
        if not encoded:
            continue
        path = repo / encoded.decode("utf-8", "surrogateescape")
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        chunks.append(data)
        if data and not data.endswith(b"\n"):
            chunks.append(b"\n")
        included += 1
    return b"".join(chunks), commit, included


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--shards", type=int, default=16)
    parser.add_argument("--shard-mib", type=int, default=64)
    parser.add_argument(
        "--semantic-files",
        type=int,
        default=4096,
        help="tiny files used to force a mid-search nullable-pattern cutover",
    )
    parser.add_argument(
        "--storage",
        choices=("copy", "hardlink"),
        default="copy",
        help="copy is the primary protocol; hardlink is a space-saving pilot only",
    )
    parser.add_argument(
        "--source-repo",
        type=Path,
        help="optionally add a source-shaped scenario from tracked non-NUL files",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.shards < 16:
        raise SystemExit("--shards must be at least 16 for the predeclared matrix")
    if args.shard_mib <= 0:
        raise SystemExit("--shard-mib must be positive")
    if args.semantic_files < 1024:
        raise SystemExit("--semantic-files must be at least 1024")
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to replace existing corpus directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.staging-{os.getpid()}"
    if staging.exists():
        raise SystemExit(f"staging path already exists: {staging}")
    staging.mkdir()
    shard_bytes = args.shard_mib * MIB
    try:
        scenarios = {
            "a_negative": generate_scenario(
                staging,
                "a-negative",
                args.shards,
                shard_bytes,
                args.storage,
                lambda output, size: write_repeated_a(output, size, b"c\n"),
                "one long run of a bytes ending in c+LF; no final b",
            ),
            "a_positive": generate_scenario(
                staging,
                "a-positive",
                args.shards,
                shard_bytes,
                args.storage,
                lambda output, size: write_repeated_a(output, size, b"b\n"),
                "one long run of a bytes ending in b+LF",
            ),
            "mixed_log": generate_scenario(
                staging,
                "mixed-log",
                args.shards,
                shard_bytes,
                args.storage,
                write_mixed_log,
                "newline-dense deterministic synthetic logs",
            ),
        }
        source = None
        if args.source_repo is not None:
            data, commit, included = tracked_text(args.source_repo.resolve())
            scenarios["source_shaped"] = generate_scenario(
                staging,
                "source-shaped",
                args.shards,
                shard_bytes,
                args.storage,
                lambda output, size: write_bytes_repeated(output, size, data),
                "tracked non-NUL source concatenation repeated to the shard boundary",
            )
            source = {
                "repo": str(args.source_repo.resolve()),
                "commit": commit,
                "tracked_text_files": included,
                "one_pass_bytes": len(data),
                "one_pass_sha256": hashlib.sha256(data).hexdigest(),
            }

        correctness_files = [
            write_small(
                staging,
                "correctness/input.txt",
                b"ab a aaaaaaaaab\nERR_SYS ordinary\nfoo BAR\nempty-next\n\n",
            ),
            write_small(
                staging,
                "correctness/no-match.txt",
                b"ordinary text without any selected witness\n",
            ),
            write_small(
                staging,
                "correctness/second.txt",
                b"aab\nCFG_BME_EVT\nbar\n",
            ),
        ]
        for index in range(args.semantic_files):
            correctness_files.append(
                write_small(
                    staging,
                    f"correctness/nullable-many/file-{index:05}.txt",
                    b"bbb\n\naba\n",
                )
            )
        correctness = {
            "description": "small output-mode and fallback fixtures",
            "nullable_many_files": args.semantic_files,
            "files": correctness_files,
        }
        manifest = {
            "schema": "ripgrep.fre-aot-background-corpus.v1",
            "generator": "experiments/background-aot/generate_corpus.py",
            "shard_bytes": shard_bytes,
            "shards_per_scenario": args.shards,
            "storage": args.storage,
            "semantic_files": args.semantic_files,
            "primary_storage_required": "copy",
            "scenarios": scenarios,
            "correctness": correctness,
            "source": source,
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
                "shard_bytes": shard_bytes,
                "shards_per_scenario": args.shards,
                "semantic_files": args.semantic_files,
                "storage": args.storage,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

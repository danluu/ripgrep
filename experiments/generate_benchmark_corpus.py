#!/usr/bin/env python3
"""Generate a deterministic text/log corpus for the one-query benchmark."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "experiments/bench-data/mixed-logs-64m.log"
REAL_SOURCE_REPO = Path("/Users/danluu/dev/ripgrep")
REAL_SOURCE_DESTINATION = ROOT / "experiments/bench-data/ripgrep-source-concat.log"
SHAPE_DIRECTORY = ROOT / "experiments/bench-data/shapes"
TARGET_BYTES = 64 * 1024 * 1024
LINES = (
    b"2026-08-20T12:00:00Z INFO worker=alpha message=ordinary payload=cccccccccccccccccccccccc status=OK\n",
    b"2026-08-20T12:00:01Z WARN worker=beta message=aaaaaaaaab payload=aaaaaaaab status=RETRY\n",
    b"2026-08-20T12:00:02Z ERROR worker=gamma event=ERR_SYS payload=ordinary status=FAILED\n",
    b"2026-08-20T12:00:03Z INFO worker=delta event=PME_TURN_OFF payload=abababab status=DONE\n",
    b"2026-08-20T12:00:04Z DEBUG worker=epsilon event=LINK_REQ_RST payload=aaaaaaaaab status=OK\n",
    b"2026-08-20T12:00:05Z INFO worker=zeta event=CFG_BME_EVT payload=ordinary status=OK\n",
)
CHUNK = b"".join(LINES) * 4096


def generate_mixed_logs() -> None:
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    remaining = TARGET_BYTES
    with DESTINATION.open("wb") as output:
        while remaining:
            piece = CHUNK[:remaining]
            output.write(piece)
            remaining -= len(piece)
    print(f"{DESTINATION}: {DESTINATION.stat().st_size} bytes")


def generate_real_source() -> None:
    names = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REAL_SOURCE_REPO,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.split(b"\0")
    included = 0
    with REAL_SOURCE_DESTINATION.open("wb") as output:
        for encoded_name in names:
            if not encoded_name:
                continue
            source = REAL_SOURCE_REPO / encoded_name.decode("utf-8", "surrogateescape")
            if not source.is_file():
                continue
            data = source.read_bytes()
            if b"\0" in data:
                continue
            output.write(data)
            if data and not data.endswith(b"\n"):
                output.write(b"\n")
            included += 1
    print(
        f"{REAL_SOURCE_DESTINATION}: {REAL_SOURCE_DESTINATION.stat().st_size} "
        f"bytes from {included} tracked text files"
    )


def write_repeated_a(path: Path, total_bytes: int, suffix: bytes) -> None:
    if len(suffix) >= total_bytes:
        raise ValueError("suffix must be smaller than corpus")
    remaining = total_bytes - len(suffix)
    chunk = b"a" * (1024 * 1024)
    with path.open("wb") as output:
        while remaining:
            piece = chunk[:remaining]
            output.write(piece)
            remaining -= len(piece)
        output.write(suffix)


def generate_shape_corpora() -> None:
    SHAPE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for label, size in (("64k", 64 * 1024), ("1m", 1024 * 1024), ("64m", 64 * 1024 * 1024)):
        negative = SHAPE_DIRECTORY / f"a-run-negative-{label}.log"
        sparse = SHAPE_DIRECTORY / f"a-run-sparse-final-b-{label}.log"
        write_repeated_a(negative, size, b"c\n")
        write_repeated_a(sparse, size, b"b\n")
        print(f"{negative}: {negative.stat().st_size} bytes")
        print(f"{sparse}: {sparse.stat().st_size} bytes")


def main() -> None:
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    generate_mixed_logs()
    generate_real_source()
    generate_shape_corpora()


if __name__ == "__main__":
    main()

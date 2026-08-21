"""Fresh-process invocation support shared by correctness and timing harnesses."""

from __future__ import annotations

import hashlib
import os
import resource
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from common import BACKGROUND_FLAG, RECEIPT_ENV, read_receipt


def _cpu_ns(usage: resource.struct_rusage, field: str) -> int:
    return round(getattr(usage, field) * 1_000_000_000)


def output_record(data: bytes, retain_bytes: bool = True) -> dict[str, Any]:
    record: dict[str, Any] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if retain_bytes:
        record["hex"] = data.hex()
    return record


def run_once(
    *,
    binary: Path,
    args: Sequence[str],
    cwd: Path,
    background: bool,
    receipt_policy: str = "observe",
    receipt_required: bool = True,
    stdin: bytes | None = None,
    extra_env: Mapping[str, str] | None = None,
    retain_output_bytes: bool = True,
    temp_root: Path | None = None,
) -> dict[str, Any]:
    """Run one query in one new process.

    The wall clock starts immediately before ``subprocess.run`` and stops only
    after the process exits and its ordinary output pipes are drained. The
    process writes the optional background-AOT receipt before exit, so compiler
    construction, publication, receipt serialization, and process cleanup are
    all inside this boundary. Receipt parsing and temporary-directory removal
    happen after the clock stops.
    """
    binary = binary.resolve()
    command = [str(binary)]
    if background:
        command.append(BACKGROUND_FLAG)
    command.extend(args)

    if temp_root is not None:
        temp_root.mkdir(parents=True, exist_ok=True)
        temp_parent = str(temp_root)
    else:
        temp_parent = None
    with tempfile.TemporaryDirectory(
        prefix="rg-fre-aot-background-invocation-", dir=temp_parent
    ) as temporary_text:
        temporary = Path(temporary_text)
        receipt_path = temporary / "receipt.json"
        environment = os.environ.copy()
        environment.pop(RECEIPT_ENV, None)
        environment["TMPDIR"] = str(temporary)
        if extra_env is not None:
            environment.update(extra_env)
        if background:
            # The core writer uses create-new publication. The harness
            # deliberately passes a path that does not yet exist.
            environment[RECEIPT_ENV] = str(receipt_path)

        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter_ns()
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        elapsed_ns = time.perf_counter_ns() - started
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)

        receipt = None
        if background and receipt_path.is_file():
            receipt = read_receipt(receipt_path, receipt_policy)
        elif background and receipt_required:
            raise RuntimeError(
                f"background invocation did not publish required receipt {receipt_path}"
            )
        expected = {receipt_path.name} if receipt_path.is_file() else set()
        leftovers = sorted(
            str(path.relative_to(temporary))
            for path in temporary.rglob("*")
            if str(path.relative_to(temporary)) not in expected
        )
        if leftovers:
            raise RuntimeError(
                "invocation left unexpected files in its isolated TMPDIR: "
                + ", ".join(leftovers)
            )

    return {
        "command": command,
        "background": background,
        "elapsed_ns": elapsed_ns,
        "user_cpu_ns": _cpu_ns(usage_after, "ru_utime")
        - _cpu_ns(usage_before, "ru_utime"),
        "system_cpu_ns": _cpu_ns(usage_after, "ru_stime")
        - _cpu_ns(usage_before, "ru_stime"),
        "status": completed.returncode,
        "stdout": output_record(completed.stdout, retain_output_bytes),
        "stderr": output_record(completed.stderr, retain_output_bytes),
        "receipt": receipt,
        "tmpdir_unexpected_files": [],
    }


def assert_exact_output(left: dict[str, Any], right: dict[str, Any], label: str) -> None:
    for key in ("status",):
        if left[key] != right[key]:
            raise RuntimeError(
                f"{label}: {key} differs: {left[key]!r} != {right[key]!r}"
            )
    for stream in ("stdout", "stderr"):
        if left[stream]["sha256"] != right[stream]["sha256"] or left[stream][
            "bytes"
        ] != right[stream]["bytes"]:
            raise RuntimeError(
                f"{label}: {stream} differs: "
                f"{left[stream]['bytes']} bytes/{left[stream]['sha256']} != "
                f"{right[stream]['bytes']} bytes/{right[stream]['sha256']}"
            )
        # When callers retain bytes, require literal equality too. A digest is
        # an artifact convenience, not the correctness oracle.
        if "hex" in left[stream] and left[stream].get("hex") != right[stream].get("hex"):
            raise RuntimeError(f"{label}: {stream} bytes differ")

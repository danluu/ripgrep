#!/usr/bin/env python3
"""Run the sealed four-arm retained-mask scanner-delta experiment.

This is deliberately a control runner, not a build driver. It accepts two
already-qualified ripgrep binaries, authenticates their exact source and FRE
identities plus their independent selected-or-stock probes, and times only the
four arms registered below. The companion ``audit_scanner_delta.py`` is an
offline, independently implemented verifier for the emitted artifacts.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import stat
import statistics
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence

import harness as representative


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AUDITOR = HERE / "audit_scanner_delta.py"

SCHEMA = "background-aot-scanner-delta-v1"
PREREG_SCHEMA = f"{SCHEMA}.preregistration"
PRIVATE_SCHEMA = f"{SCHEMA}.private"
PUBLIC_SCHEMA = f"{SCHEMA}.public"
AUDIT_SCHEMA = f"{SCHEMA}.audit"
CHECKPOINT_SCHEMA = f"{SCHEMA}.private-checkpoint-jsonl"
HOST_CAPABILITY_SCHEMA = f"{SCHEMA}.host-capability-v1"
PROTOCOL_SHA256 = (
    "e244d3b79d0430994c99abc2edc3d191c7a33ab8dcd5392bd9410a8b9c1670c5"
)
POLICY = "force-selected-or-stock"

OLD_SOURCE_COMMIT = "1aae40aefaab5cdf6142de0079dc51b622b4b589"
OLD_SOURCE_TREE = "44e2c9777143f2ddc9e4da5791b741e41c6a3b48"
OLD_BINARY_SHA256 = (
    "793d8971ea374448252e3cdbd2b22cadef99a9a9ad06acd7904aa0b3aba1e228"
)
OLD_FRE_COMMIT = "d2b352b7a051628bbcf8afc7f23d1362a850cb25"
OLD_FRE_TREE = "fc129a6436035103c3f5d3c589127a08f93ab3a0"
OLD_OPTIMIZER_VERSION = 25
OLD_PROBE_PRIVATE_SHA256 = (
    "872893a89d613a1c6c84dfbaa4037eb7925aa33dbb06c212675aa9956bca11bd"
)
OLD_PROBE_PUBLIC_SHA256 = (
    "0344f0befe93289643af6ea92d2cbb82fe5793031b95058d16e18164c431d27c"
)

NEW_SOURCE_COMMIT = "77ed5a475666d56dedd90200a8ffefeee543b949"
NEW_SOURCE_TREE = "60b89c07fc89a5115310ca8bb6996d47d9ce9c9d"
NEW_BINARY_SHA256 = (
    "72009b3cc591f4da60abbaaf391de7d823f503b42c2b7ea6a87bc8b3e3d2ce87"
)
NEW_FRE_COMMIT = "eca0972ff205daa860ca8cd20e125910b05baa34"
NEW_FRE_TREE = "07e72f0a7f6ade8acb15533fb041b6d60c81bc10"
NEW_OPTIMIZER_VERSION = 26
NEW_PROBE_PRIVATE_SHA256 = (
    "494229fb67d4d25df4b9a161587ab9576990ac9525dda83d8909fa329ed8023c"
)
NEW_PROBE_PUBLIC_SHA256 = (
    "296c5e01692a5f5f5e7a1e2631fe223103aa07aad3ce3eb8c29788273f30ec22"
)
NEW_QUALIFICATION_MANIFEST_SHA256 = (
    "92b7004df4d003ba9e1ee1ec60cf3ad202b799209e7d35f744db37cd3d730194"
)
NEW_QUALIFICATION_ARCHIVE_SHA256 = (
    "eb75c7fa645cfd2529bf4b1b1b6ff02a45cdfa9bd5b14f61fc724b55a89fa40b"
)

FIXED44_MANIFEST_SHA256 = (
    "35b0037122bf2ab9a2c1641a562f23f12b88856ceb66c713ceb9403adb541823"
)
SELECTED34_MANIFEST_SHA256 = (
    "b2e2ab1fcdc39d78e60eadb1bb34aeb3075ebf0133ef67532843d8da952cb951"
)
SELECTED34_IDS_SHA256 = (
    "a1887065aa4765351bc72564a566177334d58f0bc9fc2e119ce8648df647c68c"
)
COMPLEMENT10_MANIFEST_SHA256 = (
    "398657722d7192f0b641770e69fc390f808faf249efc02990667c0587a38a795"
)
COMPLEMENT10_IDS_SHA256 = (
    "6f3c3f59067b4769721b774a7ad8f3585d598680a4d73edc748a95fcb46b1fe2"
)

CPU_PROFILES = ("auto", "asimd", "sve", "sve2")
PANELS = representative.PANELS
EXPECTED_SVE_VL_BYTES = 16
TIMEOUT_SECONDS = 30.0
WARMUP_QUARTETS = 2
MEASURED_QUARTETS = 8
BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_LOW_INDEX = 250
BOOTSTRAP_HIGH_INDEX = 9749
BOOTSTRAP_DOMAIN = b"rg-aot-retained-mask-scanner-delta-v1-bootstrap"
METRICS = ("S", "C", "D", "R0", "R1")
STRATA = ("intention_to_treat", "selected34", "complement10")
PROFILE_TARGET_BITS = {
    "asimd": 1 << 32,
    "sve": 1 << 33,
    "sve2": (1 << 33) | (1 << 34),
}

# A=B0, B=B1, D=N1, C=N0. The first four orders are one cycle and the
# second four are its reverse orientation. Do not reorder this tuple.
ORDERS = (
    ("A", "B", "D", "C"),
    ("B", "D", "C", "A"),
    ("D", "C", "A", "B"),
    ("C", "A", "B", "D"),
    ("A", "C", "D", "B"),
    ("C", "D", "B", "A"),
    ("D", "B", "A", "C"),
    ("B", "A", "C", "D"),
)
ARM_RECORD = {
    "A": {
        "name": "B0",
        "binary_identity": "old",
        "background": True,
        "exact_teddy_policy_v2": POLICY,
    },
    "B": {
        "name": "B1",
        "binary_identity": "new",
        "background": True,
        "exact_teddy_policy_v2": POLICY,
    },
    "D": {
        "name": "N1",
        "binary_identity": "new",
        "background": False,
        "exact_teddy_policy_v2": None,
    },
    "C": {
        "name": "N0",
        "binary_identity": "old",
        "background": False,
        "exact_teddy_policy_v2": None,
    },
}


class ScannerDeltaError(RuntimeError):
    """A fail-closed scanner-delta protocol or evidence error."""


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def strict_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON trees without Python's ``True == 1`` coercion."""
    try:
        return canonical_json_bytes(left) == canonical_json_bytes(right)
    except (TypeError, ValueError, UnicodeError):
        return False


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        and value != "0" * 64
    )


def is_git_oid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{40}", value) is not None
        and value != "0" * 40
    )


def exact_keys(value: Any, keys: Iterable[str], label: str) -> Mapping[str, Any]:
    expected = set(keys)
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ScannerDeltaError(f"{label} fields do not match the sealed schema")
    return value


def positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def validate_capability_signature(value: Any) -> dict[str, Any]:
    signature = exact_keys(
        value,
        (
            "platform", "machine", "cpu_count", "sve_vector_length_bytes",
            "host_target_feature_bits", "requested_target_feature_bits_by_profile",
            "effective_target_feature_bits_by_profile",
        ),
        "host capability signature",
    )
    expected_profiles = set(CPU_PROFILES)
    requested = exact_keys(
        signature["requested_target_feature_bits_by_profile"],
        CPU_PROFILES,
        "requested host profile bits",
    )
    effective = exact_keys(
        signature["effective_target_feature_bits_by_profile"],
        CPU_PROFILES,
        "effective host profile bits",
    )
    if (
        not isinstance(signature["platform"], str)
        or not signature["platform"].startswith("Linux-")
        or signature["machine"] not in ("aarch64", "arm64")
        or not positive_int(signature["cpu_count"])
        or signature["sve_vector_length_bytes"] != EXPECTED_SVE_VL_BYTES
        or not isinstance(signature["host_target_feature_bits"], str)
        or re.fullmatch(r"0x[0-9a-f]+", signature["host_target_feature_bits"])
        is None
        or set(requested) != expected_profiles
        or set(effective) != expected_profiles
    ):
        raise ScannerDeltaError("host capability signature is invalid")
    host_bits = int(signature["host_target_feature_bits"], 16)
    required = (1 << 32) | (1 << 33) | (1 << 34)
    if host_bits & required != required:
        raise ScannerDeltaError("host lacks ASIMD/SVE/SVE2 capability")
    expected_bits = {
        "auto": host_bits,
        **PROFILE_TARGET_BITS,
    }
    for profile in CPU_PROFILES:
        expected = f"0x{expected_bits[profile]:x}"
        if requested[profile] != expected or effective[profile] != expected:
            raise ScannerDeltaError("effective host profile bits are invalid")
    return dict(signature)


def validate_capability_attestation(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    attestation = exact_keys(
        value,
        ("schema", "canonical_json_ascii", "sha256"),
        "host capability attestation",
    )
    encoded_text = attestation["canonical_json_ascii"]
    if (
        attestation["schema"] != HOST_CAPABILITY_SCHEMA
        or not isinstance(encoded_text, str)
        or not is_sha256(attestation["sha256"])
    ):
        raise ScannerDeltaError("host capability attestation is invalid")
    try:
        encoded = encoded_text.encode("ascii")
        signature = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScannerDeltaError("host capability attestation is malformed") from error
    validated = validate_capability_signature(signature)
    if (
        encoded != canonical_json_bytes(validated)
        or sha256_bytes(encoded) != attestation["sha256"]
    ):
        raise ScannerDeltaError("host capability attestation bytes changed")
    return dict(attestation), validated


def _single_feature_key(value: Any, label: str) -> str:
    counts = exact_keys(value, tuple(value) if isinstance(value, Mapping) else (), label)
    keys = [key for key, count in counts.items() if key != "unreported" and positive_int(count)]
    if len(keys) != 1 or set(counts) != set(keys):
        raise ScannerDeltaError(f"{label} is not a single reported feature mask")
    key = keys[0]
    if not isinstance(key, str) or re.fullmatch(r"0x[0-9a-f]+", key) is None:
        raise ScannerDeltaError(f"{label} feature mask is invalid")
    return key


def probe_capability_signature(public: Mapping[str, Any]) -> dict[str, Any]:
    host = exact_keys(
        public.get("host"),
        (
            "platform", "machine", "cpu_count", "python", "rustc", "cargo",
            "sve_vector_length_bytes",
        ),
        "probe host",
    )
    panels = public.get("panels")
    if not isinstance(panels, Mapping):
        raise ScannerDeltaError("probe panel capability evidence is missing")
    requested: dict[str, str] = {}
    effective: dict[str, str] = {}
    observed_hosts: set[str] = set()
    for profile in CPU_PROFILES:
        profile_requested: set[str] = set()
        profile_effective: set[str] = set()
        for panel in PANELS:
            aggregate = panels.get(f"{profile}/{panel}")
            if not isinstance(aggregate, Mapping):
                raise ScannerDeltaError("probe panel capability matrix is incomplete")
            selected = aggregate.get("all_selected")
            if not isinstance(selected, Mapping):
                raise ScannerDeltaError("probe panel all-selected evidence is missing")
            classification = selected.get("receipt_classification")
            if not isinstance(classification, Mapping):
                raise ScannerDeltaError("probe receipt classification is missing")
            profile_requested.add(_single_feature_key(
                classification.get("requested_target_feature_bits"),
                f"{profile}/{panel} requested features",
            ))
            profile_effective.add(_single_feature_key(
                classification.get("effective_target_feature_bits"),
                f"{profile}/{panel} effective features",
            ))
            observed_hosts.add(_single_feature_key(
                classification.get("host_target_feature_bits"),
                f"{profile}/{panel} host features",
            ))
        if len(profile_requested) != 1 or len(profile_effective) != 1:
            raise ScannerDeltaError("probe profile feature masks disagree by panel")
        requested[profile] = next(iter(profile_requested))
        effective[profile] = next(iter(profile_effective))
    matrix = public.get("target_validation_matrix")
    if (
        not isinstance(matrix, Mapping)
        or matrix.get("qualified") is not True
        or len(observed_hosts) != 1
        or matrix.get("global_qualified_host_feature_bits")
        != sorted(observed_hosts)
    ):
        raise ScannerDeltaError("probe target capability matrix is not qualified")
    return validate_capability_signature({
        "platform": host["platform"],
        "machine": host["machine"],
        "cpu_count": host["cpu_count"],
        "sve_vector_length_bytes": host["sve_vector_length_bytes"],
        "host_target_feature_bits": next(iter(observed_hosts)),
        "requested_target_feature_bits_by_profile": requested,
        "effective_target_feature_bits_by_profile": effective,
    })


def current_capability_signature() -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() not in ("aarch64", "arm64"):
        raise ScannerDeltaError("scanner-delta requires Linux AArch64")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        getauxval = libc.getauxval
        getauxval.argtypes = [ctypes.c_ulong]
        getauxval.restype = ctypes.c_ulong
        hwcap = int(getauxval(16))
        hwcap2 = int(getauxval(26))
    except (AttributeError, OSError, ValueError) as error:
        raise ScannerDeltaError("cannot snapshot AArch64 host capabilities") from error
    feature_bits = 0
    if hwcap & (1 << 1):
        feature_bits |= 1 << 32
    if hwcap & (1 << 22):
        feature_bits |= 1 << 33
    if hwcap2 & (1 << 1):
        feature_bits |= 1 << 34
    requested = {
        "auto": f"0x{feature_bits:x}",
        **{name: f"0x{bits:x}" for name, bits in PROFILE_TARGET_BITS.items()},
    }
    return validate_capability_signature({
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "sve_vector_length_bytes": representative.sve_vector_length_bytes(),
        "host_target_feature_bits": f"0x{feature_bits:x}",
        "requested_target_feature_bits_by_profile": requested,
        "effective_target_feature_bits_by_profile": dict(requested),
    })


def protocol_record() -> dict[str, Any]:
    """Return the immutable, result-blind experimental protocol."""
    return {
        "arms": ARM_RECORD,
        "orders": [list(order) for order in ORDERS],
        "warmup_quartets": WARMUP_QUARTETS,
        "warmup_schedule": (
            "stable canonical row ordinal minus 2, then minus 1, modulo 8"
        ),
        "measured_quartets": MEASURED_QUARTETS,
        "measured_schedule": (
            "stable canonical row ordinal plus measured index 0..7, modulo 8"
        ),
        "row_traversals": {
            "primary": "canonical",
            "reverse-row-confirmation": "reverse-canonical",
        },
        "profiles": list(CPU_PROFILES),
        "panels": list(PANELS),
        "expected_sve_vector_length_bytes": EXPECTED_SVE_VL_BYTES,
        "timeout_seconds": TIMEOUT_SECONDS,
        "policy": POLICY,
        "cohorts": {
            "intention_to_treat": {
                "count_panel_patterns": 44,
                "manifest_sha256": FIXED44_MANIFEST_SHA256,
                "result_blind": True,
            },
            "selected34": {
                "count_panel_patterns": 34,
                "manifest_sha256": SELECTED34_MANIFEST_SHA256,
                "private_ids_sha256": SELECTED34_IDS_SHA256,
                "result_blind": False,
                "source": "frozen pre-timing compiler fact",
            },
            "complement10": {
                "count_panel_patterns": 10,
                "manifest_sha256": COMPLEMENT10_MANIFEST_SHA256,
                "private_ids_sha256": COMPLEMENT10_IDS_SHA256,
                "result_blind": False,
                "source": "frozen pre-timing compiler fact complement",
            },
        },
        "metrics": {
            "S": "A/B = B0/B1",
            "C": "C/D = N0/N1",
            "D": "(D/B)/(C/A) = R1/R0 = S/C",
            "R0": "C/A = N0/B0",
            "R1": "D/B = N1/B1",
            "orientation": "all ratios greater than one favor the new scanner or background arm",
            "within_id": "median of eight complete measured quartets",
            "across_id": "equal-ID geometric mean of within-ID medians",
        },
        "diagnostic_splits": {
            "background_direction": (
                "S: per-ID median over four A-before-B orders versus four "
                "B-before-A orders, then equal-ID geometric means and ratio"
            ),
            "cycle_orientation": (
                "D: per-ID median over order indices 0..3 versus 4..7, then "
                "equal-ID geometric means and ratio"
            ),
        },
        "bootstrap": {
            "replicates": BOOTSTRAP_REPLICATES,
            "seed_preimage": (
                "ASCII domain || NUL || decode_hex(old binary) || "
                "decode_hex(new binary) || decode_hex(old private probe) || "
                "decode_hex(new private probe) || decode_hex(fixed44 manifest)"
            ),
            "domain": BOOTSTRAP_DOMAIN.decode("ascii"),
            "seed_integer": "unsigned big-endian first eight digest bytes",
            "loop_order": (
                "profile, panel, stratum (ITT/selected/complement), replicate"
            ),
            "resampling": (
                "draw n IDs with replacement; for each drawn occurrence draw "
                "eight complete four-arm quartets with replacement; derive "
                "S,C,D,R0,R1 jointly from the same draws"
            ),
            "metric_emission_order": list(METRICS),
            "percentile_indices": [BOOTSTRAP_LOW_INDEX, BOOTSTRAP_HIGH_INDEX],
        },
        "decision": {
            "primary_cell": {
                "profile": "auto",
                "panel": "fre-count-default-threads",
                "stratum": "intention_to_treat",
            },
            "direct_R1_target": 1.03,
            "clear_go": "R1 interval wholly above 1.03",
            "clear_no_go": "R1 interval wholly below 1.03",
            "scanner_win": {
                "ITT_S_interval_wholly_above": 1.0,
                "ITT_D_interval_wholly_above": 1.0,
                "selected34_D_interval_wholly_above": 1.0,
                "C_point_inclusive": [0.97, 1.03],
                "complement10_S_point_inclusive": [0.97, 1.03],
                "complement10_D_point_inclusive": [0.97, 1.03],
                "background_direction_ratio_inclusive": [0.95, 1.05],
                "cycle_orientation_ratio_inclusive": [0.95, 1.05],
            },
            "material_delta_D_point_at_least": 1.03,
            "reverse_confirmation_trigger": "any failed or inconclusive primary gate",
            "reverse_confirmation_analysis": (
                "validate runs separately; per-ID pool is sqrt(primary median "
                "times reverse median); equal-ID geometric-mean cells; joint "
                "bootstrap resamples the same IDs and independently resamples "
                "eight complete quartets within each run"
            ),
            "combined_enablement": {
                "both_run_R1_points_at_least": 1.03,
                "pooled_R1_interval_wholly_above": 1.03,
                "reverse_over_primary_R1_point_inclusive": [0.95, 1.05],
            },
            "combined_scanner_win": {
                "both_run_S_and_D_points_wholly_above": 1.0,
                "pooled_S_and_D_intervals_wholly_above": 1.0,
                "pooled_selected34_D_interval_wholly_above": 1.0,
                "pooled_C_point_inclusive": [0.97, 1.03],
                "pooled_complement10_S_D_points_inclusive": [0.97, 1.03],
                "reverse_over_primary_S_D_C_R1_inclusive": [0.95, 1.05],
                "each_run_direction_orientation_and_controls_must_pass": True,
            },
            "combined_clear_no_go": (
                "pooled R1 interval wholly below 1.03 or either run R1 point "
                "below 1.03"
            ),
            "combined_material_delta_D_point_at_least": 1.03,
            "pooling_cannot_rescue_direction_order_or_control_failure": True,
        },
        "correctness": {
            "statuses": [0, 1],
            "all_four_outputs_and_statuses_equal": True,
            "stderr_equal": True,
            "timeouts_allowed": False,
            "temporary_artifacts_allowed": False,
            "timed_receipts": False,
        },
        "failure_evidence": {
            "format": CHECKPOINT_SCHEMA,
            "mode": "0600",
            "append_only": True,
            "one_completed_row_event_per_row": True,
            "terminal_failure_has_safe_stage_and_reason": True,
            "public_success_written_on_failure": False,
        },
    }


def expected_identity_record(role: str) -> dict[str, Any]:
    if role == "old":
        return {
            "source_commit": OLD_SOURCE_COMMIT,
            "source_tree": OLD_SOURCE_TREE,
            "binary_sha256": OLD_BINARY_SHA256,
            "fre_commit": OLD_FRE_COMMIT,
            "fre_tree": OLD_FRE_TREE,
            "optimizer_version": OLD_OPTIMIZER_VERSION,
        }
    if role == "new":
        return {
            "source_commit": NEW_SOURCE_COMMIT,
            "source_tree": NEW_SOURCE_TREE,
            "binary_sha256": NEW_BINARY_SHA256,
            "fre_commit": NEW_FRE_COMMIT,
            "fre_tree": NEW_FRE_TREE,
            "optimizer_version": NEW_OPTIMIZER_VERSION,
        }
    raise ScannerDeltaError("unknown binary identity")


def expected_probe_hashes(role: str) -> tuple[str, str]:
    if role == "old":
        return OLD_PROBE_PRIVATE_SHA256, OLD_PROBE_PUBLIC_SHA256
    if role == "new":
        return NEW_PROBE_PRIVATE_SHA256, NEW_PROBE_PUBLIC_SHA256
    raise ScannerDeltaError("unknown probe identity")


def bootstrap_seed_record(prereg: Mapping[str, Any]) -> dict[str, Any]:
    identities = prereg["identities"]
    probes = prereg["qualification_probes"]
    preimage = (
        BOOTSTRAP_DOMAIN
        + b"\0"
        + bytes.fromhex(identities["old"]["binary_sha256"])
        + bytes.fromhex(identities["new"]["binary_sha256"])
        + bytes.fromhex(probes["old"]["private_sha256"])
        + bytes.fromhex(probes["new"]["private_sha256"])
        + bytes.fromhex(FIXED44_MANIFEST_SHA256)
    )
    digest = hashlib.sha256(preimage).digest()
    return {
        "sha256": digest.hex(),
        "u64_big_endian_first8": int.from_bytes(digest[:8], "big"),
    }


def load_preregistration(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScannerDeltaError("preregistration is not valid JSON") from error
    exact_keys(
        document,
        (
            "schema", "sealed_before_timing", "protocol", "identities",
            "qualification_probes", "qualification_artifacts", "inputs",
            "runner", "host_capability_attestation",
        ),
        "preregistration",
    )
    if raw != canonical_json_bytes(document):
        raise ScannerDeltaError("preregistration is not canonical JSON")
    if document["schema"] != PREREG_SCHEMA or document["sealed_before_timing"] is not True:
        raise ScannerDeltaError("preregistration schema or seal is invalid")
    if (
        document["protocol"] != protocol_record()
        or sha256_bytes(canonical_json_bytes(document["protocol"]))
        != PROTOCOL_SHA256
    ):
        raise ScannerDeltaError("preregistration protocol differs from sealed protocol")
    identities = exact_keys(document["identities"], ("old", "new"), "identities")
    for role in ("old", "new"):
        exact_keys(
            identities[role],
            (
                "source_commit", "source_tree", "binary_sha256",
                "fre_commit", "fre_tree", "optimizer_version",
            ),
            f"{role} identity",
        )
        if identities[role] != expected_identity_record(role):
            raise ScannerDeltaError(f"{role} identity is not the frozen identity")
    probes = exact_keys(
        document["qualification_probes"], ("old", "new"),
        "qualification probes",
    )
    for role in ("old", "new"):
        probe = exact_keys(
            probes[role],
            (
                "private_sha256", "public_sha256", "stock_binary_sha256",
                "stock_source_commit", "stock_source_tree",
            ),
            f"{role} qualification probe",
        )
        expected_private, expected_public = expected_probe_hashes(role)
        if (
            probe["private_sha256"] != expected_private
            or probe["public_sha256"] != expected_public
            or not is_sha256(probe["stock_binary_sha256"])
            or not is_git_oid(probe["stock_source_commit"])
            or not is_git_oid(probe["stock_source_tree"])
        ):
            raise ScannerDeltaError(f"{role} probe binding is invalid")
    qualification = exact_keys(
        document["qualification_artifacts"],
        ("new_manifest_sha256", "new_archive_sha256"),
        "qualification artifacts",
    )
    if qualification != {
        "new_manifest_sha256": NEW_QUALIFICATION_MANIFEST_SHA256,
        "new_archive_sha256": NEW_QUALIFICATION_ARCHIVE_SHA256,
    }:
        raise ScannerDeltaError("new qualification artifact binding is invalid")
    inputs = exact_keys(
        document["inputs"],
        (
            "selection_transport_sha256", "ripgrep_corpus_commit",
            "ripgrep_corpus_tree", "fre_corpus_commit", "fre_corpus_tree",
        ),
        "preregistered inputs",
    )
    if (
        not is_sha256(inputs["selection_transport_sha256"])
        or not all(is_git_oid(inputs[field]) for field in (
            "ripgrep_corpus_commit", "ripgrep_corpus_tree",
            "fre_corpus_commit", "fre_corpus_tree",
        ))
    ):
        raise ScannerDeltaError("preregistered input identity is invalid")
    runner = exact_keys(
        document["runner"],
        (
            "source_commit", "source_tree", "scanner_delta_sha256",
            "auditor_sha256",
        ),
        "runner binding",
    )
    if (
        not is_git_oid(runner["source_commit"])
        or not is_git_oid(runner["source_tree"])
        or not is_sha256(runner["scanner_delta_sha256"])
        or not is_sha256(runner["auditor_sha256"])
    ):
        raise ScannerDeltaError("runner identity is invalid")
    validate_capability_attestation(document["host_capability_attestation"])
    return dict(document), sha256_bytes(raw)


def geometric_mean(values: Sequence[float]) -> float:
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        raise ScannerDeltaError("geometric mean requires finite positive values")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def metric_values(elapsed: Mapping[str, int]) -> dict[str, float]:
    if set(elapsed) != {"A", "B", "C", "D"} or any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in elapsed.values()
    ):
        raise ScannerDeltaError("quartet timing is incomplete")
    a = elapsed["A"]
    b = elapsed["B"]
    c = elapsed["C"]
    d = elapsed["D"]
    result = {
        "S": a / b,
        "C": c / d,
        "D": (d / b) / (c / a),
        "R0": c / a,
        "R1": d / b,
    }
    if not math.isclose(result["D"], result["S"] / result["C"], rel_tol=1e-15):
        raise ScannerDeltaError("delta identity did not reconcile")
    return result


def median(values: Sequence[float]) -> float:
    if not values:
        raise ScannerDeltaError("median requires values")
    return float(statistics.median(values))


def row_summary(quartets: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(quartets) != MEASURED_QUARTETS:
        raise ScannerDeltaError("row does not contain eight measured quartets")
    order_indices = [quartet.get("order_index") for quartet in quartets]
    if sorted(order_indices) != list(range(MEASURED_QUARTETS)):
        raise ScannerDeltaError("row does not use every measured order exactly once")
    metrics = {
        metric: median([float(quartet["metrics"][metric]) for quartet in quartets])
        for metric in METRICS
    }
    a_before_b = [
        float(quartet["metrics"]["S"])
        for quartet in quartets
        if quartet["order"].index("A") < quartet["order"].index("B")
    ]
    b_before_a = [
        float(quartet["metrics"]["S"])
        for quartet in quartets
        if quartet["order"].index("B") < quartet["order"].index("A")
    ]
    first_cycle = [
        float(quartet["metrics"]["D"])
        for quartet in quartets if int(quartet["order_index"]) < 4
    ]
    reverse_cycle = [
        float(quartet["metrics"]["D"])
        for quartet in quartets if int(quartet["order_index"]) >= 4
    ]
    if not all(len(values) == 4 for values in (
        a_before_b, b_before_a, first_cycle, reverse_cycle,
    )):
        raise ScannerDeltaError("row split balance is incomplete")
    return {
        "metrics": metrics,
        "background_direction_S": {
            "A_before_B": median(a_before_b),
            "B_before_A": median(b_before_a),
        },
        "cycle_orientation_D": {
            "orders_0_3": median(first_cycle),
            "orders_4_7": median(reverse_cycle),
        },
    }


def bootstrap_seed_from_prereg(prereg: Mapping[str, Any]) -> int:
    return int(bootstrap_seed_record(prereg)["u64_big_endian_first8"])


def stratum_rows(
    rows: Sequence[Mapping[str, Any]], stratum: str,
) -> list[Mapping[str, Any]]:
    if stratum == "intention_to_treat":
        return list(rows)
    ids = (
        representative.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_PRIVATE_IDS
        if stratum == "selected34"
        else representative.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_PRIVATE_IDS
        if stratum == "complement10"
        else None
    )
    if ids is None:
        raise ScannerDeltaError("unknown aggregate stratum")
    return [row for row in rows if row["private_id"] in ids]


def point_aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ScannerDeltaError("aggregate stratum is empty")
    points = {
        metric: geometric_mean([
            float(row["summary"]["metrics"][metric]) for row in rows
        ])
        for metric in METRICS
    }
    direction_a = geometric_mean([
        float(row["summary"]["background_direction_S"]["A_before_B"])
        for row in rows
    ])
    direction_b = geometric_mean([
        float(row["summary"]["background_direction_S"]["B_before_A"])
        for row in rows
    ])
    orientation_first = geometric_mean([
        float(row["summary"]["cycle_orientation_D"]["orders_0_3"])
        for row in rows
    ])
    orientation_reverse = geometric_mean([
        float(row["summary"]["cycle_orientation_D"]["orders_4_7"])
        for row in rows
    ])
    return {
        "patterns": len(rows),
        "metrics": {
            metric: {"point": points[metric]} for metric in METRICS
        },
        "diagnostic_splits": {
            "background_direction_S": {
                "A_before_B": direction_a,
                "B_before_A": direction_b,
                "ratio": direction_a / direction_b,
            },
            "cycle_orientation_D": {
                "orders_0_3": orientation_first,
                "orders_4_7": orientation_reverse,
                "ratio": orientation_first / orientation_reverse,
            },
        },
    }


def add_bootstrap_intervals(
    aggregate: dict[str, Any],
    rows: Sequence[Mapping[str, Any]],
    rng: random.Random,
) -> None:
    if not rows:
        raise ScannerDeltaError("bootstrap stratum is empty")
    samples = {metric: [] for metric in METRICS}
    count = len(rows)
    for _ in range(BOOTSTRAP_REPLICATES):
        per_metric_logs = {metric: [] for metric in METRICS}
        for _ in range(count):
            row = rows[rng.randrange(count)]
            quartets = row["quartets"]
            chosen = [quartets[rng.randrange(MEASURED_QUARTETS)] for _ in range(MEASURED_QUARTETS)]
            for metric in METRICS:
                per_metric_logs[metric].append(math.log(median([
                    float(quartet["metrics"][metric]) for quartet in chosen
                ])))
        for metric in METRICS:
            samples[metric].append(math.exp(math.fsum(per_metric_logs[metric]) / count))
    for metric in METRICS:
        ordered = sorted(samples[metric])
        aggregate["metrics"][metric]["confidence_interval_95"] = [
            ordered[BOOTSTRAP_LOW_INDEX], ordered[BOOTSTRAP_HIGH_INDEX]
        ]


def aggregate_rows(
    rows: Sequence[Mapping[str, Any]], seed: int,
) -> dict[str, Any]:
    """Aggregate in the frozen profile/panel/stratum/RNG consumption order."""
    rng = random.Random(seed)
    cells: dict[str, Any] = {}
    for profile in CPU_PROFILES:
        cells[profile] = {}
        for panel in PANELS:
            panel_rows = [
                row for row in rows
                if row["cpu_profile"] == profile and row["panel"] == panel
            ]
            panel_rows.sort(key=lambda row: int(row["canonical_row_ordinal"]))
            cells[profile][panel] = {}
            for stratum in STRATA:
                selected = stratum_rows(panel_rows, stratum)
                aggregate = point_aggregate(selected)
                add_bootstrap_intervals(aggregate, selected, rng)
                cells[profile][panel][stratum] = aggregate
    return cells


def in_closed_interval(value: float, bounds: Sequence[float]) -> bool:
    return float(bounds[0]) <= value <= float(bounds[1])


def decision_record(cells: Mapping[str, Any]) -> dict[str, Any]:
    primary = cells["auto"]["fre-count-default-threads"]
    itt = primary["intention_to_treat"]
    selected = primary["selected34"]
    complement = primary["complement10"]
    r1 = itt["metrics"]["R1"]
    r1_low, r1_high = r1["confidence_interval_95"]
    direct = (
        "clear_go" if r1_low > 1.03
        else "clear_no_go" if r1_high < 1.03
        else "inconclusive"
    )
    requirements = {
        "direct_R1_point_at_least_1_03": r1["point"] >= 1.03,
        "direct_R1_interval_wholly_above_1_03": r1_low > 1.03,
        "ITT_S_interval_wholly_above_1": (
            itt["metrics"]["S"]["confidence_interval_95"][0] > 1.0
        ),
        "ITT_D_interval_wholly_above_1": (
            itt["metrics"]["D"]["confidence_interval_95"][0] > 1.0
        ),
        "selected34_D_interval_wholly_above_1": (
            selected["metrics"]["D"]["confidence_interval_95"][0] > 1.0
        ),
        "C_point_in_0_97_1_03": in_closed_interval(
            itt["metrics"]["C"]["point"], (0.97, 1.03)
        ),
        "complement10_S_point_in_0_97_1_03": in_closed_interval(
            complement["metrics"]["S"]["point"], (0.97, 1.03)
        ),
        "complement10_D_point_in_0_97_1_03": in_closed_interval(
            complement["metrics"]["D"]["point"], (0.97, 1.03)
        ),
        "background_direction_ratio_in_0_95_1_05": in_closed_interval(
            itt["diagnostic_splits"]["background_direction_S"]["ratio"],
            (0.95, 1.05),
        ),
        "cycle_orientation_ratio_in_0_95_1_05": in_closed_interval(
            itt["diagnostic_splits"]["cycle_orientation_D"]["ratio"],
            (0.95, 1.05),
        ),
        "material_D_point_at_least_1_03": (
            itt["metrics"]["D"]["point"] >= 1.03
        ),
    }
    triggers = [name for name, passed in requirements.items() if not passed]
    scanner_gate_names = (
        "ITT_S_interval_wholly_above_1",
        "ITT_D_interval_wholly_above_1",
        "selected34_D_interval_wholly_above_1",
        "C_point_in_0_97_1_03",
        "complement10_S_point_in_0_97_1_03",
        "complement10_D_point_in_0_97_1_03",
        "background_direction_ratio_in_0_95_1_05",
        "cycle_orientation_ratio_in_0_95_1_05",
    )
    scanner_win = all(requirements[name] for name in scanner_gate_names)
    material = requirements["material_D_point_at_least_1_03"]
    overall = (
        "go" if direct == "clear_go" and scanner_win and material
        else "no_go" if direct == "clear_no_go"
        else "inconclusive"
    )
    return {
        "primary_cell": {
            "profile": "auto",
            "panel": "fre-count-default-threads",
            "stratum": "intention_to_treat",
        },
        "direct_R1_classification": direct,
        "scanner_win": scanner_win,
        "material_delta": material,
        "requirements": requirements,
        "overall": overall,
        "reverse_row_confirmation_required": bool(triggers),
        "reverse_row_confirmation_triggers": triggers,
    }


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScannerDeltaError(f"{label} is not valid JSON") from error
    if not isinstance(value, Mapping):
        raise ScannerDeltaError(f"{label} is not a JSON object")
    return dict(value)


def normalize_bound_probe_optimizer(
    value: Any, *, role: str, expected: int,
) -> tuple[Any, int]:
    """Authenticate a probe optimizer and normalize only the sealed old copy.

    The representative validator remains unchanged: v7 generally requires
    optimizer 26. The sole optimizer-25 exception is an in-memory copy of the
    exact old probe whose source, binary, and file digests were already pinned.
    """
    count = 0

    def visit(item: Any) -> Any:
        nonlocal count
        if isinstance(item, list):
            return [visit(child) for child in item]
        if not isinstance(item, Mapping):
            return item
        copied = {key: visit(child) for key, child in item.items()}
        if (
            "optimizer_version" in item
            and "exact_finite_selected_end_teddy_policy" in item
            and "schema_version" in item
        ):
            if item.get("optimizer_version") != expected:
                raise ScannerDeltaError(
                    f"{role} probe optimizer identity is invalid"
                )
            count += 1
            if role == "old":
                copied["optimizer_version"] = NEW_OPTIMIZER_VERSION
        return copied

    normalized = visit(value)
    return normalized, count


def validate_qualification_probe(
    *,
    role: str,
    private_path: Path,
    public_path: Path,
    prereg: Mapping[str, Any],
    oot: Sequence[representative.QueryCase],
    wider: Sequence[representative.QueryCase],
) -> dict[str, Any]:
    expected_private, expected_public = expected_probe_hashes(role)
    actual_private = representative.sha256_file(private_path)
    actual_public = representative.sha256_file(public_path)
    if (actual_private, actual_public) != (expected_private, expected_public):
        raise ScannerDeltaError(f"{role} qualification probe hash changed")
    registered = prereg["qualification_probes"][role]
    if (
        registered["private_sha256"] != actual_private
        or registered["public_sha256"] != actual_public
    ):
        raise ScannerDeltaError(f"{role} probe is not preregistered")
    private = load_json_object(private_path, f"{role} private probe")
    public = load_json_object(public_path, f"{role} public probe")
    _, registered_host_signature = validate_capability_attestation(
        prereg["host_capability_attestation"]
    )
    if (
        private.get("schema")
        != f"{representative.RESULT_SCHEMA}.probe.private.v1"
        or public.get("schema")
        != f"{representative.RESULT_SCHEMA}.probe.public.v1"
        or public.get("private_result_sha256") != actual_private
        or public.get("aggregate_only") is not True
        or public.get("contains_patterns_commands_paths_or_per_pattern_rows")
        is not False
        or public.get("post_run_selection_verified") is not True
        or public.get("post_run_provenance_verified") is not True
    ):
        raise ScannerDeltaError(f"{role} probe envelope is invalid")
    identity = expected_identity_record(role)
    source = public.get("candidate_source")
    binary = public.get("binaries", {}).get("candidate")
    dependency = public.get("fre_dependency")
    stock_source = public.get("stock_source")
    stock_binary = public.get("binaries", {}).get("stock")
    if (
        not isinstance(source, Mapping)
        or source.get("commit") != identity["source_commit"]
        or source.get("tree") != identity["source_tree"]
        or source.get("clean") is not True
        or not isinstance(binary, Mapping)
        or binary.get("sha256") != identity["binary_sha256"]
        or not isinstance(dependency, Mapping)
        or dependency.get("manifest_revision") != identity["fre_commit"]
        or dependency.get("locked_revision") != identity["fre_commit"]
        or not isinstance(stock_source, Mapping)
        or stock_source.get("commit") != registered["stock_source_commit"]
        or stock_source.get("tree") != registered["stock_source_tree"]
        or stock_source.get("clean") is not True
        or not isinstance(stock_binary, Mapping)
        or stock_binary.get("sha256") != registered["stock_binary_sha256"]
    ):
        raise ScannerDeltaError(f"{role} probe provenance is invalid")
    method = public.get("method")
    campaign = public.get("exact_teddy_v2_campaign")
    expected_manifest = representative.case_manifest([*oot, *wider])
    if (
        not isinstance(method, Mapping)
        or method.get("cpu_profiles") != list(CPU_PROFILES)
        or method.get("exact_teddy_v2_campaign") != campaign
        or not isinstance(campaign, Mapping)
        or campaign.get("exact_teddy_policy_v2") != POLICY
        or campaign.get("selection_manifest_sha256")
        != FIXED44_MANIFEST_SHA256
        or private.get("selection_manifest_sha256")
        != FIXED44_MANIFEST_SHA256
        or private.get("selection_manifest") != expected_manifest
        or private.get("exact_teddy_v2_campaign") != campaign
    ):
        raise ScannerDeltaError(f"{role} probe campaign is invalid")
    expected_optimizer = (
        OLD_OPTIMIZER_VERSION if role == "old" else NEW_OPTIMIZER_VERSION
    )
    normalized, optimizer_receipts = normalize_bound_probe_optimizer(
        private, role=role, expected=expected_optimizer
    )
    if optimizer_receipts == 0:
        raise ScannerDeltaError(f"{role} probe contains no optimizer evidence")
    try:
        recomputed_panels, target_matrix = (
            representative.validate_and_aggregate_private_probe(
                normalized,
                cpu_profiles=CPU_PROFILES,
                oot=oot,
                wider=wider,
                exact_teddy_policy_v2=POLICY,
            )
        )
    except representative.HarnessError as error:
        raise ScannerDeltaError(
            f"{role} probe receipt or correctness validation failed"
        ) from error
    rows = normalized.get("rows")
    if not isinstance(rows, list):
        raise ScannerDeltaError(f"{role} probe rows are missing")
    forced_gates = normalized.get("forced_midscan_gates")
    v2_gates = normalized.get("exact_teddy_v2_gates")
    if (
        not isinstance(forced_gates, list)
        or not isinstance(v2_gates, list)
        or len(forced_gates) != len(CPU_PROFILES)
        or len(v2_gates) != len(CPU_PROFILES)
    ):
        raise ScannerDeltaError(f"{role} private gate matrix is incomplete")
    forced_by_profile: dict[str, Mapping[str, Any]] = {}
    v2_by_profile: dict[str, Mapping[str, Any]] = {}
    for gate in forced_gates:
        if not isinstance(gate, Mapping):
            raise ScannerDeltaError(f"{role} forced gate is malformed")
        profile = gate.get("cpu_profile")
        if profile not in CPU_PROFILES or profile in forced_by_profile:
            raise ScannerDeltaError(f"{role} forced gate matrix is invalid")
        failures = representative.validate_forced_midscan_gate_record(
            gate, str(profile), require_current_schema=True
        )
        if gate.get("failures") != failures:
            raise ScannerDeltaError(f"{role} forced gate does not reconcile")
        forced_by_profile[str(profile)] = gate
    for gate in v2_gates:
        if not isinstance(gate, Mapping):
            raise ScannerDeltaError(f"{role} exact-Teddy gate is malformed")
        profile = gate.get("cpu_profile")
        if profile not in CPU_PROFILES or profile in v2_by_profile:
            raise ScannerDeltaError(f"{role} exact-Teddy gate matrix is invalid")
        failures = representative.validate_exact_teddy_v2_gate_record(
            gate, str(profile), POLICY
        )
        if gate.get("failures") != failures:
            raise ScannerDeltaError(
                f"{role} exact-Teddy gate does not reconcile"
            )
        v2_by_profile[str(profile)] = gate
    if set(forced_by_profile) != set(CPU_PROFILES) or set(v2_by_profile) != set(CPU_PROFILES):
        raise ScannerDeltaError(f"{role} private gate matrix is incomplete")
    forced_summary = representative.forced_midscan_gate_summary(forced_gates)
    v2_summary = representative.exact_teddy_v2_gate_summary(v2_gates, POLICY)
    disposition = representative.selected_or_stock_disposition_summary(
        rows, CPU_PROFILES, POLICY
    )
    probe_host_signature = probe_capability_signature(public)
    expected_disposition = {
        "fixed_itt": 44,
        "selected_teddy_published": 34,
        "ordinary_compiled_stock_fallback": 9,
        "compile_object_decline": 1,
    }
    target_profiles = target_matrix.get("per_profile", {})
    target_host_masks = target_matrix.get(
        "global_qualified_host_feature_bits", []
    )
    if (
        public.get("panels") != recomputed_panels
        or public.get("target_validation_matrix") != target_matrix
        or normalized.get("target_validation_matrix") != target_matrix
        or disposition is None
        or disposition.get("all_profiles_qualified") is not True
        or disposition.get("expected_per_profile") != expected_disposition
        or any(
            entry != {
                "selected_teddy_published": 34,
                "ordinary_compiled_stock_fallback": 9,
                "compile_object_decline": 1,
                "invalid": 0,
                "qualified": True,
            }
            for entry in disposition.get("per_profile", {}).values()
        )
        or set(disposition.get("per_profile", {})) != set(CPU_PROFILES)
        or public.get("selected_or_stock_disposition") != disposition
        or normalized.get("selected_or_stock_disposition") != disposition
        or public.get("exact_teddy_v2_gate") != v2_summary
        or public.get("forced_midscan_gate") != forced_summary
        or target_matrix.get("qualified") is not True
        or set(target_profiles) != set(CPU_PROFILES)
        or len(target_host_masks) != 1
        or any(
            not isinstance(entry, Mapping)
            or set(entry) != {
                "receipt_count", "fully_target_validated_receipts",
                "qualified_host_feature_bits", "qualified",
            }
            or entry.get("receipt_count") != 102
            or entry.get("fully_target_validated_receipts") != 102
            or entry.get("qualified_host_feature_bits") != target_host_masks
            or entry.get("qualified") is not True
            for entry in target_profiles.values()
        )
        or probe_host_signature != registered_host_signature
    ):
        raise ScannerDeltaError(f"{role} qualification probe did not close")
    forced_verification = {
        "summary_sha256": sha256_bytes(canonical_json_bytes(forced_summary)),
        "profiles": forced_summary["profiles"],
        "all_passed": forced_summary["all_passed"],
    }
    v2_verification = {
        "summary_sha256": sha256_bytes(canonical_json_bytes(v2_summary)),
        "profiles": v2_summary["profiles"],
        "all_passed": v2_summary["all_passed"],
    }
    return {
        "private_sha256": actual_private,
        "public_sha256": actual_public,
        "optimizer_version": expected_optimizer,
        "optimizer_receipts_authenticated": optimizer_receipts,
        "stock_reference": {
            "binary_sha256": registered["stock_binary_sha256"],
            "source_commit": registered["stock_source_commit"],
            "source_tree": registered["stock_source_tree"],
            "timed_in_scanner_delta": False,
        },
        "selected_or_stock_disposition": disposition,
        "target_validation_matrix": target_matrix,
        "host_capability_signature": probe_host_signature,
        "forced_midscan_gate_verification": forced_verification,
        "exact_teddy_v2_gate_verification": v2_verification,
        "untimed_reference_correctness_verified": True,
    }


def verify_exact_git_record(path: Path, expected: Mapping[str, Any], label: str) -> dict[str, Any]:
    record = representative.git_record(path)
    if (
        record.get("commit") != expected["source_commit"]
        or record.get("tree") != expected["source_tree"]
        or record.get("clean") is not True
    ):
        raise ScannerDeltaError(f"{label} source identity is invalid")
    return record


def binary_source_binding(
    *, role: str, binary_path: Path, source_path: Path, fre_source_path: Path,
) -> dict[str, Any]:
    expected = expected_identity_record(role)
    source = verify_exact_git_record(source_path, expected, role)
    binary = representative.binary_record(binary_path)
    if binary.get("sha256") != expected["binary_sha256"]:
        raise ScannerDeltaError(f"{role} binary hash is invalid")
    try:
        representative.verify_binary_source(binary, source)
    except representative.HarnessError as error:
        raise ScannerDeltaError(f"{role} binary/source revision mismatch") from error
    dependency = representative.fre_dependency_record(source_path)
    fre_source = representative.git_record(fre_source_path)
    if (
        dependency.get("manifest_revision") != expected["fre_commit"]
        or dependency.get("locked_revision") != expected["fre_commit"]
        or fre_source.get("commit") != expected["fre_commit"]
        or fre_source.get("tree") != expected["fre_tree"]
        or fre_source.get("clean") is not True
    ):
        raise ScannerDeltaError(f"{role} FRE dependency identity is invalid")
    return {
        "source": source,
        "binary": binary,
        "fre_dependency": dependency,
        "fre_source": fre_source,
        "optimizer_version": expected["optimizer_version"],
    }


def host_record(prereg: Mapping[str, Any]) -> dict[str, Any]:
    attestation, registered = validate_capability_attestation(
        prereg["host_capability_attestation"]
    )
    current = current_capability_signature()
    if current != registered:
        raise ScannerDeltaError(
            "current host capabilities differ from the preregistered probes"
        )
    return {
        "capability_attestation": attestation,
        "current_capability_signature": current,
    }


def runner_binding(prereg: Mapping[str, Any]) -> dict[str, Any]:
    source = representative.git_record(REPO)
    scripts = {
        "scanner_delta_sha256": representative.sha256_file(Path(__file__)),
        "auditor_sha256": representative.sha256_file(AUDITOR),
    }
    expected = prereg["runner"]
    if (
        source.get("clean") is not True
        or source.get("commit") != expected["source_commit"]
        or source.get("tree") != expected["source_tree"]
        or scripts["scanner_delta_sha256"] != expected["scanner_delta_sha256"]
        or scripts["auditor_sha256"] != expected["auditor_sha256"]
    ):
        raise ScannerDeltaError("runner source or script identity is invalid")
    return {"source": source, **scripts}


def corpus_binding(
    *, repo: Path, commit: str, expected_commit: str, expected_tree: str,
    label: str,
) -> dict[str, Any]:
    mirror = representative.git_record(repo)
    resolved_commit = representative.git_text(
        repo, ("rev-parse", f"{commit}^{{commit}}")
    )
    resolved_tree = representative.git_text(
        repo, ("rev-parse", f"{commit}^{{tree}}")
    )
    if (
        mirror.get("clean") is not True
        or resolved_commit != expected_commit
        or resolved_tree != expected_tree
    ):
        raise ScannerDeltaError(f"{label} corpus identity is invalid")
    return {
        "mirror_clean": mirror["clean"],
        "materialized_commit": resolved_commit,
        "materialized_tree": resolved_tree,
    }


def materialized_corpus_record(
    root: Path, source: Mapping[str, Any], label: str,
) -> dict[str, Any]:
    if not root.is_dir():
        raise ScannerDeltaError(f"{label} materialized corpus is missing")
    digest = hashlib.sha256()
    digest.update(b"rg-scanner-delta-materialized-tree-v1\0")
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    regular_files = 0
    symlinks = 0
    directories = 0
    total_bytes = 0
    for path in entries:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            kind = b"f"
            regular_files += 1
            size = metadata.st_size
            total_bytes += size
            payload = None
        elif stat.S_ISLNK(metadata.st_mode):
            kind = b"l"
            symlinks += 1
            payload = os.readlink(path).encode("utf-8")
            size = len(payload)
        elif stat.S_ISDIR(metadata.st_mode):
            kind = b"d"
            directories += 1
            size = 0
            payload = b""
        else:
            raise ScannerDeltaError(
                f"{label} materialized corpus has a non-portable entry"
            )
        digest.update(kind)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(size.to_bytes(8, "big"))
        if payload is not None:
            digest.update(payload)
        else:
            with path.open("rb") as source_file:
                for block in iter(lambda: source_file.read(1024 * 1024), b""):
                    digest.update(block)
    record = exact_keys(
        source,
        ("commit", "tree", "file_count", "total_file_bytes"),
        f"{label} archive materialization report",
    )
    if (
        not is_git_oid(record["commit"])
        or not is_git_oid(record["tree"])
        or not positive_int(record["file_count"])
        or not positive_int(record["total_file_bytes"])
        or regular_files + symlinks <= 0
        or total_bytes <= 0
    ):
        raise ScannerDeltaError(f"{label} materialization report is invalid")
    return {
        "commit": record["commit"],
        "tree": record["tree"],
        "archive_reported_file_count": record["file_count"],
        "archive_reported_total_file_bytes": record["total_file_bytes"],
        "entry_count": len(entries),
        "directory_count": directories,
        "regular_file_count": regular_files,
        "symlink_count": symlinks,
        "total_regular_file_bytes": total_bytes,
        "content_tree_sha256": digest.hexdigest(),
    }


def materialized_corpus_records(
    paths: Mapping[str, Path], source: Mapping[str, Any],
) -> dict[str, Any]:
    if set(paths) != {"ripgrep", "fre"} or set(source) != {"ripgrep", "fre"}:
        raise ScannerDeltaError("materialized corpus matrix is invalid")
    return {
        name: materialized_corpus_record(paths[name], source[name], name)
        for name in ("ripgrep", "fre")
    }


def input_binding(
    args: argparse.Namespace,
    prereg: Mapping[str, Any],
    prereg_sha256: str,
    oot: Sequence[representative.QueryCase],
    wider: Sequence[representative.QueryCase],
    corpus_paths: Mapping[str, Path],
    corpus_records: Mapping[str, Any],
) -> dict[str, Any]:
    inputs = prereg["inputs"]
    if representative.sha256_file(args.selection_manifest_input) != inputs[
        "selection_transport_sha256"
    ]:
        raise ScannerDeltaError("selection transport changed")
    if representative.sha256_file(args.new_qualification_manifest) != (
        NEW_QUALIFICATION_MANIFEST_SHA256
    ) or representative.sha256_file(args.new_qualification_archive) != (
        NEW_QUALIFICATION_ARCHIVE_SHA256
    ):
        raise ScannerDeltaError("new qualification artifact changed")
    fixed = [*oot, *wider]
    if representative.manifest_digest(
        representative.case_manifest(fixed)
    ) != FIXED44_MANIFEST_SHA256:
        raise ScannerDeltaError("fixed44 manifest changed")
    return {
        "preregistration_sha256": prereg_sha256,
        "runner": runner_binding(prereg),
        "host": host_record(prereg),
        "identities": {
            "old": binary_source_binding(
                role="old", binary_path=args.old_binary,
                source_path=args.old_source,
                fre_source_path=args.old_fre_source,
            ),
            "new": binary_source_binding(
                role="new", binary_path=args.new_binary,
                source_path=args.new_source,
                fre_source_path=args.new_fre_source,
            ),
        },
        "qualification_probes": {
            "old": validate_qualification_probe(
                role="old", private_path=args.old_probe_private,
                public_path=args.old_probe_public, prereg=prereg,
                oot=oot, wider=wider,
            ),
            "new": validate_qualification_probe(
                role="new", private_path=args.new_probe_private,
                public_path=args.new_probe_public, prereg=prereg,
                oot=oot, wider=wider,
            ),
        },
        "qualification_artifacts": {
            "new_manifest_sha256": NEW_QUALIFICATION_MANIFEST_SHA256,
            "new_archive_sha256": NEW_QUALIFICATION_ARCHIVE_SHA256,
        },
        "selection": {
            "transport_sha256": inputs["selection_transport_sha256"],
            "fixed44_manifest_sha256": FIXED44_MANIFEST_SHA256,
            "selected34_manifest_sha256": SELECTED34_MANIFEST_SHA256,
            "selected34_ids_sha256": SELECTED34_IDS_SHA256,
            "complement10_manifest_sha256": COMPLEMENT10_MANIFEST_SHA256,
            "complement10_ids_sha256": COMPLEMENT10_IDS_SHA256,
        },
        "corpus_sources": {
            "ripgrep": corpus_binding(
                repo=args.ripgrep_corpus_repo,
                commit=args.ripgrep_corpus_commit,
                expected_commit=inputs["ripgrep_corpus_commit"],
                expected_tree=inputs["ripgrep_corpus_tree"],
                label="ripgrep",
            ),
            "fre": corpus_binding(
                repo=args.fre_corpus_repo,
                commit=args.fre_corpus_commit,
                expected_commit=inputs["fre_corpus_commit"],
                expected_tree=inputs["fre_corpus_tree"],
                label="FRE",
            ),
        },
        "materialized_corpora": materialized_corpus_records(
            corpus_paths, corpus_records
        ),
    }


def canonical_rows(
    panels: Sequence[representative.Panel],
    oot: Sequence[representative.QueryCase],
    wider: Sequence[representative.QueryCase],
) -> list[tuple[int, str, representative.Panel, representative.QueryCase]]:
    rows = []
    ordinal = 0
    for profile in CPU_PROFILES:
        for panel in panels:
            cases = representative.cases_for_panel(panel.id, oot, wider, POLICY)
            for case in cases:
                rows.append((ordinal, profile, panel, case))
                ordinal += 1
    if len(rows) != 408 or [item[0] for item in rows] != list(range(408)):
        raise ScannerDeltaError("canonical scanner-delta row matrix changed")
    return rows


def compact_arm(result: Mapping[str, Any], *, include_timing: bool) -> dict[str, Any]:
    fields = (
        "elapsed_ns", "user_ns", "system_ns", "timed_out", "status",
        "stdout", "stderr", "receipt", "receipt_parse_error",
        "unexpected_temporary_artifacts",
    ) if include_timing else (
        "timed_out", "status", "stdout", "stderr", "receipt",
        "receipt_parse_error", "unexpected_temporary_artifacts",
    )
    return {field: result[field] for field in fields if field in result}


def validate_quartet_closure(
    results: Mapping[str, Mapping[str, Any]],
    comparisons: Mapping[str, Mapping[str, Any]],
    output_mode: str,
) -> None:
    if set(results) != set(ARM_RECORD) or set(comparisons) != set(ARM_RECORD):
        raise ScannerDeltaError("quartet arms are incomplete")
    anchor = results["A"]
    for arm in ARM_RECORD:
        result = results[arm]
        comparison = comparisons[arm]
        stdout = result.get("stdout")
        stderr = result.get("stderr")
        if (
            result.get("timed_out") is not False
            or type(result.get("status")) is not int
            or result.get("status") not in (0, 1)
            or result.get("receipt") is not None
            or result.get("receipt_parse_error") is not False
            or type(result.get("unexpected_temporary_artifacts")) is not int
            or result.get("unexpected_temporary_artifacts") != 0
            or not isinstance(stdout, Mapping)
            or not isinstance(stderr, Mapping)
            or comparison.get("status") != result.get("status")
            or comparison.get("stderr_sha256") != stderr.get("sha256")
            or not is_sha256(comparison.get("semantic_stdout_sha256"))
            or output_mode == "literal"
            and comparison.get("semantic_stdout_sha256")
            != stdout.get("sha256")
            or not representative.outputs_equal(anchor, result, output_mode)
        ):
            raise ScannerDeltaError("four-arm output/status/temp closure failed")


def run_quartet(
    *,
    case: representative.QueryCase,
    panel: representative.Panel,
    order_index: int,
    binaries: Mapping[str, Path],
    cwd: Path,
    cpu_profile: str,
    include_timing: bool,
) -> dict[str, Any]:
    query, normalization = representative.query_args(case, panel)
    order = ORDERS[order_index]
    raw: dict[str, Mapping[str, Any]] = {}
    comparisons: dict[str, Mapping[str, Any]] = {}
    for arm in order:
        arm_record = ARM_RECORD[arm]
        role = str(arm_record["binary_identity"])
        result = representative.run_once(
            binary=binaries[role],
            args=query,
            cwd=cwd,
            background=bool(arm_record["background"]),
            capture_receipt=False,
            cpu_profile=cpu_profile,
            timeout_seconds=TIMEOUT_SECONDS,
            collect_timing=True,
            exact_teddy_policy_v2=(
                POLICY if arm_record["background"] else None
            ),
        )
        raw[arm] = result
        comparisons[arm] = representative.comparison_record(
            result, panel.output_comparison
        )
    validate_quartet_closure(raw, comparisons, panel.output_comparison)
    record = {
        "order_index": order_index,
        "order": list(order),
        "normalization": normalization,
        "comparison_records": comparisons,
        "arms": {
            arm: compact_arm(raw[arm], include_timing=include_timing)
            for arm in ARM_RECORD
        },
        "closure_verified": True,
    }
    if include_timing:
        elapsed = {
            arm: int(raw[arm]["elapsed_ns"]) for arm in ARM_RECORD
        }
        record["metrics"] = metric_values(elapsed)
    return record


def run_row(
    *,
    row_ordinal: int,
    cpu_profile: str,
    panel: representative.Panel,
    case: representative.QueryCase,
    binaries: Mapping[str, Path],
    cwd: Path,
) -> dict[str, Any]:
    warmup_indices = [
        (row_ordinal - 2) % len(ORDERS),
        (row_ordinal - 1) % len(ORDERS),
    ]
    warmups = [
        run_quartet(
            case=case, panel=panel, order_index=order_index,
            binaries=binaries, cwd=cwd, cpu_profile=cpu_profile,
            include_timing=False,
        )
        for order_index in warmup_indices
    ]
    quartets = []
    for measured_index in range(MEASURED_QUARTETS):
        order_index = (row_ordinal + measured_index) % len(ORDERS)
        print(
            f"scanner-delta {cpu_profile} {panel.id} row "
            f"{row_ordinal + 1}/408 quartet {measured_index + 1}/8",
            flush=True,
        )
        quartets.append(run_quartet(
            case=case, panel=panel, order_index=order_index,
            binaries=binaries, cwd=cwd, cpu_profile=cpu_profile,
            include_timing=True,
        ))
    summary = row_summary(quartets)
    return {
        "canonical_row_ordinal": row_ordinal,
        "private_id": case.private_id,
        "cohort": case.cohort,
        "pattern": case.pattern,
        "occurrence_weight": case.occurrence_weight,
        "suffix": case.suffix,
        "semantics": dict(case.semantics),
        "target_kind": case.target_kind,
        "extension_class": case.extension_class,
        "query_argv_after_binary": representative.query_args(case, panel)[0],
        "cpu_profile": cpu_profile,
        "panel": panel.id,
        "warmups": warmups,
        "quartets": quartets,
        "summary": summary,
    }


def validate_primary_authorization(
    args: argparse.Namespace,
    prereg: Mapping[str, Any],
    prereg_sha256: str,
) -> dict[str, Any] | None:
    primary_paths = (
        args.primary_private_result,
        args.primary_public_result,
        args.primary_audit_result,
    )
    if args.campaign_role == "primary":
        if args.row_traversal != "canonical" or any(path is not None for path in primary_paths):
            raise ScannerDeltaError("primary role/traversal or inputs are invalid")
        return None
    if (
        args.campaign_role != "reverse-row-confirmation"
        or args.row_traversal != "reverse-canonical"
        or any(path is None for path in primary_paths)
    ):
        raise ScannerDeltaError("reverse confirmation is not fully authorized")
    assert args.primary_private_result is not None
    assert args.primary_public_result is not None
    assert args.primary_audit_result is not None
    primary_private_sha = representative.sha256_file(args.primary_private_result)
    primary_public_sha = representative.sha256_file(args.primary_public_result)
    primary_public = load_json_object(args.primary_public_result, "primary public result")
    audit = load_json_object(args.primary_audit_result, "primary audit")
    exact_keys(
        audit,
        (
            "schema", "verified", "auditor", "audit_unix_ns",
            "preregistration_sha256", "primary_private_sha256",
            "primary_public_sha256", "reverse_private_sha256",
            "reverse_public_sha256", "reverse_row_confirmation_required",
            "reverse_row_confirmation_triggers", "chronology", "primary",
            "reverse", "combined_analysis",
        ),
        "primary authorization audit",
    )
    auditor = exact_keys(
        audit["auditor"],
        ("implementation", "sha256", "imports_runner_or_representative_harness"),
        "primary authorization auditor",
    )
    chronology = exact_keys(
        audit["chronology"],
        (
            "primary_start_unix_ns", "primary_end_unix_ns",
            "primary_authorization_audit_unix_ns", "reverse_start_unix_ns",
            "reverse_end_unix_ns", "non_overlapping",
        ),
        "primary authorization chronology",
    )
    workload = primary_public.get("workload_environment")
    decision = primary_public.get("decision")
    if not isinstance(workload, Mapping) or not isinstance(decision, Mapping):
        raise ScannerDeltaError("primary public authorization evidence is malformed")
    primary_end = workload.get("end")
    if not isinstance(primary_end, Mapping):
        raise ScannerDeltaError("primary workload end is malformed")
    audit_unix_ns = audit["audit_unix_ns"]
    if (
        primary_public.get("schema") != PUBLIC_SCHEMA
        or primary_public.get("campaign_role") != "primary"
        or primary_public.get("row_traversal") != "canonical"
        or primary_public.get("preregistration_sha256") != prereg_sha256
        or primary_public.get("private_result_sha256") != primary_private_sha
        or decision.get("reverse_row_confirmation_required") is not True
        or audit.get("schema") != AUDIT_SCHEMA
        or audit.get("verified") is not True
        or audit.get("preregistration_sha256") != prereg_sha256
        or audit.get("primary_private_sha256") != primary_private_sha
        or audit.get("primary_public_sha256") != primary_public_sha
        or not strict_json_equal(auditor, {
            "implementation": "independent_offline_v1",
            "sha256": prereg["runner"]["auditor_sha256"],
            "imports_runner_or_representative_harness": False,
        })
        or audit.get("reverse_row_confirmation_required") is not True
        or audit.get("reverse_row_confirmation_triggers")
        != decision.get("reverse_row_confirmation_triggers")
        or audit.get("reverse_private_sha256") is not None
        or audit.get("reverse_public_sha256") is not None
        or not strict_json_equal(audit.get("primary"), {
            "decision": decision, "cells": primary_public.get("cells")
        })
        or audit.get("reverse") is not None
        or audit.get("combined_analysis") is not None
        or not positive_int(audit_unix_ns)
        or not positive_int(primary_end.get("unix_ns"))
        or audit_unix_ns <= primary_end["unix_ns"]
        or not strict_json_equal(chronology, {
            "primary_start_unix_ns": workload.get("start", {}).get("unix_ns"),
            "primary_end_unix_ns": primary_end["unix_ns"],
            "primary_authorization_audit_unix_ns": audit_unix_ns,
            "reverse_start_unix_ns": None,
            "reverse_end_unix_ns": None,
            "non_overlapping": None,
        })
    ):
        raise ScannerDeltaError("primary audit does not authorize confirmation")
    return {
        "primary_private_sha256": primary_private_sha,
        "primary_public_sha256": primary_public_sha,
        "primary_audit_sha256": representative.sha256_file(
            args.primary_audit_result
        ),
        "auditor_sha256": prereg["runner"]["auditor_sha256"],
        "primary_audit_unix_ns": audit_unix_ns,
        "primary_workload_end": dict(primary_end),
        "triggers": decision[
            "reverse_row_confirmation_triggers"
        ],
    }


class PrivateCheckpointJournal:
    """Append-only, fsync'd private evidence surviving a terminal failure."""

    def __init__(self, path: Path, *, campaign_role: str, row_traversal: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._output = os.fdopen(descriptor, "wb", buffering=0)
        self._campaign_role = campaign_role
        self._row_traversal = row_traversal
        self._index = 0
        self._completed_rows = 0
        self._stage = "reserved"
        self.append("checkpoint_reserved", reason=None, row=None)

    @property
    def stage_name(self) -> str:
        return self._stage

    def append(
        self, event: str, *, reason: str | None, row: Mapping[str, Any] | None,
    ) -> None:
        record = {
            "schema": CHECKPOINT_SCHEMA,
            "event_index": self._index,
            "event": event,
            "stage": self._stage,
            "reason": reason,
            "completed_rows": self._completed_rows,
            "campaign_role": self._campaign_role,
            "row_traversal": self._row_traversal,
            "row": dict(row) if row is not None else None,
        }
        self._output.write(canonical_json_bytes(record))
        self._output.flush()
        os.fsync(self._output.fileno())
        self._index += 1

    def stage(self, name: str) -> None:
        if not re.fullmatch(r"[a-z0-9_]+", name):
            raise ScannerDeltaError("checkpoint stage is invalid")
        self._stage = name
        self.append("stage", reason=None, row=None)

    def completed_row(self, row: Mapping[str, Any]) -> None:
        self._completed_rows += 1
        self.append("completed_row", reason=None, row=row)

    def terminal_failure(self, error: BaseException) -> None:
        self.append(
            "terminal_failure", reason=type(error).__name__, row=None
        )

    def terminal_success(self, private_sha256: str, public_sha256: str) -> None:
        self._stage = "complete"
        self.append(
            "terminal_success",
            reason=f"private={private_sha256};public={public_sha256}",
            row=None,
        )

    def close(self) -> None:
        self._output.close()


def run_scanner_delta(
    args: argparse.Namespace, journal: PrivateCheckpointJournal,
) -> None:
    journal.stage("preregistration_and_authorization")
    prereg, prereg_sha256 = load_preregistration(args.preregistration)
    authorization = validate_primary_authorization(
        args, prereg, prereg_sha256
    )
    journal.stage("selection_and_probe_binding")
    source_oot, source_wider = representative.selected_cases(args)
    all_cases = representative.exact_teddy_v2_campaign_cases(
        [*source_oot, *source_wider], POLICY
    )
    oot = [case for case in all_cases if case.private_id.startswith("oot-")]
    wider = [
        case for case in all_cases if case.private_id.startswith("wider-")
    ]
    representative.validate_frozen_exact_teddy_v2_force_strata(all_cases)
    seed_record = bootstrap_seed_record(prereg)
    journal.stage("corpus_materialization")
    with tempfile.TemporaryDirectory(prefix="rg-fre-scanner-delta-") as text:
        temporary = Path(text)
        corpus_paths, corpus_records = representative.create_corpora(
            args, temporary
        )
        if (
            corpus_records["ripgrep"]["commit"]
            != prereg["inputs"]["ripgrep_corpus_commit"]
            or corpus_records["ripgrep"]["tree"]
            != prereg["inputs"]["ripgrep_corpus_tree"]
            or corpus_records["fre"]["commit"]
            != prereg["inputs"]["fre_corpus_commit"]
            or corpus_records["fre"]["tree"]
            != prereg["inputs"]["fre_corpus_tree"]
        ):
            raise ScannerDeltaError("materialized corpus identity changed")
        panels = representative.panels_for(corpus_paths)
        canonical = canonical_rows(panels, oot, wider)
        traversal = (
            canonical
            if args.row_traversal == "canonical"
            else list(reversed(canonical))
        )
        pre = input_binding(
            args, prereg, prereg_sha256, oot, wider, corpus_paths,
            corpus_records,
        )
        workload_start = representative.load_snapshot()
        if authorization is not None:
            primary_end = authorization.get("primary_workload_end")
            audit_unix_ns = authorization.get("primary_audit_unix_ns")
            if (
                not isinstance(primary_end, Mapping)
                or not isinstance(primary_end.get("unix_ns"), int)
                or not positive_int(audit_unix_ns)
                or workload_start["unix_ns"] <= primary_end["unix_ns"]
                or workload_start["unix_ns"] <= audit_unix_ns
            ):
                raise ScannerDeltaError("confirmation does not follow primary")
        rows = []
        journal.stage("timing_rows")
        binaries = {"old": args.old_binary, "new": args.new_binary}
        workload_cwd = temporary / "neutral-cwd"
        workload_cwd.mkdir(mode=0o700)
        for row_ordinal, profile, panel, case in traversal:
            completed = run_row(
                row_ordinal=row_ordinal,
                cpu_profile=profile,
                panel=panel,
                case=case,
                binaries=binaries,
                cwd=workload_cwd,
            )
            rows.append(completed)
            journal.completed_row(completed)
        workload_end = representative.load_snapshot()
        journal.stage("post_run_revalidation")
        representative.revalidate_selection(args, source_oot, source_wider)
        post = input_binding(
            args, prereg, prereg_sha256, oot, wider, corpus_paths,
            corpus_records,
        )
        if post != pre:
            raise ScannerDeltaError("input provenance changed during benchmark")
    journal.stage("analysis")
    cells = aggregate_rows(rows, bootstrap_seed_from_prereg(prereg))
    decision = decision_record(cells)
    private = {
        "schema": PRIVATE_SCHEMA,
        "contains_raw_patterns": True,
        "local_only_do_not_commit": True,
        "campaign_role": args.campaign_role,
        "row_traversal": args.row_traversal,
        "preregistration_sha256": prereg_sha256,
        "protocol": protocol_record(),
        "bootstrap_seed": seed_record,
        "pre_run_input_binding": pre,
        "post_run_input_binding": post,
        "confirmation_of": authorization,
        "selection_manifest_sha256": FIXED44_MANIFEST_SHA256,
        "selection_manifest": representative.case_manifest(all_cases),
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "rows": rows,
        "cells": cells,
        "decision": decision,
        "post_run_selection_verified": True,
        "post_run_provenance_verified": True,
    }
    public = {
        "schema": PUBLIC_SCHEMA,
        "aggregate_only": True,
        "contains_patterns_commands_paths_or_per_pattern_rows": False,
        "campaign_role": args.campaign_role,
        "row_traversal": args.row_traversal,
        "preregistration_sha256": prereg_sha256,
        "protocol": protocol_record(),
        "bootstrap_seed": seed_record,
        "pre_run_input_binding": pre,
        "post_run_input_binding": post,
        "confirmation_of": authorization,
        "method": {
            "unit": "one frozen query in one fresh ripgrep process",
            "timed_arms": ["B0", "B1", "N1", "N0"],
            "stock_or_automatic_timed_arms": 0,
            "warmup_quartets_per_row": WARMUP_QUARTETS,
            "measured_quartets_per_row": MEASURED_QUARTETS,
            "canonical_rows": 408,
            "row_offset_uses_stable_canonical_ordinal": True,
            "timed_receipts": False,
            "filesystem_cache_state": (
                "cache-hot/uncontrolled after one archive materialization; "
                "no eviction between invocations"
            ),
        },
        "workload_environment": {
            "start": workload_start,
            "end": workload_end,
        },
        "cohorts": {
            "oot": representative.cohort_profile(oot),
            "wider": representative.cohort_profile(wider),
        },
        "cells": cells,
        "decision": decision,
        "post_run_selection_verified": True,
        "post_run_provenance_verified": True,
    }
    journal.stage("result_write")
    representative.write_bound_result_pair(
        args.private_output, args.public_output, private, public
    )
    journal.terminal_success(
        representative.sha256_file(args.private_output),
        representative.sha256_file(args.public_output),
    )


def resolved_new_path(parser: argparse.ArgumentParser, value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if path.exists():
        parser.error(f"output already exists: {path}")
    return path


def add_existing_path_argument(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(
        name,
        type=lambda value: Path(value).expanduser().resolve(strict=True),
        required=True,
    )


def benchmark_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("benchmark-scanner-delta",))
    add_existing_path_argument(parser, "--preregistration")
    add_existing_path_argument(parser, "--selection-manifest-input")
    add_existing_path_argument(parser, "--old-binary")
    add_existing_path_argument(parser, "--old-source")
    add_existing_path_argument(parser, "--old-fre-source")
    add_existing_path_argument(parser, "--new-binary")
    add_existing_path_argument(parser, "--new-source")
    add_existing_path_argument(parser, "--new-fre-source")
    add_existing_path_argument(parser, "--old-probe-private")
    add_existing_path_argument(parser, "--old-probe-public")
    add_existing_path_argument(parser, "--new-probe-private")
    add_existing_path_argument(parser, "--new-probe-public")
    add_existing_path_argument(parser, "--new-qualification-manifest")
    add_existing_path_argument(parser, "--new-qualification-archive")
    add_existing_path_argument(parser, "--ripgrep-corpus-repo")
    parser.add_argument("--ripgrep-corpus-commit", required=True)
    add_existing_path_argument(parser, "--fre-corpus-repo")
    parser.add_argument("--fre-corpus-commit", required=True)
    parser.add_argument(
        "--campaign-role",
        choices=("primary", "reverse-row-confirmation"),
        required=True,
    )
    parser.add_argument(
        "--row-traversal",
        choices=("canonical", "reverse-canonical"),
        required=True,
    )
    parser.add_argument("--primary-private-result", type=Path)
    parser.add_argument("--primary-public-result", type=Path)
    parser.add_argument("--primary-audit-result", type=Path)
    parser.add_argument("--private-output", required=True)
    parser.add_argument("--public-output", required=True)
    parser.add_argument("--private-checkpoint-output", required=True)
    return parser


def parse_benchmark_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = benchmark_parser()
    args = parser.parse_args(argv)
    for field in (
        "primary_private_result", "primary_public_result",
        "primary_audit_result",
    ):
        value = getattr(args, field)
        if value is not None:
            setattr(args, field, value.expanduser().resolve(strict=True))
    args.private_output = resolved_new_path(parser, args.private_output)
    args.public_output = resolved_new_path(parser, args.public_output)
    args.private_checkpoint_output = resolved_new_path(
        parser, args.private_checkpoint_output
    )
    if len({
        args.private_output, args.public_output,
        args.private_checkpoint_output,
    }) != 3:
        parser.error("private, public, and checkpoint outputs must differ")
    # Supply the exact representative-loader settings without exposing
    # mutable campaign controls on this CLI.
    args.inventory_root = None
    args.database = None
    args.wider_sample_size = 128
    args.wider_sample_seed = 0xA07_2026
    args.expected_sve_vl_bytes = EXPECTED_SVE_VL_BYTES
    args.timeout_seconds = TIMEOUT_SECONDS
    return args


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "audit-scanner-delta":
        import audit_scanner_delta

        return audit_scanner_delta.main(arguments[1:])
    journal = None
    try:
        args = parse_benchmark_args(arguments)
        journal = PrivateCheckpointJournal(
            args.private_checkpoint_output,
            campaign_role=args.campaign_role,
            row_traversal=args.row_traversal,
        )
        run_scanner_delta(args, journal)
        return 0
    except Exception as error:
        if journal is not None:
            try:
                journal.terminal_failure(error)
            except Exception:
                pass
        print('{"error":"scanner_delta_failed_safely"}', file=sys.stderr)
        return 2
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())

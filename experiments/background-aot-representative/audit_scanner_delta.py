#!/usr/bin/env python3
"""Independently audit sealed SVE fused-bucket scanner-screen artifacts offline.

This module intentionally imports neither the runner nor the representative
harness. It duplicates the frozen protocol constants and independently
recomputes row metrics, equal-ID aggregates, hierarchical confidence
intervals, and decision gates for the sole primary canonical campaign.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
SCHEMA = "background-aot-sve-fused-bucket-screen-v1"
PREREG_SCHEMA = f"{SCHEMA}.preregistration"
PRIVATE_SCHEMA = f"{SCHEMA}.private"
PUBLIC_SCHEMA = f"{SCHEMA}.public"
AUDIT_SCHEMA = f"{SCHEMA}.audit"
HOST_CAPABILITY_SCHEMA = f"{SCHEMA}.host-capability-v1"
PROTOCOL_SHA256 = (
    "2a9821264ed817b47a6ddf42ccf46e17ed471306bd964d58ca6c454c0eb47e3f"
)
OLD_SOURCE_COMMIT = "16879a181bd768e25f80af203efc5518b7ec4800"
OLD_SOURCE_TREE = "89a4ef811c4edeb69b174f27b0b3b62a57b04a5a"
OLD_BINARY_SHA256 = (
    "0ed88e013674250281a493fef74b9d72e116b66a321202f68dbd56ee5f2d0168"
)
OLD_FRE_COMMIT = "76fc8a58e8d65007a714770fe9478e198bb88442"
OLD_FRE_TREE = "536a45ab4c67fbb272c0788196a7b699ce2f8b9d"
OLD_PROBE_PRIVATE_SHA256 = (
    "cb351bbe9e7b73fa4cd2fb4e45ce1cef295e76d6e9cc074145f9359ce86d5754"
)
OLD_PROBE_PUBLIC_SHA256 = (
    "0baa031d45de310d994784df87e55a17367fc5a90301e70ae96e8482b676a20a"
)
NEW_SOURCE_COMMIT = "78e02eec61740f036a71607e534cb64575d575d5"
NEW_SOURCE_TREE = "ab722aa45d83fdb798de399d6e8aaade9229a9e9"
NEW_BINARY_SHA256 = (
    "d65eb86b6fca70a6af19aba66e76c6fd9abcdf43dab000699886bde12173433f"
)
NEW_FRE_COMMIT = "94d87a5ddb983e6b46178fbf1140fd4043519f81"
NEW_FRE_TREE = "3dd9c487e1c9575d5192d8ecaff100ba2eec8c01"
NEW_PROBE_PRIVATE_SHA256 = (
    "5998a839e60ff5df8e1df1e68384accfb7d64fa7cfe531533f912677666d32cf"
)
NEW_PROBE_PUBLIC_SHA256 = (
    "75f8b21f8efd80802618194435617ca1a0f221ea42800f2263077f9789ae74f2"
)
NEW_QUALIFICATION_MANIFEST_SHA256 = (
    "6873173c0e94694d9990419f6f2a8e6fe9b1d6ea924291b901b44a1c2eb4aed7"
)
NEW_QUALIFICATION_ARCHIVE_SHA256 = (
    "f736a50637b25037a5b2fea24070c5f5a45721962721190fbd170b450a1926fe"
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
SELECTED_IDS = frozenset((
    "oot-0003", "oot-0005", "oot-0008", "oot-0019", "oot-0039",
    "oot-0043", "oot-0047", "oot-0051", "oot-0052", "oot-0078",
    "oot-0084", "wider-0001", "wider-0006", "wider-0008",
    "wider-0010", "wider-0012", "wider-0013", "wider-0014",
    "wider-0024", "wider-0040", "wider-0042", "wider-0047",
    "wider-0062", "wider-0064", "wider-0084", "wider-0088",
    "wider-0092", "wider-0093", "wider-0096", "wider-0108",
    "wider-0109", "wider-0111", "wider-0113", "wider-0118",
))
COMPLEMENT_IDS = frozenset((
    "oot-0002", "oot-0004", "oot-0035", "wider-0003",
    "wider-0030", "wider-0039", "wider-0052", "wider-0058",
    "wider-0075", "wider-0121",
))
CPU_PROFILES = ("auto", "asimd", "sve", "sve2")
PANELS = (
    "ripgrep-default-output",
    "fre-count-default-threads",
    "fre-count-thread1",
)
STRATA = ("intention_to_treat", "selected34", "complement10")
METRICS = ("S", "C", "D", "R0", "R1")
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
BOOTSTRAP_DOMAIN = b"rg-aot-sve-fused-bucket-screen-v1-bootstrap"
BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_LOW_INDEX = 250
BOOTSTRAP_HIGH_INDEX = 9749
PROFILE_TARGET_BITS = {
    "asimd": 1 << 32,
    "sve": 1 << 33,
    "sve2": (1 << 33) | (1 << 34),
}


class AuditError(RuntimeError):
    """An independently detected schema, evidence, or analysis failure."""


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise AuditError(f"{label} fields do not match the v1 schema")
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
    requested = exact_keys(
        signature["requested_target_feature_bits_by_profile"],
        CPU_PROFILES,
        "requested profile bits",
    )
    effective = exact_keys(
        signature["effective_target_feature_bits_by_profile"],
        CPU_PROFILES,
        "effective profile bits",
    )
    if (
        not isinstance(signature["platform"], str)
        or not signature["platform"].startswith("Linux-")
        or signature["machine"] not in ("aarch64", "arm64")
        or not positive_int(signature["cpu_count"])
        or signature["sve_vector_length_bytes"] != 16
        or not isinstance(signature["host_target_feature_bits"], str)
        or re.fullmatch(r"0x[0-9a-f]+", signature["host_target_feature_bits"])
        is None
    ):
        raise AuditError("host capability signature is invalid")
    host_bits = int(signature["host_target_feature_bits"], 16)
    required = (1 << 32) | (1 << 33) | (1 << 34)
    if host_bits & required != required:
        raise AuditError("host lacks ASIMD/SVE/SVE2")
    expected = {"auto": host_bits, **PROFILE_TARGET_BITS}
    for profile in CPU_PROFILES:
        encoded = f"0x{expected[profile]:x}"
        if requested[profile] != encoded or effective[profile] != encoded:
            raise AuditError("host profile feature bits are invalid")
    return dict(signature)


def validate_capability_attestation(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    attestation = exact_keys(
        value,
        ("schema", "canonical_json_ascii", "sha256"),
        "host capability attestation",
    )
    text = attestation["canonical_json_ascii"]
    if (
        attestation["schema"] != HOST_CAPABILITY_SCHEMA
        or not isinstance(text, str)
        or not is_sha256(attestation["sha256"])
    ):
        raise AuditError("host capability attestation is invalid")
    try:
        encoded = text.encode("ascii")
        signature = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AuditError("host capability attestation is malformed") from error
    validated = validate_capability_signature(signature)
    if (
        encoded != canonical_json_bytes(validated)
        or hashlib.sha256(encoded).hexdigest() != attestation["sha256"]
    ):
        raise AuditError("host capability attestation bytes changed")
    return dict(attestation), validated


def single_feature_key(value: Any, label: str) -> str:
    if not isinstance(value, Mapping):
        raise AuditError(f"{label} is missing")
    keys = [
        key for key, count in value.items()
        if key != "unreported" and positive_int(count)
    ]
    if len(keys) != 1 or set(value) != set(keys):
        raise AuditError(f"{label} is not a single feature mask")
    key = keys[0]
    if not isinstance(key, str) or re.fullmatch(r"0x[0-9a-f]+", key) is None:
        raise AuditError(f"{label} is invalid")
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
        raise AuditError("probe panel capability evidence is missing")
    requested: dict[str, str] = {}
    effective: dict[str, str] = {}
    hosts: set[str] = set()
    for profile in CPU_PROFILES:
        requested_set: set[str] = set()
        effective_set: set[str] = set()
        for panel in PANELS:
            aggregate = panels.get(f"{profile}/{panel}")
            if not isinstance(aggregate, Mapping):
                raise AuditError("probe panel capability matrix is incomplete")
            selected = aggregate.get("all_selected")
            if not isinstance(selected, Mapping):
                raise AuditError("probe all-selected evidence is missing")
            classification = selected.get("receipt_classification")
            if not isinstance(classification, Mapping):
                raise AuditError("probe receipt classification is missing")
            requested_set.add(single_feature_key(
                classification.get("requested_target_feature_bits"),
                f"{profile}/{panel} requested features",
            ))
            effective_set.add(single_feature_key(
                classification.get("effective_target_feature_bits"),
                f"{profile}/{panel} effective features",
            ))
            hosts.add(single_feature_key(
                classification.get("host_target_feature_bits"),
                f"{profile}/{panel} host features",
            ))
        if len(requested_set) != 1 or len(effective_set) != 1:
            raise AuditError("probe feature masks disagree by panel")
        requested[profile] = next(iter(requested_set))
        effective[profile] = next(iter(effective_set))
    matrix = public.get("target_validation_matrix")
    if (
        not isinstance(matrix, Mapping)
        or matrix.get("qualified") is not True
        or len(hosts) != 1
        or matrix.get("global_qualified_host_feature_bits") != sorted(hosts)
    ):
        raise AuditError("probe host target matrix is not qualified")
    return validate_capability_signature({
        "platform": host["platform"],
        "machine": host["machine"],
        "cpu_count": host["cpu_count"],
        "sve_vector_length_bytes": host["sve_vector_length_bytes"],
        "host_target_feature_bits": next(iter(hosts)),
        "requested_target_feature_bits_by_profile": requested,
        "effective_target_feature_bits_by_profile": effective,
    })


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"{label} is not valid JSON") from error
    if not isinstance(value, Mapping):
        raise AuditError(f"{label} is not a JSON object")
    return dict(value)


def frozen_ids_digest(values: Iterable[str]) -> str:
    encoded = json.dumps(
        sorted(values), ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def identity_record(role: str) -> dict[str, Any]:
    if role == "old":
        return {
            "source_commit": OLD_SOURCE_COMMIT,
            "source_tree": OLD_SOURCE_TREE,
            "binary_sha256": OLD_BINARY_SHA256,
            "fre_commit": OLD_FRE_COMMIT,
            "fre_tree": OLD_FRE_TREE,
            "optimizer_version": 26,
        }
    if role == "new":
        return {
            "source_commit": NEW_SOURCE_COMMIT,
            "source_tree": NEW_SOURCE_TREE,
            "binary_sha256": NEW_BINARY_SHA256,
            "fre_commit": NEW_FRE_COMMIT,
            "fre_tree": NEW_FRE_TREE,
            "optimizer_version": 26,
        }
    raise AuditError("unknown identity")


def bootstrap_seed(prereg: Mapping[str, Any]) -> dict[str, Any]:
    preimage = (
        BOOTSTRAP_DOMAIN
        + b"\0"
        + bytes.fromhex(prereg["identities"]["old"]["binary_sha256"])
        + bytes.fromhex(prereg["identities"]["new"]["binary_sha256"])
        + bytes.fromhex(
            prereg["qualification_probes"]["old"]["private_sha256"]
        )
        + bytes.fromhex(
            prereg["qualification_probes"]["new"]["private_sha256"]
        )
        + bytes.fromhex(FIXED44_MANIFEST_SHA256)
    )
    digest = hashlib.sha256(preimage).digest()
    return {
        "sha256": digest.hex(),
        "u64_big_endian_first8": int.from_bytes(digest[:8], "big"),
    }


def validate_preregistration(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    prereg = load_object(path, "preregistration")
    exact_keys(
        prereg,
        (
            "schema", "sealed_before_timing", "protocol", "identities",
            "qualification_probes", "qualification_artifacts", "inputs",
            "runner", "host_capability_attestation",
        ),
        "preregistration",
    )
    if (
        raw != canonical_json_bytes(prereg)
        or prereg["schema"] != PREREG_SCHEMA
        or prereg["sealed_before_timing"] is not True
        or hashlib.sha256(canonical_json_bytes(prereg["protocol"])).hexdigest()
        != PROTOCOL_SHA256
    ):
        raise AuditError("preregistration seal or protocol is invalid")
    identities = exact_keys(prereg["identities"], ("old", "new"), "identities")
    for role in ("old", "new"):
        if identities[role] != identity_record(role):
            raise AuditError(f"{role} identity is invalid")
    probes = exact_keys(
        prereg["qualification_probes"], ("old", "new"), "probe bindings"
    )
    expected_hashes = {
        "old": (OLD_PROBE_PRIVATE_SHA256, OLD_PROBE_PUBLIC_SHA256),
        "new": (NEW_PROBE_PRIVATE_SHA256, NEW_PROBE_PUBLIC_SHA256),
    }
    for role in ("old", "new"):
        probe = exact_keys(
            probes[role],
            (
                "private_sha256", "public_sha256", "stock_binary_sha256",
                "stock_source_commit", "stock_source_tree",
            ),
            f"{role} probe binding",
        )
        if (
            (probe["private_sha256"], probe["public_sha256"])
            != expected_hashes[role]
            or not is_sha256(probe["stock_binary_sha256"])
            or not is_git_oid(probe["stock_source_commit"])
            or not is_git_oid(probe["stock_source_tree"])
        ):
            raise AuditError(f"{role} probe binding is invalid")
    if prereg["qualification_artifacts"] != {
        "new_manifest_sha256": NEW_QUALIFICATION_MANIFEST_SHA256,
        "new_archive_sha256": NEW_QUALIFICATION_ARCHIVE_SHA256,
    }:
        raise AuditError("qualification artifact binding is invalid")
    exact_keys(
        prereg["inputs"],
        (
            "selection_transport_sha256", "ripgrep_corpus_commit",
            "ripgrep_corpus_tree", "fre_corpus_commit", "fre_corpus_tree",
        ),
        "input bindings",
    )
    exact_keys(
        prereg["runner"],
        (
            "source_commit", "source_tree", "scanner_delta_sha256",
            "auditor_sha256",
        ),
        "runner binding",
    )
    inputs = prereg["inputs"]
    runner = prereg["runner"]
    if (
        not is_sha256(inputs["selection_transport_sha256"])
        or not all(is_git_oid(inputs[field]) for field in (
            "ripgrep_corpus_commit", "ripgrep_corpus_tree",
            "fre_corpus_commit", "fre_corpus_tree",
        ))
        or not is_git_oid(runner["source_commit"])
        or not is_git_oid(runner["source_tree"])
        or not is_sha256(runner["scanner_delta_sha256"])
        or not is_sha256(runner["auditor_sha256"])
    ):
        raise AuditError("input or runner hash binding is invalid")
    validate_capability_attestation(prereg["host_capability_attestation"])
    return prereg, hashlib.sha256(raw).hexdigest()


def batch_vector_verification(
    private: Mapping[str, Any], *, role: str,
) -> dict[str, Any]:
    if role == "old":
        return {
            "required": False,
            "reason": "baseline predates the authenticated batch-width field",
        }
    if role != "new":
        raise AuditError("unknown batch-vector verification role")
    rows = private.get("rows")
    if not isinstance(rows, list):
        raise AuditError("new probe rows are missing")
    expected_batches = {"auto": 4, "asimd": 1, "sve": 4, "sve2": 4}
    expected_tiers = {
        "auto": "aarch64_sve2",
        "asimd": "aarch64_asimd",
        "sve": "aarch64_sve",
        "sve2": "aarch64_sve2",
    }
    expected_ids_by_panel = {
        "ripgrep-default-output": {
            private_id for private_id in SELECTED_IDS
            if private_id.startswith("oot-")
        },
        "fre-count-default-threads": set(SELECTED_IDS),
        "fre-count-thread1": set(SELECTED_IDS),
    }
    expected_keys = {
        (profile, panel, private_id)
        for profile in CPU_PROFILES
        for panel, private_ids in expected_ids_by_panel.items()
        for private_id in private_ids
    }
    observed_keys: set[tuple[str, str, str]] = set()
    observed = {profile: 0 for profile in CPU_PROFILES}
    observed_by_panel = {
        profile: {panel: 0 for panel in PANELS}
        for profile in CPU_PROFILES
    }
    distributions = {profile: {} for profile in CPU_PROFILES}
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or row.get("private_id") not in SELECTED_IDS
        ):
            continue
        profile = row.get("cpu_profile")
        panel = row.get("panel")
        private_id = row.get("private_id")
        key = (profile, panel, private_id)
        if key not in expected_keys or key in observed_keys:
            raise AuditError(
                "new probe batch-vector receipt key is invalid or duplicated"
            )
        observed_keys.add(key)
        background = row.get("background")
        receipt = (
            background.get("receipt")
            if isinstance(background, Mapping) else None
        )
        compile_receipt = (
            receipt.get("compile_receipt_v2")
            if isinstance(receipt, Mapping) else None
        )
        report = (
            compile_receipt.get("exact_finite_selected_end_teddy_aot_v2")
            if isinstance(compile_receipt, Mapping) else None
        )
        lowering = report.get("lowering") if isinstance(report, Mapping) else None
        expected_batch = expected_batches[str(profile)]
        expected_tier = expected_tiers[str(profile)]
        if (
            not isinstance(lowering, Mapping)
            or lowering.get("batch_vectors") != expected_batch
            or lowering.get("selected_target_tier") != expected_tier
            or lowering.get("emitted_isa")
            != ("aarch64_asimd" if profile == "asimd" else "aarch64_sve")
            or lowering.get("authenticated_compiler_report") is not True
        ):
            raise AuditError(
                "new probe does not authenticate the selected batch width"
        )
        observed[str(profile)] += 1
        observed_by_panel[str(profile)][str(panel)] += 1
        key = str(lowering["batch_vectors"])
        distributions[str(profile)][key] = (
            distributions[str(profile)].get(key, 0) + 1
        )
    expected_counts = {profile: 79 for profile in CPU_PROFILES}
    expected_panel_counts = {
        panel: len(private_ids)
        for panel, private_ids in expected_ids_by_panel.items()
    }
    expected_by_panel = {
        profile: dict(expected_panel_counts) for profile in CPU_PROFILES
    }
    if (
        observed_keys != expected_keys
        or observed != expected_counts
        or observed_by_panel != expected_by_panel
    ):
        raise AuditError("new probe batch-vector receipt matrix is incomplete")
    return {
        "required": True,
        "expected_selected_receipts_per_profile": expected_counts,
        "expected_selected_receipts_per_profile_by_panel": expected_by_panel,
        "expected_batch_vectors_by_profile": expected_batches,
        "observed_selected_receipts_per_profile": observed,
        "observed_selected_receipts_per_profile_by_panel": observed_by_panel,
        "observed_batch_vectors_by_profile": distributions,
        "exact_profile_panel_private_id_coverage": True,
        "all_passed": True,
    }


def verify_external_bindings(
    args: argparse.Namespace, prereg: Mapping[str, Any],
) -> dict[str, Any]:
    files = {
        "old_probe_private": (
            args.old_probe_private,
            prereg["qualification_probes"]["old"]["private_sha256"],
        ),
        "old_probe_public": (
            args.old_probe_public,
            prereg["qualification_probes"]["old"]["public_sha256"],
        ),
        "new_probe_private": (
            args.new_probe_private,
            prereg["qualification_probes"]["new"]["private_sha256"],
        ),
        "new_probe_public": (
            args.new_probe_public,
            prereg["qualification_probes"]["new"]["public_sha256"],
        ),
        "selection_transport": (
            args.selection_manifest_input,
            prereg["inputs"]["selection_transport_sha256"],
        ),
        "new_qualification_manifest": (
            args.new_qualification_manifest,
            NEW_QUALIFICATION_MANIFEST_SHA256,
        ),
        "new_qualification_archive": (
            args.new_qualification_archive,
            NEW_QUALIFICATION_ARCHIVE_SHA256,
        ),
    }
    if any(sha256_file(path) != expected for path, expected in files.values()):
        raise AuditError("an externally bound artifact hash changed")
    _, registered_host = validate_capability_attestation(
        prereg["host_capability_attestation"]
    )
    result: dict[str, Any] = {}
    for role in ("old", "new"):
        private = load_object(
            getattr(args, f"{role}_probe_private"), f"{role} private probe"
        )
        public = load_object(
            getattr(args, f"{role}_probe_public"), f"{role} public probe"
        )
        registered = prereg["qualification_probes"][role]
        identity = identity_record(role)
        source = exact_keys(
            public.get("candidate_source"), ("commit", "tree", "clean"),
            f"{role} probe candidate source",
        )
        stock_source = exact_keys(
            public.get("stock_source"), ("commit", "tree", "clean"),
            f"{role} probe stock source",
        )
        binaries = exact_keys(
            public.get("binaries"), ("candidate", "stock"),
            f"{role} probe binaries",
        )
        candidate_binary = exact_keys(
            binaries["candidate"], ("sha256", "version"),
            f"{role} probe candidate binary",
        )
        stock_binary = exact_keys(
            binaries["stock"], ("sha256", "version"),
            f"{role} probe stock binary",
        )
        dependency = exact_keys(
            public.get("fre_dependency"),
            (
                "source", "manifest_revision", "locked_revision",
                "locked_package_count", "cargo_toml_sha256",
                "cargo_lock_sha256",
            ),
            f"{role} probe FRE dependency",
        )
        disposition = public.get("selected_or_stock_disposition")
        matrix = public.get("target_validation_matrix")
        if not isinstance(disposition, Mapping) or not isinstance(matrix, Mapping):
            raise AuditError(f"{role} qualification probe matrices are malformed")
        host_signature = probe_capability_signature(public)
        batch_verification = batch_vector_verification(private, role=role)
        target_profiles = matrix.get("per_profile", {})
        target_hosts = matrix.get("global_qualified_host_feature_bits", [])
        expected_disposition = {
            "fixed_itt": 44,
            "selected_teddy_published": 34,
            "ordinary_compiled_stock_fallback": 9,
            "compile_object_decline": 1,
        }
        compare_float_tree(
            disposition.get("expected_per_profile"),
            expected_disposition,
            f"{role} expected disposition",
        )
        per_profile_disposition = disposition.get("per_profile")
        if (
            not isinstance(per_profile_disposition, Mapping)
            or set(per_profile_disposition) != set(CPU_PROFILES)
        ):
            raise AuditError(f"{role} disposition profile matrix is invalid")
        for profile in CPU_PROFILES:
            compare_float_tree(
                per_profile_disposition[profile],
                {
                    "selected_teddy_published": 34,
                    "ordinary_compiled_stock_fallback": 9,
                    "compile_object_decline": 1,
                    "invalid": 0,
                    "qualified": True,
                },
                f"{role} {profile} disposition",
            )
        if (
            private.get("schema") != "ripgrep.fre-aot-representative.probe.private.v1"
            or public.get("schema") != "ripgrep.fre-aot-representative.probe.public.v1"
            or public.get("aggregate_only") is not True
            or public.get("contains_patterns_commands_paths_or_per_pattern_rows")
            is not False
            or public.get("post_run_selection_verified") is not True
            or public.get("post_run_provenance_verified") is not True
            or public.get("private_result_sha256")
            != registered["private_sha256"]
            or public.get("candidate_source", {}).get("commit")
            != identity["source_commit"]
            or public.get("candidate_source", {}).get("tree")
            != identity["source_tree"]
            or public.get("binaries", {}).get("candidate", {}).get("sha256")
            != identity["binary_sha256"]
            or public.get("fre_dependency", {}).get("locked_revision")
            != identity["fre_commit"]
            or public.get("stock_source", {}).get("commit")
            != registered["stock_source_commit"]
            or public.get("stock_source", {}).get("tree")
            != registered["stock_source_tree"]
            or public.get("binaries", {}).get("stock", {}).get("sha256")
            != registered["stock_binary_sha256"]
            or public.get("selected_or_stock_disposition", {}).get(
                "all_profiles_qualified"
            ) is not True
            or public.get("exact_teddy_v2_gate", {}).get("all_passed") is not True
            or public.get("forced_midscan_gate", {}).get("all_passed") is not True
            or private.get("selection_manifest_sha256")
            != FIXED44_MANIFEST_SHA256
            or source["clean"] is not True
            or stock_source["clean"] is not True
            or not isinstance(candidate_binary["version"], str)
            or not isinstance(stock_binary["version"], str)
            or dependency["source"] != "https://github.com/danluu/fre.git"
            or dependency["manifest_revision"] != identity["fre_commit"]
            or not positive_int(dependency["locked_package_count"])
            or not is_sha256(dependency["cargo_toml_sha256"])
            or not is_sha256(dependency["cargo_lock_sha256"])
            or matrix.get("qualified") is not True
            or set(target_profiles) != set(CPU_PROFILES)
            or len(target_hosts) != 1
            or any(
                not isinstance(entry, Mapping)
                or set(entry) != {
                    "receipt_count", "fully_target_validated_receipts",
                    "qualified_host_feature_bits", "qualified",
                }
                or entry.get("receipt_count") != 102
                or entry.get("fully_target_validated_receipts") != 102
                or entry.get("qualified_host_feature_bits") != target_hosts
                or entry.get("qualified") is not True
                for entry in target_profiles.values()
            )
            or host_signature != registered_host
        ):
            raise AuditError(f"{role} qualification probe binding is invalid")
        result[role] = {
            "candidate_source": dict(source),
            "candidate_binary": dict(candidate_binary),
            "fre_dependency": dict(dependency),
            "stock_source": dict(stock_source),
            "stock_binary": dict(stock_binary),
            "host_capability_signature": host_signature,
            "selected_or_stock_disposition": disposition,
            "target_validation_matrix": matrix,
            "forced_midscan_gate_verification": {
                "summary_sha256": hashlib.sha256(canonical_json_bytes(
                    public.get("forced_midscan_gate")
                )).hexdigest(),
                "profiles": public["forced_midscan_gate"]["profiles"],
                "all_passed": public["forced_midscan_gate"]["all_passed"],
            },
            "exact_teddy_v2_gate_verification": {
                "summary_sha256": hashlib.sha256(canonical_json_bytes(
                    public.get("exact_teddy_v2_gate")
                )).hexdigest(),
                "profiles": public["exact_teddy_v2_gate"]["profiles"],
                "all_passed": public["exact_teddy_v2_gate"]["all_passed"],
            },
            "batch_vector_verification": batch_verification,
        }
    return result


def median(values: Sequence[float]) -> float:
    if not values:
        raise AuditError("median requires values")
    return float(statistics.median(values))


def geometric_mean(values: Sequence[float]) -> float:
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        raise AuditError("geometric mean requires finite positive values")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def close_float(left: Any, right: float) -> bool:
    return (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and math.isfinite(float(left))
        and math.isclose(float(left), right, rel_tol=1e-15, abs_tol=0.0)
    )


def metrics_from_arms(arms: Mapping[str, Any]) -> dict[str, float]:
    elapsed = {}
    for arm in ("A", "B", "C", "D"):
        value = arms[arm].get("elapsed_ns")
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise AuditError("measured arm elapsed time is invalid")
        elapsed[arm] = value
    a, b, c, d = (elapsed[name] for name in ("A", "B", "C", "D"))
    return {
        "S": a / b,
        "C": c / d,
        "D": (d / b) / (c / a),
        "R0": c / a,
        "R1": d / b,
    }


def validate_output_record(value: Any, label: str) -> Mapping[str, Any]:
    record = exact_keys(value, ("bytes", "sha256"), label)
    if (
        not isinstance(record["bytes"], int)
        or isinstance(record["bytes"], bool)
        or record["bytes"] < 0
        or not is_sha256(record["sha256"])
    ):
        raise AuditError(f"{label} is invalid")
    return record


def validate_arm(value: Any, *, measured: bool, label: str) -> Mapping[str, Any]:
    common = (
        "timed_out", "status", "stdout", "stderr", "receipt",
        "receipt_parse_error", "unexpected_temporary_artifacts",
    )
    arm = exact_keys(
        value,
        (*(("elapsed_ns", "user_ns", "system_ns") if measured else ()), *common),
        label,
    )
    if (
        arm["timed_out"] is not False
        or type(arm["status"]) is not int
        or arm["status"] not in (0, 1)
        or arm["receipt"] is not None
        or arm["receipt_parse_error"] is not False
        or type(arm["unexpected_temporary_artifacts"]) is not int
        or arm["unexpected_temporary_artifacts"] != 0
    ):
        raise AuditError(f"{label} status/temp/receipt closure failed")
    validate_output_record(arm["stdout"], f"{label} stdout")
    validate_output_record(arm["stderr"], f"{label} stderr")
    if measured and any(
        not isinstance(arm[field], int)
        or isinstance(arm[field], bool)
        or arm[field] < (1 if field == "elapsed_ns" else 0)
        for field in ("elapsed_ns", "user_ns", "system_ns")
    ):
        raise AuditError(f"{label} timing is invalid")
    return arm


def validate_quartet(
    value: Any,
    *,
    measured: bool,
    expected_order_index: int,
    panel: str,
    label: str,
) -> dict[str, Any]:
    keys = (
        "order_index", "order", "normalization", "comparison_records",
        "arms", "closure_verified",
    )
    quartet = exact_keys(
        value, (*keys, *(("metrics",) if measured else ())), label
    )
    if (
        type(quartet["order_index"]) is not int
        or quartet["order_index"] != expected_order_index
        or quartet["order"] != list(ORDERS[expected_order_index])
        or not isinstance(quartet["normalization"], list)
        or quartet["closure_verified"] is not True
    ):
        raise AuditError(f"{label} schedule is invalid")
    arms = exact_keys(quartet["arms"], ("A", "B", "C", "D"), f"{label} arms")
    comparisons = exact_keys(
        quartet["comparison_records"], ("A", "B", "C", "D"),
        f"{label} comparisons",
    )
    validated_arms = {
        arm: validate_arm(arms[arm], measured=measured, label=f"{label} {arm}")
        for arm in ("A", "B", "C", "D")
    }
    validated_comparisons = {}
    for arm in ("A", "B", "C", "D"):
        comparison = exact_keys(
            comparisons[arm],
            ("status", "stderr_sha256", "semantic_stdout_sha256"),
            f"{label} {arm} comparison",
        )
        result = validated_arms[arm]
        if (
            type(comparison["status"]) is not int
            or comparison["status"] != result["status"]
            or comparison["stderr_sha256"] != result["stderr"]["sha256"]
            or not is_sha256(comparison["semantic_stdout_sha256"])
            or panel == "fre-count-thread1"
            and comparison["semantic_stdout_sha256"]
            != result["stdout"]["sha256"]
        ):
            raise AuditError(f"{label} {arm} comparison evidence is invalid")
        validated_comparisons[arm] = dict(comparison)
    if any(
        validated_comparisons[arm] != validated_comparisons["A"]
        for arm in ("B", "C", "D")
    ):
        raise AuditError(f"{label} four-arm output/status closure failed")
    result = dict(quartet)
    if measured:
        metrics = exact_keys(quartet["metrics"], METRICS, f"{label} metrics")
        recomputed = metrics_from_arms(validated_arms)
        if any(not close_float(metrics[metric], recomputed[metric]) for metric in METRICS):
            raise AuditError(f"{label} metric does not reconcile")
        if not math.isclose(
            recomputed["D"], recomputed["S"] / recomputed["C"], rel_tol=1e-15
        ):
            raise AuditError(f"{label} delta identity does not reconcile")
        result["metrics"] = recomputed
    return result


def recompute_row_summary(quartets: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    metrics = {
        metric: median([float(item["metrics"][metric]) for item in quartets])
        for metric in METRICS
    }
    a_first = [
        float(item["metrics"]["S"])
        for item in quartets
        if item["order"].index("A") < item["order"].index("B")
    ]
    b_first = [
        float(item["metrics"]["S"])
        for item in quartets
        if item["order"].index("B") < item["order"].index("A")
    ]
    first = [
        float(item["metrics"]["D"])
        for item in quartets if item["order_index"] < 4
    ]
    reverse = [
        float(item["metrics"]["D"])
        for item in quartets if item["order_index"] >= 4
    ]
    if any(len(values) != 4 for values in (a_first, b_first, first, reverse)):
        raise AuditError("row diagnostic split is unbalanced")
    return {
        "metrics": metrics,
        "background_direction_S": {
            "A_before_B": median(a_first),
            "B_before_A": median(b_first),
        },
        "cycle_orientation_D": {
            "orders_0_3": median(first),
            "orders_4_7": median(reverse),
        },
    }


def compare_float_tree(actual: Any, expected: Any, label: str) -> None:
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or set(actual) != set(expected):
            raise AuditError(f"{label} object fields differ")
        for key in expected:
            compare_float_tree(actual[key], expected[key], f"{label}.{key}")
        return
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise AuditError(f"{label} list differs")
        for index, item in enumerate(expected):
            compare_float_tree(actual[index], item, f"{label}[{index}]")
        return
    if isinstance(expected, float):
        if not close_float(actual, expected):
            raise AuditError(f"{label} float differs")
        return
    if isinstance(expected, bool):
        if actual is not expected:
            raise AuditError(f"{label} boolean differs")
        return
    if isinstance(expected, int):
        if type(actual) is not int or actual != expected:
            raise AuditError(f"{label} integer differs")
        return
    if actual != expected:
        raise AuditError(f"{label} differs")


def validate_manifest(value: Any) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    if not isinstance(value, list) or len(value) != 44:
        raise AuditError("fixed44 selection manifest is invalid")
    manifest = []
    ids = []
    for index, row in enumerate(value):
        item = exact_keys(
            row,
            (
                "private_id", "cohort", "pattern", "occurrence_weight",
                "suffix", "semantics", "target_kind", "extension_class",
            ),
            f"selection manifest row {index}",
        )
        private_id = item["private_id"]
        if (
            not isinstance(private_id, str)
            or not isinstance(item["pattern"], str)
            or not isinstance(item["cohort"], str)
            or not isinstance(item["occurrence_weight"], int)
            or isinstance(item["occurrence_weight"], bool)
            or item["occurrence_weight"] <= 0
            or not isinstance(item["semantics"], Mapping)
        ):
            raise AuditError("selection manifest value is invalid")
        ids.append(private_id)
        manifest.append(dict(item))
    if (
        len(set(ids)) != 44
        or set(ids) != SELECTED_IDS | COMPLEMENT_IDS
        or SELECTED_IDS & COMPLEMENT_IDS
        or sum(private_id.startswith("oot-") for private_id in ids) != 14
        or frozen_ids_digest(SELECTED_IDS) != SELECTED34_IDS_SHA256
        or frozen_ids_digest(COMPLEMENT_IDS) != COMPLEMENT10_IDS_SHA256
        or digest_json(manifest) != FIXED44_MANIFEST_SHA256
        or digest_json([item for item in manifest if item["private_id"] in SELECTED_IDS])
        != SELECTED34_MANIFEST_SHA256
        or digest_json([
            item for item in manifest if item["private_id"] in COMPLEMENT_IDS
        ]) != COMPLEMENT10_MANIFEST_SHA256
    ):
        raise AuditError("frozen cohort manifests or IDs changed")
    return manifest, {item["private_id"]: item for item in manifest}


def normalized_profile_flags(case: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    semantics = case["semantics"]
    if not isinstance(semantics, Mapping):
        raise AuditError("case semantics are invalid")
    flags: list[str] = []
    notes: list[str] = []
    if semantics.get("matcher_mode") == "fixed_strings":
        flags.append("--fixed-strings")
    if semantics.get("regex_engine_request") not in (
        None, "ripgrep_default", "default",
    ):
        notes.append("engine_request_normalized_to_default")
    case_mode = semantics.get("case")
    if case_mode == "ignore_case":
        flags.append("--ignore-case")
    elif case_mode == "smart_case":
        flags.append("--smart-case")
    elif case_mode == "multiple_case_flags":
        notes.append("multiple_case_flags_normalized_to_default")
    for field, flag in (
        ("multiline", "--multiline"),
        ("multiline_dotall", "--multiline-dotall"),
        ("word_regexp", "--word-regexp"),
        ("invert_match", "--invert-match"),
        ("crlf", "--crlf"),
    ):
        if semantics.get(field) is True:
            flags.append(flag)
    if semantics.get("unicode") is False:
        flags.append("--no-unicode")
    if semantics.get("command_flag_parse_fallback") is True:
        notes.append("historical_flag_parse_fallback")
    return flags, notes


def expected_query_argv(
    case: Mapping[str, Any], panel: str, root: str,
) -> tuple[list[str], list[str]]:
    flags, notes = normalized_profile_flags(case)
    argv = [
        "--no-config", "--engine=default", "--hidden", "--no-ignore",
        "--text", "--color=never", "--no-heading", "--with-filename",
    ]
    if panel == "ripgrep-default-output":
        argv.append("--line-number")
    else:
        argv.extend(("--count", "--include-zero"))
    if panel == "fre-count-thread1":
        argv.append("--threads=1")
    argv.extend(flags)
    suffix = case["suffix"]
    if suffix is not None:
        if not isinstance(suffix, str):
            raise AuditError("case suffix is invalid")
        argv.extend(("--glob", f"*{suffix}"))
    argv.extend(("--", str(case["pattern"]), root))
    return argv, notes


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
    return "short_lt_32" if length < 32 else "medium_32_127" if length < 128 else "long_ge_128"


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


def cohort_profile(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    lengths: Counter[str] = Counter()
    arms: Counter[str] = Counter()
    features: Counter[str] = Counter()
    semantic_fields = ("matcher_mode", "regex_engine_request", "case")
    semantics = {field: Counter() for field in semantic_fields}
    boolean_fields = (
        "multiline", "multiline_dotall", "word_regexp", "invert_match",
        "unicode", "crlf", "command_flag_parse_fallback",
    )
    boolean_counts = {field: Counter() for field in boolean_fields}
    target_kinds: Counter[str] = Counter()
    extension_classes: Counter[str] = Counter()
    normalization: Counter[str] = Counter()
    for case in cases:
        pattern = str(case["pattern"])
        shape = query_shape(pattern)
        lengths[length_bucket(shape["length"])] += 1
        arms[arm_bucket(shape["alternations"])] += 1
        for field in (
            "anchored", "dotstar", "grouped", "escaped",
            "character_class", "plainish",
        ):
            features[field] += int(shape[field])
        case_semantics = case["semantics"]
        for field in semantic_fields:
            semantics[field][str(case_semantics.get(field, "unknown"))] += 1
        for field in boolean_fields:
            value = case_semantics.get(field)
            key = "true" if value is True else "false" if value is False else "unknown"
            boolean_counts[field][key] += 1
        target_kinds[str(case["target_kind"] or "unavailable")] += 1
        extension_classes[str(case["extension_class"] or "unavailable")] += 1
        _, notes = normalized_profile_flags(case)
        if notes:
            normalization.update(notes)
            normalization["patterns_with_normalization"] += 1
        else:
            normalization["patterns_without_normalization"] += 1
    return {
        "unique_patterns": len(cases),
        "occurrence_weight": sum(int(case["occurrence_weight"]) for case in cases),
        "suffix_filtered_patterns": sum(case["suffix"] is not None for case in cases),
        "length_buckets": dict(sorted(lengths.items())),
        "alternation_arms": dict(sorted(arms.items())),
        "syntax_feature_counts": dict(sorted(features.items())),
        "target_kinds": dict(sorted(target_kinds.items())),
        "extension_classes": dict(sorted(extension_classes.items())),
        "normalization_counts": dict(sorted(normalization.items())),
        "semantics": {
            **{field: dict(sorted(values.items())) for field, values in semantics.items()},
            **{field: dict(sorted(values.items())) for field, values in boolean_counts.items()},
        },
    }


def expected_row_specs(manifest: Sequence[Mapping[str, Any]]) -> list[tuple[int, str, str, str]]:
    result = []
    ordinal = 0
    for profile in CPU_PROFILES:
        for panel in PANELS:
            cases = (
                [item for item in manifest if item["private_id"].startswith("oot-")]
                if panel == "ripgrep-default-output" else list(manifest)
            )
            for case in cases:
                result.append((ordinal, profile, panel, str(case["private_id"])))
                ordinal += 1
    if len(result) != 408:
        raise AuditError("canonical row matrix is not 408 rows")
    return result


def validate_rows(
    rows: Any,
    *,
    traversal: str,
    manifest: Sequence[Mapping[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) != 408:
        raise AuditError("result row matrix is incomplete")
    if traversal != "canonical":
        raise AuditError("only canonical row traversal is auditable")
    specs = expected_row_specs(manifest)
    expected_order = specs
    validated = []
    corpus_roots: dict[str, str] = {}
    identity_fields = (
        "private_id", "cohort", "pattern", "occurrence_weight", "suffix",
        "semantics", "target_kind", "extension_class",
    )
    for position, (row, spec) in enumerate(zip(rows, expected_order)):
        item = exact_keys(
            row,
            (
                "canonical_row_ordinal", *identity_fields,
                "query_argv_after_binary", "cpu_profile", "panel", "warmups",
                "quartets", "summary",
            ),
            f"row {position}",
        )
        ordinal, profile, panel, private_id = spec
        expected_case = by_id[private_id]
        argv = item["query_argv_after_binary"]
        if (
            type(item["canonical_row_ordinal"]) is not int
            or item["canonical_row_ordinal"] != ordinal
            or item["cpu_profile"] != profile
            or item["panel"] != panel
            or not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) for argument in argv)
        ):
            raise AuditError(f"row {position} identity is invalid")
        for field in identity_fields:
            compare_float_tree(
                item[field], expected_case[field],
                f"row {position} identity.{field}",
            )
        root = argv[-1]
        root_path = Path(root)
        corpus_name = "ripgrep" if panel == "ripgrep-default-output" else "fre"
        expected_basename = f"corpus-{corpus_name}"
        if (
            not root_path.is_absolute()
            or ".." in root_path.parts
            or root_path.name != expected_basename
            or corpus_name in corpus_roots
            and corpus_roots[corpus_name] != root
        ):
            raise AuditError(f"row {position} corpus root is invalid")
        corpus_roots.setdefault(corpus_name, root)
        expected_argv, expected_normalization = expected_query_argv(
            expected_case, panel, root
        )
        if argv != expected_argv:
            raise AuditError(f"row {position} query argv differs from the panel grammar")
        warmups = item["warmups"]
        quartets = item["quartets"]
        if not isinstance(warmups, list) or len(warmups) != 2:
            raise AuditError(f"row {position} warmups are invalid")
        validated_warmups = [
            validate_quartet(
                warmups[index], measured=False,
                expected_order_index=(ordinal - 2 + index) % 8,
                panel=panel, label=f"row {position} warmup {index}",
            )
            for index in range(2)
        ]
        if any(
            warmup["normalization"] != expected_normalization
            for warmup in validated_warmups
        ):
            raise AuditError(f"row {position} warmup normalization differs")
        if not isinstance(quartets, list) or len(quartets) != 8:
            raise AuditError(f"row {position} measured quartets are invalid")
        validated_quartets = [
            validate_quartet(
                quartets[index], measured=True,
                expected_order_index=(ordinal + index) % 8,
                panel=panel, label=f"row {position} quartet {index}",
            )
            for index in range(8)
        ]
        if any(
            quartet["normalization"] != expected_normalization
            for quartet in validated_quartets
        ):
            raise AuditError(f"row {position} measured normalization differs")
        summary = recompute_row_summary(validated_quartets)
        compare_float_tree(item["summary"], summary, f"row {position} summary")
        validated.append({
            **dict(item),
            "warmups": validated_warmups,
            "quartets": validated_quartets,
            "summary": summary,
        })
    if (
        set(corpus_roots) != {"ripgrep", "fre"}
        or corpus_roots["ripgrep"] == corpus_roots["fre"]
        or Path(corpus_roots["ripgrep"]).parent
        != Path(corpus_roots["fre"]).parent
    ):
        raise AuditError("corpus root binding is incomplete")
    return validated


def rows_for_stratum(
    rows: Sequence[Mapping[str, Any]], stratum: str,
) -> list[Mapping[str, Any]]:
    if stratum == "intention_to_treat":
        return list(rows)
    ids = SELECTED_IDS if stratum == "selected34" else COMPLEMENT_IDS
    return [row for row in rows if row["private_id"] in ids]


def point_aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise AuditError("aggregate stratum is empty")
    per_id = {
        metric: [
            float(row["summary"]["metrics"][metric]) for row in rows
        ]
        for metric in METRICS
    }
    metrics = {
        metric: {
            "point": geometric_mean(per_id[metric]),
            "minimum_per_id": min(per_id[metric]),
            "maximum_per_id": max(per_id[metric]),
        }
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
        "metrics": metrics,
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


def add_bootstrap(
    aggregate: dict[str, Any],
    rows: Sequence[Mapping[str, Any]],
    rng: random.Random,
) -> None:
    count = len(rows)
    samples = {metric: [] for metric in METRICS}
    for _ in range(BOOTSTRAP_REPLICATES):
        logs = {metric: [] for metric in METRICS}
        for _ in range(count):
            row = rows[rng.randrange(count)]
            quartets = row["quartets"]
            chosen = [quartets[rng.randrange(8)] for _ in range(8)]
            for metric in METRICS:
                logs[metric].append(math.log(median([
                    float(quartet["metrics"][metric]) for quartet in chosen
                ])))
        for metric in METRICS:
            samples[metric].append(math.exp(math.fsum(logs[metric]) / count))
    for metric in METRICS:
        ordered = sorted(samples[metric])
        aggregate["metrics"][metric]["confidence_interval_95"] = [
            ordered[BOOTSTRAP_LOW_INDEX], ordered[BOOTSTRAP_HIGH_INDEX]
        ]


def aggregate_rows(rows: Sequence[Mapping[str, Any]], seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    result: dict[str, Any] = {}
    for profile in CPU_PROFILES:
        result[profile] = {}
        for panel in PANELS:
            panel_rows = sorted(
                (
                    row for row in rows
                    if row["cpu_profile"] == profile and row["panel"] == panel
                ),
                key=lambda row: int(row["canonical_row_ordinal"]),
            )
            result[profile][panel] = {}
            for stratum in STRATA:
                selected = rows_for_stratum(panel_rows, stratum)
                aggregate = point_aggregate(selected)
                add_bootstrap(aggregate, selected, rng)
                result[profile][panel][stratum] = aggregate
    return result


def in_range(value: float, low: float, high: float) -> bool:
    return low <= value <= high


def decision(cells: Mapping[str, Any]) -> dict[str, Any]:
    primary = cells["auto"]["fre-count-thread1"]["selected34"]
    s = primary["metrics"]["S"]
    d = primary["metrics"]["D"]
    r1 = primary["metrics"]["R1"]
    normal_controls = [
        cells[profile]["fre-count-thread1"]["intention_to_treat"]
        ["metrics"]["C"]["point"]
        for profile in CPU_PROFILES
    ]
    asimd_controls = [
        cells["asimd"]["fre-count-thread1"]["selected34"]
        ["metrics"][metric]["point"]
        for metric in ("S", "D")
    ]
    complement_controls = [
        cells[profile]["fre-count-thread1"]["complement10"]
        ["metrics"][metric]["point"]
        for profile in CPU_PROFILES
        for metric in ("S", "D")
    ]
    relevant_directions = [
        cells[profile]["fre-count-thread1"]["selected34"]
        ["metrics"][metric]["point"]
        for profile in ("auto", "sve", "sve2")
        for metric in ("S", "D")
    ]
    requirements = {
        "selected34_auto_thread1_S_point_at_least_1_07": s["point"] >= 1.07,
        "selected34_auto_thread1_S_interval_wholly_above_1": (
            s["confidence_interval_95"][0] > 1.0
        ),
        "selected34_auto_thread1_D_point_at_least_1_03": d["point"] >= 1.03,
        "selected34_auto_thread1_D_interval_wholly_above_1": (
            d["confidence_interval_95"][0] > 1.0
        ),
        "selected34_auto_thread1_R1_point_at_least_1_03": r1["point"] >= 1.03,
        "selected34_auto_thread1_R1_interval_wholly_above_1_03": (
            r1["confidence_interval_95"][0] > 1.03
        ),
        "selected34_auto_thread1_minimum_per_id_S_at_least_0_90": (
            s["minimum_per_id"] >= 0.90
        ),
        "background_direction_ratio_in_0_95_1_05": in_range(
            primary["diagnostic_splits"]["background_direction_S"]["ratio"],
            0.95, 1.05,
        ),
        "cycle_orientation_ratio_in_0_95_1_05": in_range(
            primary["diagnostic_splits"]["cycle_orientation_D"]["ratio"],
            0.95, 1.05,
        ),
        "thread1_normal_C_points_in_0_99_1_03": all(
            in_range(value, 0.99, 1.03) for value in normal_controls
        ),
        "thread1_asimd_selected34_S_D_points_in_0_99_1_03": all(
            in_range(value, 0.99, 1.03) for value in asimd_controls
        ),
        "thread1_complement10_S_D_points_in_0_99_1_03": all(
            in_range(value, 0.99, 1.03) for value in complement_controls
        ),
        "thread1_auto_sve_sve2_selected34_S_D_points_at_least_1": all(
            value >= 1.0 for value in relevant_directions
        ),
    }
    failures = [name for name, passed in requirements.items() if not passed]
    direct = (
        "clear_go"
        if requirements["selected34_auto_thread1_R1_point_at_least_1_03"]
        and requirements[
            "selected34_auto_thread1_R1_interval_wholly_above_1_03"
        ]
        else "clear_no_go"
    )
    scanner_win = all(requirements.values())
    material = requirements["selected34_auto_thread1_S_point_at_least_1_07"]
    return {
        "primary_cell": {
            "profile": "auto",
            "panel": "fre-count-thread1",
            "stratum": "selected34",
        },
        "direct_R1_classification": direct,
        "scanner_win": scanner_win,
        "material_delta": material,
        "requirements": requirements,
        "overall": "go" if scanner_win else "no_go",
        "advancement_gate_failures": failures,
        "reverse_row_confirmation_required": False,
        "reverse_row_confirmation_triggers": [],
    }


def validate_input_binding(
    value: Any,
    prereg: Mapping[str, Any],
    prereg_sha256: str,
    external_probes: Mapping[str, Any],
) -> Mapping[str, Any]:
    binding = exact_keys(
        value,
        (
            "preregistration_sha256", "runner", "host", "identities",
            "qualification_probes", "qualification_artifacts", "selection",
            "corpus_sources", "materialized_corpora",
        ),
        "input binding",
    )
    if binding["preregistration_sha256"] != prereg_sha256:
        raise AuditError("input binding preregistration hash differs")
    runner = exact_keys(
        binding["runner"],
        ("source", "scanner_delta_sha256", "auditor_sha256"),
        "runner input binding",
    )
    runner_source = exact_keys(
        runner["source"], ("commit", "tree", "clean"),
        "runner source binding",
    )
    expected_runner_source = {
        "commit": prereg["runner"]["source_commit"],
        "tree": prereg["runner"]["source_tree"],
        "clean": True,
    }
    compare_float_tree(
        runner_source, expected_runner_source, "runner source binding"
    )
    if (
        runner["scanner_delta_sha256"]
        != prereg["runner"]["scanner_delta_sha256"]
    ) or runner["auditor_sha256"] != prereg["runner"]["auditor_sha256"]:
        raise AuditError("runner binding differs from preregistration")
    host = exact_keys(
        binding["host"],
        ("capability_attestation", "current_capability_signature"),
        "timing host binding",
    )
    attestation, registered_signature = validate_capability_attestation(
        host["capability_attestation"]
    )
    if (
        attestation != prereg["host_capability_attestation"]
        or validate_capability_signature(host["current_capability_signature"])
        != registered_signature
    ):
        raise AuditError("timing host differs from the preregistered probe host")
    identities = exact_keys(
        binding["identities"], ("old", "new"), "measured identities"
    )
    for role in ("old", "new"):
        actual = exact_keys(
            identities[role],
            ("source", "binary", "fre_dependency", "fre_source", "optimizer_version"),
            f"{role} measured identity",
        )
        source = exact_keys(
            actual["source"], ("commit", "tree", "clean"),
            f"{role} measured source",
        )
        binary = exact_keys(
            actual["binary"], ("sha256", "version"),
            f"{role} measured binary",
        )
        dependency = exact_keys(
            actual["fre_dependency"],
            (
                "source", "manifest_revision", "locked_revision",
                "locked_package_count", "cargo_toml_sha256",
                "cargo_lock_sha256",
            ),
            f"{role} measured FRE dependency",
        )
        fre_source = exact_keys(
            actual["fre_source"], ("commit", "tree", "clean"),
            f"{role} measured FRE source",
        )
        expected = identity_record(role)
        external = external_probes[role]
        compare_float_tree(
            source, external["candidate_source"], f"{role} measured source"
        )
        compare_float_tree(
            binary, external["candidate_binary"], f"{role} measured binary"
        )
        compare_float_tree(
            dependency, external["fre_dependency"],
            f"{role} measured FRE dependency",
        )
        compare_float_tree(
            fre_source,
            {
                "commit": expected["fre_commit"],
                "tree": expected["fre_tree"],
                "clean": True,
            },
            f"{role} measured FRE source",
        )
        if (
            type(actual["optimizer_version"]) is not int
            or actual["optimizer_version"] != expected["optimizer_version"]
        ):
            raise AuditError(f"{role} measured identity differs")
    if binding["qualification_artifacts"] != prereg["qualification_artifacts"]:
        raise AuditError("qualification artifact provenance differs")
    qualification = exact_keys(
        binding["qualification_probes"], ("old", "new"),
        "qualification bindings",
    )
    for role in ("old", "new"):
        actual = exact_keys(
            qualification[role],
            (
                "private_sha256", "public_sha256", "optimizer_version",
                "optimizer_receipts_authenticated", "stock_reference",
                "selected_or_stock_disposition", "target_validation_matrix",
                "host_capability_signature",
                "forced_midscan_gate_verification",
                "exact_teddy_v2_gate_verification",
                "batch_vector_verification",
                "untimed_reference_correctness_verified",
            ),
            f"{role} qualification binding",
        )
        stock = exact_keys(
            actual["stock_reference"],
            ("binary_sha256", "source_commit", "source_tree", "timed_in_scanner_delta"),
            f"{role} stock reference",
        )
        registered = prereg["qualification_probes"][role]
        external = external_probes[role]
        compare_float_tree(
            stock,
            {
                "binary_sha256": registered["stock_binary_sha256"],
                "source_commit": registered["stock_source_commit"],
                "source_tree": registered["stock_source_tree"],
                "timed_in_scanner_delta": False,
            },
            f"{role} stock reference",
        )
        for field in (
            "selected_or_stock_disposition", "target_validation_matrix",
            "host_capability_signature", "forced_midscan_gate_verification",
            "exact_teddy_v2_gate_verification", "batch_vector_verification",
        ):
            compare_float_tree(
                actual[field], external[field],
                f"{role} qualification binding.{field}",
            )
        if (
            actual["private_sha256"] != registered["private_sha256"]
            or actual["public_sha256"] != registered["public_sha256"]
            or type(actual["optimizer_version"]) is not int
            or actual["optimizer_version"]
            != identity_record(role)["optimizer_version"]
            or not positive_int(actual["optimizer_receipts_authenticated"])
            or actual["untimed_reference_correctness_verified"] is not True
        ):
            raise AuditError(f"{role} qualification binding differs")
    expected_selection = {
        "transport_sha256": prereg["inputs"]["selection_transport_sha256"],
        "fixed44_manifest_sha256": FIXED44_MANIFEST_SHA256,
        "selected34_manifest_sha256": SELECTED34_MANIFEST_SHA256,
        "selected34_ids_sha256": SELECTED34_IDS_SHA256,
        "complement10_manifest_sha256": COMPLEMENT10_MANIFEST_SHA256,
        "complement10_ids_sha256": COMPLEMENT10_IDS_SHA256,
    }
    if binding["selection"] != expected_selection:
        raise AuditError("selection binding differs")
    corpus_sources = exact_keys(
        binding["corpus_sources"], ("ripgrep", "fre"), "corpus sources"
    )
    materialized = exact_keys(
        binding["materialized_corpora"], ("ripgrep", "fre"),
        "materialized corpora",
    )
    materialized_fields = (
        "commit", "tree", "archive_reported_file_count",
        "archive_reported_total_file_bytes", "entry_count", "directory_count",
        "regular_file_count", "symlink_count", "total_regular_file_bytes",
        "content_tree_sha256",
    )
    for name in ("ripgrep", "fre"):
        source = exact_keys(
            corpus_sources[name],
            ("mirror_clean", "materialized_commit", "materialized_tree"),
            f"{name} corpus source",
        )
        corpus = exact_keys(
            materialized[name], materialized_fields,
            f"{name} materialized corpus",
        )
        expected_commit = prereg["inputs"][f"{name}_corpus_commit"]
        expected_tree = prereg["inputs"][f"{name}_corpus_tree"]
        count_fields = materialized_fields[2:-1]
        compare_float_tree(
            source,
            {
                "mirror_clean": True,
                "materialized_commit": expected_commit,
                "materialized_tree": expected_tree,
            },
            f"{name} corpus source",
        )
        if (
            corpus["commit"] != expected_commit
            or corpus["tree"] != expected_tree
            or not is_sha256(corpus["content_tree_sha256"])
            or any(not nonnegative_int(corpus[field]) for field in count_fields)
            or not positive_int(corpus["archive_reported_file_count"])
            or not positive_int(corpus["archive_reported_total_file_bytes"])
            or not positive_int(corpus["entry_count"])
            or not positive_int(corpus["regular_file_count"])
            or not positive_int(corpus["total_regular_file_bytes"])
            or corpus["entry_count"]
            != corpus["directory_count"] + corpus["regular_file_count"] + corpus["symlink_count"]
        ):
            raise AuditError(f"{name} corpus binding differs")
    return binding


def validate_snapshot(value: Any, label: str) -> Mapping[str, Any]:
    snapshot = exact_keys(
        value, ("utc", "unix_ns", "load_average_1m_5m_15m"), label
    )
    if (
        not isinstance(snapshot["utc"], str)
        or not isinstance(snapshot["unix_ns"], int)
        or isinstance(snapshot["unix_ns"], bool)
        or snapshot["unix_ns"] <= 0
        or snapshot["load_average_1m_5m_15m"] is not None
        and (
            not isinstance(snapshot["load_average_1m_5m_15m"], list)
            or len(snapshot["load_average_1m_5m_15m"]) != 3
            or any(
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not math.isfinite(float(item))
                or float(item) < 0
                for item in snapshot["load_average_1m_5m_15m"]
            )
        )
    ):
        raise AuditError(f"{label} is invalid")
    return snapshot


def validate_public_privacy(
    public: Mapping[str, Any],
    manifest: Sequence[Mapping[str, Any]],
) -> None:
    def string_leaves(value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for child in value.values():
                yield from string_leaves(child)
        elif isinstance(value, list):
            for child in value:
                yield from string_leaves(child)

    def object_keys(value: Any) -> Iterable[str]:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if isinstance(key, str):
                    yield key
                yield from object_keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from object_keys(child)

    def nested_lists(value: Any) -> Iterable[list[Any]]:
        if isinstance(value, Mapping):
            for child in value.values():
                yield from nested_lists(child)
        elif isinstance(value, list):
            yield value
            for child in value:
                yield from nested_lists(child)

    strings = list(string_leaves(public))
    keys = list(object_keys(public))
    private_ids = {str(item["private_id"]) for item in manifest}
    patterns = {str(item["pattern"]) for item in manifest}
    banned_keys = {
        "pattern", "private_id", "query_argv_after_binary", "argv", "cwd",
        "path", "rows", "selection_manifest",
    }
    if (
        set(strings) & (private_ids | patterns)
        or set(keys) & (private_ids | patterns)
        or any(value.startswith(("/", "./", "../")) for value in strings)
        or any(key in banned_keys for key in keys)
        or any(
            any(
                isinstance(item, str) and item.startswith("--")
                for item in value
            )
            for value in nested_lists(public)
        )
    ):
        raise AuditError(
            "public result leaks pattern, query, path, or per-ID evidence"
        )


def validate_result_pair(
    *,
    private_path: Path,
    public_path: Path,
    expected_role: str,
    expected_traversal: str,
    prereg: Mapping[str, Any],
    prereg_sha256: str,
    external_probes: Mapping[str, Any],
) -> dict[str, Any]:
    if expected_role != "primary" or expected_traversal != "canonical":
        raise AuditError("only the primary canonical campaign is auditable")
    private_sha = sha256_file(private_path)
    public_sha = sha256_file(public_path)
    private = load_object(private_path, f"{expected_role} private result")
    public = load_object(public_path, f"{expected_role} public result")
    exact_keys(
        private,
        (
            "schema", "contains_raw_patterns", "local_only_do_not_commit",
            "campaign_role", "row_traversal", "preregistration_sha256",
            "protocol", "bootstrap_seed", "pre_run_input_binding",
            "post_run_input_binding", "confirmation_of",
            "selection_manifest_sha256", "selection_manifest",
            "workload_environment", "rows", "cells", "decision",
            "post_run_selection_verified", "post_run_provenance_verified",
        ),
        f"{expected_role} private result",
    )
    exact_keys(
        public,
        (
            "schema", "aggregate_only",
            "contains_patterns_commands_paths_or_per_pattern_rows",
            "campaign_role", "row_traversal", "preregistration_sha256",
            "protocol", "bootstrap_seed", "pre_run_input_binding",
            "post_run_input_binding", "confirmation_of",
            "method", "workload_environment", "cohorts", "cells", "decision",
            "post_run_selection_verified", "post_run_provenance_verified",
            "private_result_sha256",
        ),
        f"{expected_role} public result",
    )
    compare_float_tree(
        private["protocol"], prereg["protocol"],
        f"{expected_role} private protocol",
    )
    compare_float_tree(
        public["protocol"], prereg["protocol"],
        f"{expected_role} public protocol",
    )
    if (
        private["schema"] != PRIVATE_SCHEMA
        or private["contains_raw_patterns"] is not True
        or private["local_only_do_not_commit"] is not True
        or public["schema"] != PUBLIC_SCHEMA
        or public["aggregate_only"] is not True
        or public["contains_patterns_commands_paths_or_per_pattern_rows"]
        is not False
        or private["campaign_role"] != expected_role
        or public["campaign_role"] != expected_role
        or private["row_traversal"] != expected_traversal
        or public["row_traversal"] != expected_traversal
        or private["preregistration_sha256"] != prereg_sha256
        or public["preregistration_sha256"] != prereg_sha256
        or public["private_result_sha256"] != private_sha
        or private["post_run_selection_verified"] is not True
        or public["post_run_selection_verified"] is not True
        or private["post_run_provenance_verified"] is not True
        or public["post_run_provenance_verified"] is not True
    ):
        raise AuditError(f"{expected_role} result envelope is invalid")
    seed = bootstrap_seed(prereg)
    compare_float_tree(
        private["bootstrap_seed"], seed,
        f"{expected_role} private bootstrap seed",
    )
    compare_float_tree(
        public["bootstrap_seed"], seed,
        f"{expected_role} public bootstrap seed",
    )
    binding = validate_input_binding(
        private["pre_run_input_binding"], prereg, prereg_sha256,
        external_probes,
    )
    post_binding = validate_input_binding(
        private["post_run_input_binding"], prereg, prereg_sha256,
        external_probes,
    )
    compare_float_tree(
        post_binding, binding, f"{expected_role} post-run input binding"
    )
    compare_float_tree(
        public["pre_run_input_binding"], binding,
        f"{expected_role} public pre-run input binding",
    )
    compare_float_tree(
        public["post_run_input_binding"], post_binding,
        f"{expected_role} public post-run input binding",
    )
    compare_float_tree(
        public["confirmation_of"], private["confirmation_of"],
        f"{expected_role} confirmation binding",
    )
    if private["confirmation_of"] is not None:
        raise AuditError("primary result unexpectedly confirms another result")
    workload = exact_keys(
        private["workload_environment"], ("start", "end"),
        f"{expected_role} workload environment",
    )
    start = validate_snapshot(workload["start"], f"{expected_role} start")
    end = validate_snapshot(workload["end"], f"{expected_role} end")
    compare_float_tree(
        public["workload_environment"], workload,
        f"{expected_role} public workload environment",
    )
    if start["unix_ns"] >= end["unix_ns"]:
        raise AuditError(f"{expected_role} workload chronology is invalid")
    if private["selection_manifest_sha256"] != FIXED44_MANIFEST_SHA256:
        raise AuditError("private result fixed44 digest differs")
    manifest, by_id = validate_manifest(private["selection_manifest"])
    rows = validate_rows(
        private["rows"], traversal=expected_traversal,
        manifest=manifest, by_id=by_id,
    )
    cells = aggregate_rows(rows, int(seed["u64_big_endian_first8"]))
    recomputed_decision = decision(cells)
    compare_float_tree(private["cells"], cells, f"{expected_role} private cells")
    compare_float_tree(public["cells"], cells, f"{expected_role} public cells")
    compare_float_tree(
        private["decision"], recomputed_decision,
        f"{expected_role} private decision",
    )
    compare_float_tree(
        public["decision"], recomputed_decision,
        f"{expected_role} public decision",
    )
    method = exact_keys(
        public["method"],
        (
            "unit", "timed_arms", "stock_or_automatic_timed_arms",
            "warmup_quartets_per_row", "measured_quartets_per_row",
            "canonical_rows", "row_offset_uses_stable_canonical_ordinal",
            "timed_receipts", "filesystem_cache_state",
        ),
        f"{expected_role} method",
    )
    if (
        method["unit"] != "one frozen query in one fresh ripgrep process"
        or method["filesystem_cache_state"] != (
            "cache-hot/uncontrolled after one archive materialization; "
            "no eviction between invocations"
        )
        or method["timed_arms"] != ["B0", "B1", "N1", "N0"]
        or type(method["stock_or_automatic_timed_arms"]) is not int
        or method["stock_or_automatic_timed_arms"] != 0
        or type(method["warmup_quartets_per_row"]) is not int
        or method["warmup_quartets_per_row"] != 2
        or type(method["measured_quartets_per_row"]) is not int
        or method["measured_quartets_per_row"] != 8
        or type(method["canonical_rows"]) is not int
        or method["canonical_rows"] != 408
        or method["row_offset_uses_stable_canonical_ordinal"] is not True
        or method["timed_receipts"] is not False
    ):
        raise AuditError(f"{expected_role} method differs from protocol")
    cohorts = exact_keys(public["cohorts"], ("oot", "wider"), "public cohorts")
    expected_cohorts = {
        "oot": cohort_profile([
            item for item in manifest if item["private_id"].startswith("oot-")
        ]),
        "wider": cohort_profile([
            item for item in manifest if item["private_id"].startswith("wider-")
        ]),
    }
    compare_float_tree(cohorts, expected_cohorts, "public cohort aggregates")

    validate_public_privacy(public, manifest)
    return {
        "private": private,
        "public": public,
        "private_sha256": private_sha,
        "public_sha256": public_sha,
        "rows": rows,
        "cells": cells,
        "decision": recomputed_decision,
        "binding": binding,
        "start": dict(start),
        "end": dict(end),
    }


def combined_analysis(
    primary: Mapping[str, Any], reverse: Mapping[str, Any], seed: int,
) -> dict[str, Any]:
    del primary, reverse, seed
    raise AuditError("reverse and combined analysis are unsupported")
    primary_rows = {
        (row["cpu_profile"], row["panel"], row["private_id"]): row
        for row in primary["rows"]
    }
    reverse_rows = {
        (row["cpu_profile"], row["panel"], row["private_id"]): row
        for row in reverse["rows"]
    }
    if set(primary_rows) != set(reverse_rows):
        raise AuditError("primary and reverse row identities differ")
    rng = random.Random(seed)
    ratios: dict[str, Any] = {}
    pooled_cells: dict[str, Any] = {}
    for profile in CPU_PROFILES:
        ratios[profile] = {}
        pooled_cells[profile] = {}
        for panel in PANELS:
            ratios[profile][panel] = {}
            pooled_cells[profile][panel] = {}
            keys = sorted(
                key for key in primary_rows
                if key[0] == profile and key[1] == panel
            )
            for stratum in STRATA:
                ids = (
                    None if stratum == "intention_to_treat"
                    else SELECTED_IDS if stratum == "selected34"
                    else COMPLEMENT_IDS
                )
                selected_keys = [
                    key for key in keys if ids is None or key[2] in ids
                ]
                if not selected_keys:
                    raise AuditError("combined bootstrap stratum is empty")
                ratio_cell = {
                    metric: (
                        reverse["cells"][profile][panel][stratum]["metrics"]
                        [metric]["point"]
                        / primary["cells"][profile][panel][stratum]["metrics"]
                        [metric]["point"]
                    )
                    for metric in METRICS
                }
                ratios[profile][panel][stratum] = ratio_cell
                metric_points = {
                    metric: geometric_mean([
                        math.sqrt(
                            float(primary_rows[key]["summary"]["metrics"][metric])
                            * float(reverse_rows[key]["summary"]["metrics"][metric])
                        )
                        for key in selected_keys
                    ])
                    for metric in METRICS
                }
                direction_a = geometric_mean([
                    math.sqrt(
                        float(primary_rows[key]["summary"]["background_direction_S"]["A_before_B"])
                        * float(
                            reverse_rows[key]["summary"]
                            ["background_direction_S"]["A_before_B"]
                        )
                    )
                    for key in selected_keys
                ])
                direction_b = geometric_mean([
                    math.sqrt(
                        float(primary_rows[key]["summary"]["background_direction_S"]["B_before_A"])
                        * float(
                            reverse_rows[key]["summary"]
                            ["background_direction_S"]["B_before_A"]
                        )
                    )
                    for key in selected_keys
                ])
                orientation_first = geometric_mean([
                    math.sqrt(
                        float(primary_rows[key]["summary"]["cycle_orientation_D"]["orders_0_3"])
                        * float(reverse_rows[key]["summary"]["cycle_orientation_D"]["orders_0_3"])
                    )
                    for key in selected_keys
                ])
                orientation_reverse = geometric_mean([
                    math.sqrt(
                        float(primary_rows[key]["summary"]["cycle_orientation_D"]["orders_4_7"])
                        * float(reverse_rows[key]["summary"]["cycle_orientation_D"]["orders_4_7"])
                    )
                    for key in selected_keys
                ])
                cell = {
                    "patterns": len(selected_keys),
                    "metrics": {
                        metric: {"point": metric_points[metric]}
                        for metric in METRICS
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
                samples = {metric: [] for metric in METRICS}
                count = len(selected_keys)
                for _ in range(BOOTSTRAP_REPLICATES):
                    logs = {metric: [] for metric in METRICS}
                    for _ in range(count):
                        key = selected_keys[rng.randrange(count)]
                        primary_quartets = primary_rows[key]["quartets"]
                        reverse_quartets = reverse_rows[key]["quartets"]
                        primary_draw = [
                            primary_quartets[rng.randrange(8)] for _ in range(8)
                        ]
                        reverse_draw = [
                            reverse_quartets[rng.randrange(8)] for _ in range(8)
                        ]
                        for metric in METRICS:
                            primary_median = median([
                                float(item["metrics"][metric])
                                for item in primary_draw
                            ])
                            reverse_median = median([
                                float(item["metrics"][metric])
                                for item in reverse_draw
                            ])
                            logs[metric].append(
                                math.log(math.sqrt(primary_median * reverse_median))
                            )
                    for metric in METRICS:
                        samples[metric].append(
                            math.exp(math.fsum(logs[metric]) / count)
                        )
                for metric in METRICS:
                    ordered = sorted(samples[metric])
                    cell["metrics"][metric]["confidence_interval_95"] = [
                        ordered[BOOTSTRAP_LOW_INDEX],
                        ordered[BOOTSTRAP_HIGH_INDEX],
                    ]
                pooled_cells[profile][panel][stratum] = cell
    decision_record = combined_decision(primary, reverse, pooled_cells, ratios)
    return {
        "method": {
            "per_id_pool": "sqrt(primary_run_median * reverse_run_median)",
            "cell": "equal-ID geometric mean",
            "bootstrap_replicates": BOOTSTRAP_REPLICATES,
            "resampling": (
                "same resampled IDs; independent complete-quartet resamples "
                "within primary and reverse; joint metric derivation"
            ),
            "percentile_indices": [BOOTSTRAP_LOW_INDEX, BOOTSTRAP_HIGH_INDEX],
        },
        "reverse_over_primary_point_ratios": ratios,
        "pooled_cells": pooled_cells,
        "decision": decision_record,
    }


def combined_decision(
    primary: Mapping[str, Any],
    reverse: Mapping[str, Any],
    pooled_cells: Mapping[str, Any],
    ratios: Mapping[str, Any],
) -> dict[str, Any]:
    del primary, reverse, pooled_cells, ratios
    raise AuditError("reverse and combined analysis are unsupported")
    primary_cell = primary["cells"]["auto"]["fre-count-default-threads"]
    reverse_cell = reverse["cells"]["auto"]["fre-count-default-threads"]
    pooled = pooled_cells["auto"]["fre-count-default-threads"]
    ratio = ratios["auto"]["fre-count-default-threads"]["intention_to_treat"]
    primary_itt = primary_cell["intention_to_treat"]
    reverse_itt = reverse_cell["intention_to_treat"]
    pooled_itt = pooled["intention_to_treat"]
    pooled_selected = pooled["selected34"]
    pooled_complement = pooled["complement10"]
    p_requirements = primary["decision"]["requirements"]
    r_requirements = reverse["decision"]["requirements"]
    within = lambda value, low, high: low <= float(value) <= high
    requirements = {
        "both_run_R1_points_at_least_1_03": all(
            cell["metrics"]["R1"]["point"] >= 1.03
            for cell in (primary_itt, reverse_itt)
        ),
        "pooled_R1_interval_wholly_above_1_03": (
            pooled_itt["metrics"]["R1"]["confidence_interval_95"][0] > 1.03
        ),
        "reverse_over_primary_R1_in_0_95_1_05": within(
            ratio["R1"], 0.95, 1.05
        ),
        "both_run_S_points_above_1": all(
            cell["metrics"]["S"]["point"] > 1.0
            for cell in (primary_itt, reverse_itt)
        ),
        "both_run_D_points_above_1": all(
            cell["metrics"]["D"]["point"] > 1.0
            for cell in (primary_itt, reverse_itt)
        ),
        "pooled_S_interval_wholly_above_1": (
            pooled_itt["metrics"]["S"]["confidence_interval_95"][0] > 1.0
        ),
        "pooled_D_interval_wholly_above_1": (
            pooled_itt["metrics"]["D"]["confidence_interval_95"][0] > 1.0
        ),
        "pooled_selected34_D_interval_wholly_above_1": (
            pooled_selected["metrics"]["D"]["confidence_interval_95"][0] > 1.0
        ),
        "pooled_C_point_in_0_97_1_03": within(
            pooled_itt["metrics"]["C"]["point"], 0.97, 1.03
        ),
        "pooled_complement10_S_point_in_0_97_1_03": within(
            pooled_complement["metrics"]["S"]["point"], 0.97, 1.03
        ),
        "pooled_complement10_D_point_in_0_97_1_03": within(
            pooled_complement["metrics"]["D"]["point"], 0.97, 1.03
        ),
        "reverse_over_primary_S_D_C_R1_in_0_95_1_05": all(
            within(ratio[metric], 0.95, 1.05)
            for metric in ("S", "D", "C", "R1")
        ),
        "each_run_direction_orientation_pass": all(
            requirements[name]
            for requirements in (p_requirements, r_requirements)
            for name in (
                "background_direction_ratio_in_0_95_1_05",
                "cycle_orientation_ratio_in_0_95_1_05",
            )
        ),
        "each_run_control_points_pass": all(
            requirements[name]
            for requirements in (p_requirements, r_requirements)
            for name in (
                "C_point_in_0_97_1_03",
                "complement10_S_point_in_0_97_1_03",
                "complement10_D_point_in_0_97_1_03",
            )
        ),
        "pooled_material_D_point_at_least_1_03": (
            pooled_itt["metrics"]["D"]["point"] >= 1.03
        ),
    }
    enablement_names = (
        "both_run_R1_points_at_least_1_03",
        "pooled_R1_interval_wholly_above_1_03",
        "reverse_over_primary_R1_in_0_95_1_05",
    )
    scanner_names = tuple(
        name for name in requirements
        if name not in enablement_names
        and name != "pooled_material_D_point_at_least_1_03"
    )
    enablement = all(requirements[name] for name in enablement_names)
    scanner_win = all(requirements[name] for name in scanner_names)
    material = requirements["pooled_material_D_point_at_least_1_03"]
    pooled_r1_high = pooled_itt["metrics"]["R1"]["confidence_interval_95"][1]
    either_run_below = any(
        cell["metrics"]["R1"]["point"] < 1.03
        for cell in (primary_itt, reverse_itt)
    )
    clear_no_go = pooled_r1_high < 1.03 or either_run_below
    classification = (
        "clear_no_go" if clear_no_go
        else "clear_go" if enablement
        else "inconclusive"
    )
    overall = (
        "go" if enablement and scanner_win and material
        else "no_go" if clear_no_go
        else "inconclusive"
    )
    return {
        "classification": classification,
        "enablement_gate": enablement,
        "scanner_win": scanner_win,
        "material_delta": material,
        "requirements": requirements,
        "failed_requirements": [
            name for name, passed in requirements.items() if not passed
        ],
        "overall": overall,
        "enable_new_scanner": overall == "go",
    }


def validate_primary_authorization_audit(
    path: Path,
    *,
    prereg_sha256: str,
    primary: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> int:
    del path, prereg_sha256, primary, confirmation
    raise AuditError("reverse authorization evidence is unsupported")
    audit = load_object(path, "primary authorization audit")
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
    registered_auditor_sha = primary["binding"]["runner"]["auditor_sha256"]
    expected_auditor = {
        "implementation": "independent_offline_v1",
        "sha256": registered_auditor_sha,
        "imports_runner_or_representative_harness": False,
    }
    compare_float_tree(
        auditor, expected_auditor, "primary authorization auditor"
    )
    compare_float_tree(
        audit.get("primary"),
        {"decision": primary["decision"], "cells": primary["cells"]},
        "primary authorization analysis",
    )
    expected_chronology = {
        "primary_start_unix_ns": primary["start"]["unix_ns"],
        "primary_end_unix_ns": primary["end"]["unix_ns"],
        "primary_authorization_audit_unix_ns": audit.get("audit_unix_ns"),
        "reverse_start_unix_ns": None,
        "reverse_end_unix_ns": None,
        "non_overlapping": None,
    }
    compare_float_tree(
        chronology, expected_chronology,
        "primary authorization chronology",
    )
    if (
        sha256_file(path) != confirmation.get("primary_audit_sha256")
        or audit.get("schema") != AUDIT_SCHEMA
        or audit.get("verified") is not True
        or confirmation.get("auditor_sha256") != registered_auditor_sha
        or audit.get("preregistration_sha256") != prereg_sha256
        or audit.get("primary_private_sha256")
        != primary["private_sha256"]
        or audit.get("primary_public_sha256") != primary["public_sha256"]
        or audit.get("reverse_private_sha256") is not None
        or audit.get("reverse_public_sha256") is not None
        or audit.get("reverse_row_confirmation_required") is not True
        or audit.get("reverse_row_confirmation_triggers")
        != primary["decision"]["reverse_row_confirmation_triggers"]
        or audit.get("reverse") is not None
        or audit.get("combined_analysis") is not None
        or not positive_int(audit.get("audit_unix_ns"))
        or audit.get("audit_unix_ns") != confirmation.get("primary_audit_unix_ns")
        or audit.get("audit_unix_ns") <= primary["end"]["unix_ns"]
    ):
        raise AuditError("primary authorization audit is invalid")
    return int(audit["audit_unix_ns"])


def build_audit(args: argparse.Namespace) -> dict[str, Any]:
    prereg, prereg_sha256 = validate_preregistration(args.preregistration)
    if sha256_file(Path(__file__)) != prereg["runner"]["auditor_sha256"]:
        raise AuditError("executing auditor differs from preregistration")
    external_probes = verify_external_bindings(args, prereg)
    primary = validate_result_pair(
        private_path=args.primary_private_result,
        public_path=args.primary_public_result,
        expected_role="primary",
        expected_traversal="canonical",
        prereg=prereg,
        prereg_sha256=prereg_sha256,
        external_probes=external_probes,
    )
    audit_unix_ns = time.time_ns()
    if audit_unix_ns <= primary["end"]["unix_ns"]:
        raise AuditError("audit timestamp does not follow audited workloads")
    chronology = {
        "primary_start_unix_ns": primary["start"]["unix_ns"],
        "primary_end_unix_ns": primary["end"]["unix_ns"],
        "primary_authorization_audit_unix_ns": audit_unix_ns,
        "reverse_start_unix_ns": None,
        "reverse_end_unix_ns": None,
        "non_overlapping": None,
    }
    return {
        "schema": AUDIT_SCHEMA,
        "verified": True,
        "auditor": {
            "implementation": "independent_offline_v1",
            "sha256": sha256_file(Path(__file__)),
            "imports_runner_or_representative_harness": False,
        },
        "audit_unix_ns": audit_unix_ns,
        "preregistration_sha256": prereg_sha256,
        "primary_private_sha256": primary["private_sha256"],
        "primary_public_sha256": primary["public_sha256"],
        "reverse_private_sha256": None,
        "reverse_public_sha256": None,
        "reverse_row_confirmation_required": primary["decision"][
            "reverse_row_confirmation_required"
        ],
        "reverse_row_confirmation_triggers": primary["decision"][
            "reverse_row_confirmation_triggers"
        ],
        "chronology": chronology,
        "primary": {
            "decision": primary["decision"],
            "cells": primary["cells"],
        },
        "reverse": None,
        "combined_analysis": None,
    }


def write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise AuditError("refusing to overwrite audit output")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, allow_nan=False)
            output.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def existing_path(value: str) -> Path:
    return Path(value).expanduser().resolve(strict=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    required = (
        "preregistration", "selection-manifest-input", "old-probe-private",
        "old-probe-public", "new-probe-private", "new-probe-public",
        "new-qualification-manifest", "new-qualification-archive",
        "primary-private-result", "primary-public-result",
    )
    for name in required:
        parser.add_argument(f"--{name}", type=existing_path, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    args.output = Path(args.output).expanduser().resolve()
    if args.output.exists():
        parser.error("audit output must be new")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        write_new_json(args.output, build_audit(args))
        return 0
    except Exception:
        print('{"error":"scanner_delta_audit_failed_safely"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

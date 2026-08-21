#!/usr/bin/env python3
"""Unit and mutation tests for the sealed scanner-delta control."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = load("scanner_delta_test_runner", "scanner_delta.py")
AUDITOR = load("scanner_delta_test_auditor", "audit_scanner_delta.py")

HEX64 = "1" * 64
HEX40 = "2" * 40


def capability_signature() -> dict:
    return {
        "platform": "Linux-6.8.0-aarch64-with-glibc2.39",
        "machine": "aarch64",
        "cpu_count": 64,
        "sve_vector_length_bytes": 16,
        "host_target_feature_bits": "0x700000000",
        "requested_target_feature_bits_by_profile": {
            "auto": "0x700000000",
            "asimd": "0x100000000",
            "sve": "0x200000000",
            "sve2": "0x600000000",
        },
        "effective_target_feature_bits_by_profile": {
            "auto": "0x700000000",
            "asimd": "0x100000000",
            "sve": "0x200000000",
            "sve2": "0x600000000",
        },
    }


def capability_attestation() -> dict:
    encoded = RUNNER.canonical_json_bytes(capability_signature())
    return {
        "schema": RUNNER.HOST_CAPABILITY_SCHEMA,
        "canonical_json_ascii": encoded.decode("ascii"),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def probe_capability_document() -> dict:
    signature = capability_signature()
    panels = {}
    for profile in RUNNER.CPU_PROFILES:
        for panel in RUNNER.PANELS:
            panels[f"{profile}/{panel}"] = {
                "all_selected": {
                    "receipt_classification": {
                        "requested_target_feature_bits": {
                            signature["requested_target_feature_bits_by_profile"][profile]: 1
                        },
                        "effective_target_feature_bits": {
                            signature["effective_target_feature_bits_by_profile"][profile]: 1
                        },
                        "host_target_feature_bits": {
                            signature["host_target_feature_bits"]: 1
                        },
                    }
                }
            }
    return {
        "host": {
            "platform": signature["platform"],
            "machine": signature["machine"],
            "cpu_count": signature["cpu_count"],
            "python": "3.14",
            "rustc": "rustc 1.96.0",
            "cargo": "cargo 1.96.0",
            "sve_vector_length_bytes": 16,
        },
        "panels": panels,
        "target_validation_matrix": {
            "qualified": True,
            "global_qualified_host_feature_bits": [
                signature["host_target_feature_bits"]
            ],
        },
    }


def prereg_document() -> dict:
    return {
        "schema": RUNNER.PREREG_SCHEMA,
        "sealed_before_timing": True,
        "protocol": RUNNER.protocol_record(),
        "identities": {
            role: RUNNER.expected_identity_record(role)
            for role in ("old", "new")
        },
        "qualification_probes": {
            role: {
                "private_sha256": RUNNER.expected_probe_hashes(role)[0],
                "public_sha256": RUNNER.expected_probe_hashes(role)[1],
                "stock_binary_sha256": HEX64,
                "stock_source_commit": HEX40,
                "stock_source_tree": "3" * 40,
            }
            for role in ("old", "new")
        },
        "qualification_artifacts": {
            "new_manifest_sha256": RUNNER.NEW_QUALIFICATION_MANIFEST_SHA256,
            "new_archive_sha256": RUNNER.NEW_QUALIFICATION_ARCHIVE_SHA256,
        },
        "inputs": {
            "selection_transport_sha256": HEX64,
            "ripgrep_corpus_commit": HEX40,
            "ripgrep_corpus_tree": "3" * 40,
            "fre_corpus_commit": "4" * 40,
            "fre_corpus_tree": "5" * 40,
        },
        "runner": {
            "source_commit": HEX40,
            "source_tree": "3" * 40,
            "scanner_delta_sha256": HEX64,
            "auditor_sha256": "6" * 64,
        },
        "host_capability_attestation": capability_attestation(),
    }


def external_probe_records() -> dict:
    result = {}
    for role in ("old", "new"):
        identity = RUNNER.expected_identity_record(role)
        result[role] = {
            "candidate_source": {
                "commit": identity["source_commit"],
                "tree": identity["source_tree"],
                "clean": True,
            },
            "candidate_binary": {
                "sha256": identity["binary_sha256"],
                "version": f"ripgrep test (rev {identity['source_commit'][:10]})",
            },
            "fre_dependency": {
                "source": "https://github.com/danluu/fre.git",
                "manifest_revision": identity["fre_commit"],
                "locked_revision": identity["fre_commit"],
                "locked_package_count": 4,
                "cargo_toml_sha256": "7" * 64,
                "cargo_lock_sha256": "8" * 64,
            },
            "stock_source": {
                "commit": HEX40, "tree": "3" * 40, "clean": True,
            },
            "stock_binary": {"sha256": HEX64, "version": "stock"},
            "host_capability_signature": capability_signature(),
            "selected_or_stock_disposition": {"sealed": True},
            "target_validation_matrix": {"qualified": True},
            "forced_midscan_gate_verification": {
                "summary_sha256": "a" * 64,
                "profiles": 4,
                "all_passed": True,
            },
            "exact_teddy_v2_gate_verification": {
                "summary_sha256": "b" * 64,
                "profiles": 4,
                "all_passed": True,
            },
        }
    return result


def input_binding_document(prereg: dict, prereg_sha256: str) -> dict:
    external = external_probe_records()
    identities = {}
    qualification = {}
    for role in ("old", "new"):
        identity = RUNNER.expected_identity_record(role)
        identities[role] = {
            "source": external[role]["candidate_source"],
            "binary": external[role]["candidate_binary"],
            "fre_dependency": external[role]["fre_dependency"],
            "fre_source": {
                "commit": identity["fre_commit"],
                "tree": identity["fre_tree"],
                "clean": True,
            },
            "optimizer_version": identity["optimizer_version"],
        }
        registered = prereg["qualification_probes"][role]
        qualification[role] = {
            "private_sha256": registered["private_sha256"],
            "public_sha256": registered["public_sha256"],
            "optimizer_version": identity["optimizer_version"],
            "optimizer_receipts_authenticated": 408,
            "stock_reference": {
                "binary_sha256": registered["stock_binary_sha256"],
                "source_commit": registered["stock_source_commit"],
                "source_tree": registered["stock_source_tree"],
                "timed_in_scanner_delta": False,
            },
            "selected_or_stock_disposition": external[role]["selected_or_stock_disposition"],
            "target_validation_matrix": external[role]["target_validation_matrix"],
            "host_capability_signature": capability_signature(),
            "forced_midscan_gate_verification": external[role][
                "forced_midscan_gate_verification"
            ],
            "exact_teddy_v2_gate_verification": external[role][
                "exact_teddy_v2_gate_verification"
            ],
            "untimed_reference_correctness_verified": True,
        }
    materialized = {}
    sources = {}
    for name in ("ripgrep", "fre"):
        commit = prereg["inputs"][f"{name}_corpus_commit"]
        tree = prereg["inputs"][f"{name}_corpus_tree"]
        sources[name] = {
            "mirror_clean": True,
            "materialized_commit": commit,
            "materialized_tree": tree,
        }
        materialized[name] = {
            "commit": commit,
            "tree": tree,
            "archive_reported_file_count": 2,
            "archive_reported_total_file_bytes": 10,
            "entry_count": 3,
            "directory_count": 1,
            "regular_file_count": 2,
            "symlink_count": 0,
            "total_regular_file_bytes": 10,
            "content_tree_sha256": "9" * 64,
        }
    return {
        "preregistration_sha256": prereg_sha256,
        "runner": {
            "source": {
                "commit": prereg["runner"]["source_commit"],
                "tree": prereg["runner"]["source_tree"],
                "clean": True,
            },
            "scanner_delta_sha256": prereg["runner"]["scanner_delta_sha256"],
            "auditor_sha256": prereg["runner"]["auditor_sha256"],
        },
        "host": {
            "capability_attestation": prereg["host_capability_attestation"],
            "current_capability_signature": capability_signature(),
        },
        "identities": identities,
        "qualification_probes": qualification,
        "qualification_artifacts": prereg["qualification_artifacts"],
        "selection": {
            "transport_sha256": prereg["inputs"]["selection_transport_sha256"],
            "fixed44_manifest_sha256": RUNNER.FIXED44_MANIFEST_SHA256,
            "selected34_manifest_sha256": RUNNER.SELECTED34_MANIFEST_SHA256,
            "selected34_ids_sha256": RUNNER.SELECTED34_IDS_SHA256,
            "complement10_manifest_sha256": RUNNER.COMPLEMENT10_MANIFEST_SHA256,
            "complement10_ids_sha256": RUNNER.COMPLEMENT10_IDS_SHA256,
        },
        "corpus_sources": sources,
        "materialized_corpora": materialized,
    }


def output_record(data: bytes = b"same\n") -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def arm(elapsed: int | None = None) -> dict:
    result = {
        "timed_out": False,
        "status": 1,
        "stdout": output_record(),
        "stderr": output_record(b""),
        "receipt": None,
        "receipt_parse_error": False,
        "unexpected_temporary_artifacts": 0,
    }
    if elapsed is not None:
        result = {
            "elapsed_ns": elapsed,
            "user_ns": elapsed // 2,
            "system_ns": elapsed // 4,
            **result,
        }
    return result


def comparison() -> dict:
    return {
        "status": 1,
        "stderr_sha256": output_record(b"")["sha256"],
        "semantic_stdout_sha256": output_record()["sha256"],
    }


def quartet(order_index: int, *, measured: bool = True) -> dict:
    elapsed = {"A": 120, "B": 100, "C": 110, "D": 90}
    arms = {
        name: arm(elapsed[name] if measured else None)
        for name in ("A", "B", "C", "D")
    }
    result = {
        "order_index": order_index,
        "order": list(RUNNER.ORDERS[order_index]),
        "normalization": [],
        "comparison_records": {
            name: comparison() for name in ("A", "B", "C", "D")
        },
        "arms": arms,
        "closure_verified": True,
    }
    if measured:
        result["metrics"] = RUNNER.metric_values(elapsed)
    return result


def aggregate_row(private_id: str, value: float, ordinal: int = 0) -> dict:
    quartets = []
    for index in range(8):
        item = quartet(index)
        item["metrics"] = {metric: value for metric in RUNNER.METRICS}
        quartets.append(item)
    return {
        "canonical_row_ordinal": ordinal,
        "private_id": private_id,
        "cpu_profile": "auto",
        "panel": "fre-count-default-threads",
        "quartets": quartets,
        "summary": RUNNER.row_summary(quartets),
    }


class PreregistrationTests(unittest.TestCase):
    def write_prereg(self, root: Path, value: dict, *, canonical: bool = True) -> Path:
        path = root / "prereg.json"
        data = (
            RUNNER.canonical_json_bytes(value)
            if canonical else json.dumps(value, indent=2).encode()
        )
        path.write_bytes(data)
        return path

    def test_canonical_preregistration_and_seed_are_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            path = self.write_prereg(Path(text), prereg_document())
            expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            loaded, digest = RUNNER.load_preregistration(path)
        self.assertEqual(prereg_document(), loaded)
        self.assertEqual(expected_digest, digest)
        self.assertEqual(
            {
                "sha256": (
                    "1caba9b4acf7e92d40917bfafce52b33867be78078b4c4a748e3216b67629892"
                ),
                "u64_big_endian_first8": 2065931447540640045,
            },
            RUNNER.bootstrap_seed_record(loaded),
        )
        self.assertEqual(
            RUNNER.bootstrap_seed_record(loaded), AUDITOR.bootstrap_seed(loaded)
        )

    def test_preregistration_mutations_fail_closed(self) -> None:
        mutations = []
        base = prereg_document()
        changed = copy.deepcopy(base)
        changed["protocol"]["orders"][0].reverse()
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["identities"]["old"]["binary_sha256"] = "a" * 64
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["qualification_probes"]["new"]["private_sha256"] = "a" * 64
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["qualification_artifacts"]["new_archive_sha256"] = "a" * 64
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["inputs"]["ripgrep_corpus_commit"] = "a" * 64
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["unexpected"] = True
        mutations.append(changed)
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            for index, value in enumerate(mutations):
                path = root / f"mutation-{index}.json"
                path.write_bytes(RUNNER.canonical_json_bytes(value))
                with self.assertRaises(RUNNER.ScannerDeltaError):
                    RUNNER.load_preregistration(path)
            noncanonical = root / "noncanonical.json"
            noncanonical.write_text(json.dumps(base, indent=2))
            with self.assertRaises(RUNNER.ScannerDeltaError):
                RUNNER.load_preregistration(noncanonical)

    def test_auditor_independently_accepts_same_preregistration(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            path = self.write_prereg(Path(text), prereg_document())
            loaded, _ = AUDITOR.validate_preregistration(path)
        self.assertEqual(prereg_document(), loaded)
        self.assertNotIn("scanner_delta_test_runner", AUDITOR.__dict__.values())

    def test_host_attestation_mutations_fail_closed(self) -> None:
        attestation = capability_attestation()
        self.assertEqual(
            capability_signature(),
            RUNNER.validate_capability_attestation(attestation)[1],
        )
        self.assertEqual(
            capability_signature(),
            AUDITOR.validate_capability_attestation(attestation)[1],
        )
        for mutate in ("bits", "bytes", "hash", "extra"):
            changed = copy.deepcopy(attestation)
            if mutate == "bits":
                signature = json.loads(changed["canonical_json_ascii"])
                signature["effective_target_feature_bits_by_profile"]["sve2"] = (
                    "0x200000000"
                )
                changed["canonical_json_ascii"] = RUNNER.canonical_json_bytes(
                    signature
                ).decode("ascii")
                changed["sha256"] = hashlib.sha256(
                    changed["canonical_json_ascii"].encode("ascii")
                ).hexdigest()
            elif mutate == "bytes":
                changed["canonical_json_ascii"] += " "
            elif mutate == "hash":
                changed["sha256"] = "a" * 64
            else:
                changed["extra"] = True
            with self.assertRaises(RUNNER.ScannerDeltaError):
                RUNNER.validate_capability_attestation(changed)
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_capability_attestation(changed)

    def test_probe_capability_evidence_is_reconstructed(self) -> None:
        probe = probe_capability_document()
        self.assertEqual(
            capability_signature(), RUNNER.probe_capability_signature(probe)
        )
        self.assertEqual(
            capability_signature(), AUDITOR.probe_capability_signature(probe)
        )
        changed = copy.deepcopy(probe)
        cell = changed["panels"]["sve2/fre-count-thread1"]["all_selected"]
        cell["receipt_classification"]["effective_target_feature_bits"] = {
            "0x200000000": 1
        }
        with self.assertRaises(RUNNER.ScannerDeltaError):
            RUNNER.probe_capability_signature(changed)
        with self.assertRaises(AUDITOR.AuditError):
            AUDITOR.probe_capability_signature(changed)


class MetricAndScheduleTests(unittest.TestCase):
    def test_metric_formulas_and_delta_identity(self) -> None:
        result = RUNNER.metric_values({"A": 120, "B": 100, "C": 110, "D": 90})
        self.assertAlmostEqual(1.2, result["S"])
        self.assertAlmostEqual(110 / 90, result["C"])
        self.assertAlmostEqual((90 / 100) / (110 / 120), result["D"])
        self.assertAlmostEqual(result["S"] / result["C"], result["D"])
        self.assertAlmostEqual(110 / 120, result["R0"])
        self.assertAlmostEqual(90 / 100, result["R1"])

    def test_orders_are_balanced_in_direction_and_orientation(self) -> None:
        self.assertEqual(8, len(set(RUNNER.ORDERS)))
        self.assertTrue(all(set(order) == {"A", "B", "C", "D"} for order in RUNNER.ORDERS))
        self.assertEqual(
            4,
            sum(order.index("A") < order.index("B") for order in RUNNER.ORDERS),
        )
        for ordinal in range(8):
            self.assertEqual(
                [(ordinal - 2) % 8, (ordinal - 1) % 8],
                [(ordinal - 2 + index) % 8 for index in range(2)],
            )
            self.assertEqual(
                list(range(8)), sorted((ordinal + index) % 8 for index in range(8))
            )

    def test_row_summary_uses_only_predeclared_splits(self) -> None:
        quartets = [quartet(index) for index in range(8)]
        summary = RUNNER.row_summary(quartets)
        self.assertEqual(set(RUNNER.METRICS), set(summary["metrics"]))
        self.assertEqual(
            {"A_before_B", "B_before_A"},
            set(summary["background_direction_S"]),
        )
        self.assertEqual(
            {"orders_0_3", "orders_4_7"},
            set(summary["cycle_orientation_D"]),
        )

    def test_auditor_rejects_quartet_mutations(self) -> None:
        valid = quartet(0)
        AUDITOR.validate_quartet(
            valid, measured=True, expected_order_index=0,
            panel="fre-count-thread1", label="valid",
        )
        mutations = []
        changed = copy.deepcopy(valid)
        changed["order"] = list(RUNNER.ORDERS[1])
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["B"]["status"] = 2
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["C"]["unexpected_temporary_artifacts"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["C"]["unexpected_temporary_artifacts"] = False
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["comparison_records"]["D"]["semantic_stdout_sha256"] = "a" * 64
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["metrics"]["D"] *= 1.1
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["A"]["receipt"] = {}
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["A"]["status"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["comparison_records"]["A"]["status"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["order_index"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["arms"]["A"]["stdout"]["bytes"] = True
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_quartet(
                    changed, measured=True, expected_order_index=0,
                    panel="fre-count-thread1", label="mutated",
                )

    def test_warmup_schema_excludes_timing(self) -> None:
        valid = quartet(6, measured=False)
        AUDITOR.validate_quartet(
            valid, measured=False, expected_order_index=6,
            panel="fre-count-thread1", label="warmup",
        )
        changed = copy.deepcopy(valid)
        changed["arms"]["A"]["elapsed_ns"] = 1
        with self.assertRaises(AUDITOR.AuditError):
            AUDITOR.validate_quartet(
                changed, measured=False, expected_order_index=6,
                panel="fre-count-thread1", label="warmup",
            )


class RunnerIsolationTests(unittest.TestCase):
    def raw_result(self, elapsed: int) -> dict:
        return {
            "elapsed_ns": elapsed,
            "user_ns": elapsed // 2,
            "system_ns": elapsed // 4,
            "timed_out": False,
            "status": 1,
            "stdout": output_record(),
            "stderr": output_record(b""),
            "stdout_raw": b"same\n",
            "stderr_raw": b"",
            "receipt": None,
            "receipt_parse_error": False,
            "unexpected_temporary_artifacts": 0,
        }

    def test_runner_closure_rejects_bool_status_and_count(self) -> None:
        results = {
            arm_name: self.raw_result(100)
            for arm_name in ("A", "B", "C", "D")
        }
        comparisons = {
            arm_name: comparison()
            for arm_name in ("A", "B", "C", "D")
        }
        RUNNER.validate_quartet_closure(results, comparisons, "literal")
        for field, value in (
            ("status", True),
            ("unexpected_temporary_artifacts", False),
        ):
            changed = copy.deepcopy(results)
            changed["C"][field] = value
            with self.assertRaises(RUNNER.ScannerDeltaError):
                RUNNER.validate_quartet_closure(
                    changed, comparisons, "literal"
                )

    def test_quartet_runs_only_registered_binary_policy_arms(self) -> None:
        calls = []
        elapsed = iter((120, 100, 90, 110))

        def fake_run_once(**kwargs):
            calls.append(kwargs)
            return self.raw_result(next(elapsed))

        case = RUNNER.representative.QueryCase(
            "oot-0001", "cohort", "needle", 1, None, {}
        )
        panel = RUNNER.representative.Panel(
            "fre-count-thread1", Path("/tmp/corpus"), "literal", None, True, 1
        )
        with mock.patch.object(RUNNER.representative, "run_once", fake_run_once):
            result = RUNNER.run_quartet(
                case=case, panel=panel, order_index=0,
                binaries={"old": Path("/old"), "new": Path("/new")},
                cwd=Path("/neutral"), cpu_profile="auto", include_timing=True,
            )
        self.assertEqual(list(RUNNER.ORDERS[0]), [
            next(name for name, record in RUNNER.ARM_RECORD.items() if (
                record["binary_identity"] == ("old" if call["binary"] == Path("/old") else "new")
                and record["background"] == call["background"]
            ))
            for call in calls
        ])
        self.assertEqual(
            [RUNNER.POLICY, RUNNER.POLICY, None, None],
            [call["exact_teddy_policy_v2"] for call in calls],
        )
        self.assertTrue(all(call["capture_receipt"] is False for call in calls))
        self.assertEqual(set(RUNNER.METRICS), set(result["metrics"]))

    def test_bound_old_optimizer_exception_is_copy_only(self) -> None:
        receipt = {
            "schema_version": 2,
            "optimizer_version": 25,
            "exact_finite_selected_end_teddy_policy": "force_structurally_eligible",
        }
        original = {"compile_receipt_v2": receipt}
        normalized, count = RUNNER.normalize_bound_probe_optimizer(
            original, role="old", expected=25
        )
        self.assertEqual(1, count)
        self.assertEqual(25, original["compile_receipt_v2"]["optimizer_version"])
        self.assertEqual(26, normalized["compile_receipt_v2"]["optimizer_version"])
        with self.assertRaises(RUNNER.ScannerDeltaError):
            RUNNER.normalize_bound_probe_optimizer(
                original, role="new", expected=26
            )


class ProvenanceAndFailureTests(unittest.TestCase):
    def test_materialized_corpus_digest_detects_post_run_mutation(self) -> None:
        source = {
            "commit": HEX40,
            "tree": "3" * 40,
            "file_count": 2,
            "total_file_bytes": 9,
        }
        with tempfile.TemporaryDirectory() as text:
            root = Path(text) / "corpus-ripgrep"
            root.mkdir()
            (root / "a.txt").write_text("alpha")
            nested = root / "nested"
            nested.mkdir()
            (nested / "b.txt").write_text("beta")
            before = RUNNER.materialized_corpus_record(root, source, "test")
            (nested / "b.txt").write_text("BETA")
            after = RUNNER.materialized_corpus_record(root, source, "test")
        self.assertNotEqual(
            before["content_tree_sha256"], after["content_tree_sha256"]
        )
        self.assertEqual(before["total_regular_file_bytes"], after["total_regular_file_bytes"])

    def test_checkpoint_is_mode_0600_and_retains_completed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            path = Path(text) / "checkpoint.jsonl"
            journal = RUNNER.PrivateCheckpointJournal(
                path, campaign_role="primary", row_traversal="canonical"
            )
            journal.stage("timing_rows")
            journal.completed_row({"canonical_row_ordinal": 0, "status": "closed"})
            journal.terminal_failure(RUNNER.ScannerDeltaError("secret path"))
            journal.close()
            raw = path.read_text()
            lines = [json.loads(line) for line in raw.splitlines()]
            mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(0o600, mode)
        self.assertEqual("completed_row", lines[-2]["event"])
        self.assertEqual(1, lines[-1]["completed_rows"])
        self.assertEqual("ScannerDeltaError", lines[-1]["reason"])
        self.assertNotIn("secret path", raw)

    def test_terminal_failure_writes_no_public_success(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            args = SimpleNamespace(
                private_checkpoint_output=root / "checkpoint.jsonl",
                private_output=root / "private.json",
                public_output=root / "public.json",
                campaign_role="primary",
                row_traversal="canonical",
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(RUNNER, "parse_benchmark_args", return_value=args),
                mock.patch.object(
                    RUNNER, "run_scanner_delta",
                    side_effect=RUNNER.ScannerDeltaError("failed"),
                ),
                mock.patch("sys.stderr", stderr),
            ):
                status = RUNNER.main(["benchmark-scanner-delta"])
            events = [
                json.loads(line)
                for line in args.private_checkpoint_output.read_text().splitlines()
            ]
        self.assertEqual(2, status)
        self.assertEqual("terminal_failure", events[-1]["event"])
        self.assertFalse(args.public_output.exists())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_closed_input_binding_rejects_nested_mutations(self) -> None:
        prereg = prereg_document()
        prereg_sha = "a" * 64
        external = external_probe_records()
        valid = input_binding_document(prereg, prereg_sha)
        AUDITOR.validate_input_binding(valid, prereg, prereg_sha, external)
        mutations = []
        changed = copy.deepcopy(valid)
        changed["identities"]["new"]["binary"]["extra"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["qualification_probes"]["old"]["target_validation_matrix"] = {
            "qualified": False
        }
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["materialized_corpora"]["fre"]["content_tree_sha256"] = "bad"
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["host"]["current_capability_signature"]["cpu_count"] = 63
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["corpus_sources"]["ripgrep"]["extra"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["qualification_probes"]["old"]["stock_reference"][
            "timed_in_scanner_delta"
        ] = 0
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_input_binding(
                    changed, prereg, prereg_sha, external
                )

    def test_public_privacy_rejects_pattern_query_and_path_leaks(self) -> None:
        manifest = [{"private_id": "oot-0001", "pattern": "private-needle"}]
        AUDITOR.validate_public_privacy({"aggregate": 1}, manifest)
        for leaked in (
            {"aggregate": "private-needle"},
            {"private_id": "redacted"},
            {"oot-0001": 1},
            {"private-needle": 1},
            {"note": "/tmp/private-corpus"},
            {"command": ["--", "redacted", "corpus"]},
            {"command": ["--threads=1", "redacted", "corpus"]},
        ):
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_public_privacy(leaked, manifest)

    def test_cohort_profile_is_independently_recomputed(self) -> None:
        cases = [
            RUNNER.representative.QueryCase(
                "oot-0001", "cohort", "^(foo|bar).*$", 3, ".rs",
                {"case": "ignore_case", "multiline": True},
                "code", "rust",
            ),
            RUNNER.representative.QueryCase(
                "wider-0001", "cohort", "literal", 2, None,
                {"matcher_mode": "fixed_strings", "unicode": False},
                None, None,
            ),
        ]
        manifest = RUNNER.representative.case_manifest(cases)
        self.assertEqual(
            RUNNER.representative.cohort_profile(cases),
            AUDITOR.cohort_profile(manifest),
        )

    def test_cli_boundaries_hide_structural_tracebacks(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(AUDITOR, "parse_args", side_effect=TypeError("bad")),
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(2, AUDITOR.main([]))
        self.assertEqual('{"error":"scanner_delta_audit_failed_safely"}\n', stderr.getvalue())

    def test_auditor_self_hash_is_checked_before_artifacts(self) -> None:
        prereg = prereg_document()
        prereg["runner"]["auditor_sha256"] = "f" * 64
        args = SimpleNamespace(preregistration=Path("unused"))
        with (
            mock.patch.object(
                AUDITOR, "validate_preregistration",
                return_value=(prereg, "e" * 64),
            ),
            mock.patch.object(AUDITOR, "verify_external_bindings") as external,
        ):
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.build_audit(args)
        external.assert_not_called()

    def test_reverse_authorization_requires_exact_audit_envelope(self) -> None:
        prereg = prereg_document()
        prereg_sha = "a" * 64
        decision = {
            "reverse_row_confirmation_required": True,
            "reverse_row_confirmation_triggers": ["gate"],
        }
        cells = {"sealed": True}
        workload = {
            "start": {"unix_ns": 100},
            "end": {"unix_ns": 150},
        }
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            private_path = root / "primary.private.json"
            public_path = root / "primary.public.json"
            audit_path = root / "primary.audit.json"
            private_path.write_text("private\n")
            private_sha = hashlib.sha256(private_path.read_bytes()).hexdigest()
            public = {
                "schema": RUNNER.PUBLIC_SCHEMA,
                "campaign_role": "primary",
                "row_traversal": "canonical",
                "preregistration_sha256": prereg_sha,
                "private_result_sha256": private_sha,
                "decision": decision,
                "cells": cells,
                "workload_environment": workload,
            }
            public_path.write_text(json.dumps(public) + "\n")
            public_sha = hashlib.sha256(public_path.read_bytes()).hexdigest()
            audit = {
                "schema": RUNNER.AUDIT_SCHEMA,
                "verified": True,
                "auditor": {
                    "implementation": "independent_offline_v1",
                    "sha256": prereg["runner"]["auditor_sha256"],
                    "imports_runner_or_representative_harness": False,
                },
                "audit_unix_ns": 200,
                "preregistration_sha256": prereg_sha,
                "primary_private_sha256": private_sha,
                "primary_public_sha256": public_sha,
                "reverse_private_sha256": None,
                "reverse_public_sha256": None,
                "reverse_row_confirmation_required": True,
                "reverse_row_confirmation_triggers": ["gate"],
                "chronology": {
                    "primary_start_unix_ns": 100,
                    "primary_end_unix_ns": 150,
                    "primary_authorization_audit_unix_ns": 200,
                    "reverse_start_unix_ns": None,
                    "reverse_end_unix_ns": None,
                    "non_overlapping": None,
                },
                "primary": {"decision": decision, "cells": cells},
                "reverse": None,
                "combined_analysis": None,
            }
            audit_path.write_text(json.dumps(audit) + "\n")
            args = SimpleNamespace(
                campaign_role="reverse-row-confirmation",
                row_traversal="reverse-canonical",
                primary_private_result=private_path,
                primary_public_result=public_path,
                primary_audit_result=audit_path,
            )
            authorization = RUNNER.validate_primary_authorization(
                args, prereg, prereg_sha
            )
            self.assertEqual(200, authorization["primary_audit_unix_ns"])
            primary_record = {
                "private_sha256": private_sha,
                "public_sha256": public_sha,
                "decision": decision,
                "cells": cells,
                "start": {"unix_ns": 100},
                "end": {"unix_ns": 150},
                "binding": input_binding_document(prereg, prereg_sha),
            }
            confirmation = copy.deepcopy(authorization)
            self.assertEqual(
                200,
                AUDITOR.validate_primary_authorization_audit(
                    audit_path,
                    prereg_sha256=prereg_sha,
                    primary=primary_record,
                    confirmation=confirmation,
                ),
            )
            audit["extra"] = True
            audit_path.write_text(json.dumps(audit) + "\n")
            with self.assertRaises(RUNNER.ScannerDeltaError):
                RUNNER.validate_primary_authorization(args, prereg, prereg_sha)


class FullMatrixMutationTests(unittest.TestCase):
    def manifest(self) -> list[dict]:
        # Preserve an interleaved, deterministic order so the row-ordinal
        # checks exercise manifest order rather than sorted-ID assumptions.
        ids = sorted(AUDITOR.SELECTED_IDS | AUDITOR.COMPLEMENT_IDS)
        return [
            {
                "private_id": private_id,
                "cohort": (
                    "frozen-oot-84" if private_id.startswith("oot-")
                    else "frozen-unique-sample-128"
                ),
                "pattern": f"synthetic-pattern-{index}",
                "occurrence_weight": index + 1,
                "suffix": None,
                "semantics": {},
                "target_kind": None,
                "extension_class": None,
            }
            for index, private_id in enumerate(ids)
        ]

    def rows(self, manifest: list[dict]) -> list[dict]:
        by_id = {row["private_id"]: row for row in manifest}
        rows = []
        for ordinal, profile, panel, private_id in AUDITOR.expected_row_specs(manifest):
            case = by_id[private_id]
            measured = [quartet((ordinal + index) % 8) for index in range(8)]
            rows.append({
                "canonical_row_ordinal": ordinal,
                **case,
                "query_argv_after_binary": AUDITOR.expected_query_argv(
                    case,
                    panel,
                    "/tmp/scanner-delta/corpus-ripgrep"
                    if panel == "ripgrep-default-output"
                    else "/tmp/scanner-delta/corpus-fre",
                )[0],
                "cpu_profile": profile,
                "panel": panel,
                "warmups": [
                    quartet((ordinal - 2 + index) % 8, measured=False)
                    for index in range(2)
                ],
                "quartets": measured,
                "summary": RUNNER.row_summary(measured),
            })
        return rows

    def digest_patches(self, manifest: list[dict]):
        selected = [row for row in manifest if row["private_id"] in AUDITOR.SELECTED_IDS]
        complement = [row for row in manifest if row["private_id"] in AUDITOR.COMPLEMENT_IDS]
        return (
            mock.patch.object(AUDITOR, "FIXED44_MANIFEST_SHA256", AUDITOR.digest_json(manifest)),
            mock.patch.object(AUDITOR, "SELECTED34_MANIFEST_SHA256", AUDITOR.digest_json(selected)),
            mock.patch.object(
                AUDITOR, "COMPLEMENT10_MANIFEST_SHA256",
                AUDITOR.digest_json(complement),
            ),
        )

    def test_full_408_row_matrix_and_reverse_traversal(self) -> None:
        manifest = self.manifest()
        rows = self.rows(manifest)
        patches = self.digest_patches(manifest)
        with patches[0], patches[1], patches[2]:
            validated_manifest, by_id = AUDITOR.validate_manifest(manifest)
            canonical = AUDITOR.validate_rows(
                rows, traversal="canonical", manifest=validated_manifest,
                by_id=by_id,
            )
            reverse = AUDITOR.validate_rows(
                list(reversed(rows)), traversal="reverse-canonical",
                manifest=validated_manifest, by_id=by_id,
            )
        self.assertEqual(408, len(canonical))
        self.assertEqual(407, reverse[0]["canonical_row_ordinal"])

    def test_full_matrix_rejects_row_and_warmup_mutations(self) -> None:
        manifest = self.manifest()
        rows = self.rows(manifest)
        patches = self.digest_patches(manifest)
        with patches[0], patches[1], patches[2]:
            validated_manifest, by_id = AUDITOR.validate_manifest(manifest)
            changed = copy.deepcopy(rows)
            changed[100]["canonical_row_ordinal"] += 1
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical", manifest=validated_manifest,
                    by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            changed[0]["warmups"][0]["order_index"] = 0
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical", manifest=validated_manifest,
                    by_id=by_id,
                )
            changed = list(reversed(copy.deepcopy(rows)))
            changed[0], changed[1] = changed[1], changed[0]
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="reverse-canonical",
                    manifest=validated_manifest, by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            changed[0]["query_argv_after_binary"].insert(0, "--threads=99")
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical",
                    manifest=validated_manifest, by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            changed[14]["query_argv_after_binary"][-1] = (
                "/tmp/scanner-delta/other-corpus"
            )
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical",
                    manifest=validated_manifest, by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            changed[14]["query_argv_after_binary"][-1] = (
                "/tmp/different-parent/corpus-fre"
            )
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical",
                    manifest=validated_manifest, by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            changed[0]["canonical_row_ordinal"] = False
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical",
                    manifest=validated_manifest, by_id=by_id,
                )
            changed = copy.deepcopy(rows)
            self.assertEqual(1, changed[0]["occurrence_weight"])
            changed[0]["occurrence_weight"] = True
            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.validate_rows(
                    changed, traversal="canonical",
                    manifest=validated_manifest, by_id=by_id,
                )

    def test_full_result_pair_closes_public_schema_and_cohorts(self) -> None:
        manifest = self.manifest()
        rows = self.rows(manifest)
        selected = [
            row for row in manifest if row["private_id"] in AUDITOR.SELECTED_IDS
        ]
        complement = [
            row for row in manifest if row["private_id"] in AUDITOR.COMPLEMENT_IDS
        ]
        fixed_digest = AUDITOR.digest_json(manifest)
        selected_digest = AUDITOR.digest_json(selected)
        complement_digest = AUDITOR.digest_json(complement)
        prereg = prereg_document()
        prereg_sha = "a" * 64
        external = external_probe_records()
        binding = input_binding_document(prereg, prereg_sha)
        binding["selection"].update({
            "fixed44_manifest_sha256": fixed_digest,
            "selected34_manifest_sha256": selected_digest,
            "complement10_manifest_sha256": complement_digest,
        })
        workload = {
            "start": {
                "utc": "2026-08-21T00:00:00+00:00",
                "unix_ns": 100,
                "load_average_1m_5m_15m": [0.1, 0.2, 0.3],
            },
            "end": {
                "utc": "2026-08-21T00:01:00+00:00",
                "unix_ns": 200,
                "load_average_1m_5m_15m": [0.1, 0.2, 0.3],
            },
        }
        patches = (
            mock.patch.object(AUDITOR, "FIXED44_MANIFEST_SHA256", fixed_digest),
            mock.patch.object(AUDITOR, "SELECTED34_MANIFEST_SHA256", selected_digest),
            mock.patch.object(AUDITOR, "COMPLEMENT10_MANIFEST_SHA256", complement_digest),
            mock.patch.object(AUDITOR, "BOOTSTRAP_REPLICATES", 2),
            mock.patch.object(AUDITOR, "BOOTSTRAP_LOW_INDEX", 0),
            mock.patch.object(AUDITOR, "BOOTSTRAP_HIGH_INDEX", 1),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            cells = AUDITOR.aggregate_rows(rows, 1234)
            decision = AUDITOR.decision(cells)
            private = {
                "schema": AUDITOR.PRIVATE_SCHEMA,
                "contains_raw_patterns": True,
                "local_only_do_not_commit": True,
                "campaign_role": "primary",
                "row_traversal": "canonical",
                "preregistration_sha256": prereg_sha,
                "protocol": prereg["protocol"],
                "bootstrap_seed": {"sha256": "b" * 64, "u64_big_endian_first8": 1234},
                "pre_run_input_binding": binding,
                "post_run_input_binding": copy.deepcopy(binding),
                "confirmation_of": None,
                "selection_manifest_sha256": fixed_digest,
                "selection_manifest": manifest,
                "workload_environment": workload,
                "rows": rows,
                "cells": cells,
                "decision": decision,
                "post_run_selection_verified": True,
                "post_run_provenance_verified": True,
            }
            public = {
                "schema": AUDITOR.PUBLIC_SCHEMA,
                "aggregate_only": True,
                "contains_patterns_commands_paths_or_per_pattern_rows": False,
                "campaign_role": "primary",
                "row_traversal": "canonical",
                "preregistration_sha256": prereg_sha,
                "protocol": prereg["protocol"],
                "bootstrap_seed": private["bootstrap_seed"],
                "pre_run_input_binding": binding,
                "post_run_input_binding": copy.deepcopy(binding),
                "confirmation_of": None,
                "method": {
                    "unit": "one frozen query in one fresh ripgrep process",
                    "timed_arms": ["B0", "B1", "N1", "N0"],
                    "stock_or_automatic_timed_arms": 0,
                    "warmup_quartets_per_row": 2,
                    "measured_quartets_per_row": 8,
                    "canonical_rows": 408,
                    "row_offset_uses_stable_canonical_ordinal": True,
                    "timed_receipts": False,
                    "filesystem_cache_state": (
                        "cache-hot/uncontrolled after one archive materialization; "
                        "no eviction between invocations"
                    ),
                },
                "workload_environment": workload,
                "cohorts": {
                    "oot": AUDITOR.cohort_profile([
                        row for row in manifest
                        if row["private_id"].startswith("oot-")
                    ]),
                    "wider": AUDITOR.cohort_profile([
                        row for row in manifest
                        if row["private_id"].startswith("wider-")
                    ]),
                },
                "cells": cells,
                "decision": decision,
                "post_run_selection_verified": True,
                "post_run_provenance_verified": True,
            }
            with tempfile.TemporaryDirectory() as text:
                root = Path(text)
                private_path = root / "private.json"
                public_path = root / "public.json"
                private_path.write_text(json.dumps(private) + "\n")
                public["private_result_sha256"] = hashlib.sha256(
                    private_path.read_bytes()
                ).hexdigest()
                public_path.write_text(json.dumps(public) + "\n")
                with mock.patch.object(
                    AUDITOR, "bootstrap_seed",
                    return_value=private["bootstrap_seed"],
                ):
                    validated = AUDITOR.validate_result_pair(
                        private_path=private_path,
                        public_path=public_path,
                        expected_role="primary",
                        expected_traversal="canonical",
                        prereg=prereg,
                        prereg_sha256=prereg_sha,
                        external_probes=external,
                    )
                self.assertEqual(408, len(validated["rows"]))
                public["cohorts"]["oot"]["unique_patterns"] += 1
                public_path.write_text(json.dumps(public) + "\n")
                with (
                    mock.patch.object(
                        AUDITOR, "bootstrap_seed",
                        return_value=private["bootstrap_seed"],
                    ),
                    self.assertRaises(AUDITOR.AuditError),
                ):
                    AUDITOR.validate_result_pair(
                        private_path=private_path,
                        public_path=public_path,
                        expected_role="primary",
                        expected_traversal="canonical",
                        prereg=prereg,
                        prereg_sha256=prereg_sha,
                        external_probes=external,
                    )
class AggregateAndDecisionTests(unittest.TestCase):
    def matrix_rows(self) -> list[dict]:
        selected = next(iter(
            RUNNER.representative.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_PRIVATE_IDS
        ))
        complement = next(iter(
            RUNNER.representative.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_PRIVATE_IDS
        ))
        rows = []
        ordinal = 0
        for profile in RUNNER.CPU_PROFILES:
            for panel in RUNNER.PANELS:
                for private_id, value in ((selected, 1.1), (complement, 1.0)):
                    row = aggregate_row(private_id, value, ordinal)
                    row["cpu_profile"] = profile
                    row["panel"] = panel
                    rows.append(row)
                    ordinal += 1
        return rows

    def test_runner_and_auditor_bootstrap_recompute_identically(self) -> None:
        rows = self.matrix_rows()
        with (
            mock.patch.object(RUNNER, "BOOTSTRAP_REPLICATES", 20),
            mock.patch.object(RUNNER, "BOOTSTRAP_LOW_INDEX", 0),
            mock.patch.object(RUNNER, "BOOTSTRAP_HIGH_INDEX", 19),
            mock.patch.object(AUDITOR, "BOOTSTRAP_REPLICATES", 20),
            mock.patch.object(AUDITOR, "BOOTSTRAP_LOW_INDEX", 0),
            mock.patch.object(AUDITOR, "BOOTSTRAP_HIGH_INDEX", 19),
        ):
            runner = RUNNER.aggregate_rows(rows, 1234)
            auditor = AUDITOR.aggregate_rows(rows, 1234)
        AUDITOR.compare_float_tree(runner, auditor, "cross implementation")

    def decision_cells(self, *, direct_low: float, direct_high: float) -> dict:
        aggregate = {
            "patterns": 44,
            "metrics": {
                metric: {
                    "point": 1.04 if metric in ("S", "D", "R1") else 1.0,
                    "confidence_interval_95": [1.01, 1.07],
                }
                for metric in RUNNER.METRICS
            },
            "diagnostic_splits": {
                "background_direction_S": {
                    "A_before_B": 1.04, "B_before_A": 1.04, "ratio": 1.0,
                },
                "cycle_orientation_D": {
                    "orders_0_3": 1.04, "orders_4_7": 1.04, "ratio": 1.0,
                },
            },
        }
        aggregate["metrics"]["R1"]["confidence_interval_95"] = [
            direct_low, direct_high
        ]
        selected = copy.deepcopy(aggregate)
        selected["patterns"] = 34
        complement = copy.deepcopy(aggregate)
        complement["patterns"] = 10
        complement["metrics"]["S"]["point"] = 1.0
        complement["metrics"]["D"]["point"] = 1.0
        return {
            "auto": {
                "fre-count-default-threads": {
                    "intention_to_treat": aggregate,
                    "selected34": selected,
                    "complement10": complement,
                }
            }
        }

    def test_decision_clear_go_no_go_and_inconclusive(self) -> None:
        go = RUNNER.decision_record(self.decision_cells(direct_low=1.031, direct_high=1.08))
        self.assertEqual("go", go["overall"])
        self.assertFalse(go["reverse_row_confirmation_required"])
        no_go = RUNNER.decision_record(self.decision_cells(direct_low=0.98, direct_high=1.02))
        self.assertEqual("no_go", no_go["overall"])
        self.assertTrue(no_go["reverse_row_confirmation_required"])
        uncertain = RUNNER.decision_record(self.decision_cells(direct_low=1.02, direct_high=1.04))
        self.assertEqual("inconclusive", uncertain["overall"])
        self.assertTrue(uncertain["reverse_row_confirmation_required"])
        self.assertEqual(
            go,
            AUDITOR.decision(
                self.decision_cells(direct_low=1.031, direct_high=1.08)
            ),
        )

    def test_every_prespecified_gate_can_trigger_confirmation(self) -> None:
        base = self.decision_cells(direct_low=1.031, direct_high=1.08)
        mutations = (
            ("C", "point", 1.04),
            ("S", "confidence_interval_95", [0.99, 1.08]),
            ("D", "confidence_interval_95", [0.99, 1.08]),
        )
        for metric, field, value in mutations:
            changed = copy.deepcopy(base)
            changed["auto"]["fre-count-default-threads"][
                "intention_to_treat"
            ]["metrics"][metric][field] = value
            self.assertTrue(RUNNER.decision_record(changed)["reverse_row_confirmation_required"])
        changed = copy.deepcopy(base)
        changed["auto"]["fre-count-default-threads"]["selected34"][
            "metrics"
        ]["D"]["confidence_interval_95"][0] = 0.99
        self.assertTrue(RUNNER.decision_record(changed)["reverse_row_confirmation_required"])
        for metric in ("S", "D"):
            changed = copy.deepcopy(base)
            changed["auto"]["fre-count-default-threads"]["complement10"][
                "metrics"
            ][metric]["point"] = 1.04
            self.assertTrue(RUNNER.decision_record(changed)["reverse_row_confirmation_required"])
        for split in ("background_direction_S", "cycle_orientation_D"):
            changed = copy.deepcopy(base)
            changed["auto"]["fre-count-default-threads"][
                "intention_to_treat"
            ]["diagnostic_splits"][split]["ratio"] = 1.051
            self.assertTrue(RUNNER.decision_record(changed)["reverse_row_confirmation_required"])

    def test_paired_combination_resamples_runs_jointly_and_deterministically(self) -> None:
        primary_rows = self.matrix_rows()
        reverse_rows = copy.deepcopy(primary_rows)
        for row in reverse_rows:
            scale = 1.1 if row["private_id"] in AUDITOR.SELECTED_IDS else 0.98
            for item in row["quartets"]:
                item["metrics"] = {
                    metric: float(value) * scale
                    for metric, value in item["metrics"].items()
                }
            row["summary"] = RUNNER.row_summary(row["quartets"])
        with (
            mock.patch.object(RUNNER, "BOOTSTRAP_REPLICATES", 20),
            mock.patch.object(RUNNER, "BOOTSTRAP_LOW_INDEX", 0),
            mock.patch.object(RUNNER, "BOOTSTRAP_HIGH_INDEX", 19),
            mock.patch.object(AUDITOR, "BOOTSTRAP_REPLICATES", 20),
            mock.patch.object(AUDITOR, "BOOTSTRAP_LOW_INDEX", 0),
            mock.patch.object(AUDITOR, "BOOTSTRAP_HIGH_INDEX", 19),
        ):
            primary_cells = RUNNER.aggregate_rows(primary_rows, 1234)
            reverse_cells = RUNNER.aggregate_rows(reverse_rows, 1234)
            primary = {
                "rows": primary_rows,
                "cells": primary_cells,
                "decision": RUNNER.decision_record(primary_cells),
            }
            reverse = {
                "rows": reverse_rows,
                "cells": reverse_cells,
                "decision": RUNNER.decision_record(reverse_cells),
            }
            first = AUDITOR.combined_analysis(primary, reverse, 4321)
            second = AUDITOR.combined_analysis(primary, reverse, 4321)
        AUDITOR.compare_float_tree(first, second, "paired determinism")
        selected_id = next(iter(AUDITOR.SELECTED_IDS & {
            row["private_id"] for row in primary_rows
        }))
        p_row = next(row for row in primary_rows if row["private_id"] == selected_id)
        r_row = next(row for row in reverse_rows if row["private_id"] == selected_id)
        expected_selected = (
            float(p_row["summary"]["metrics"]["S"])
            * float(r_row["summary"]["metrics"]["S"])
        ) ** 0.5
        actual_selected = first["pooled_cells"]["auto"][
            "fre-count-default-threads"
        ]["selected34"]["metrics"]["S"]["point"]
        self.assertAlmostEqual(expected_selected, actual_selected)
        self.assertEqual(
            [0, 19], first["method"]["percentile_indices"]
        )

    def test_combined_verdict_cannot_pool_away_run_failures(self) -> None:
        cells = self.decision_cells(direct_low=1.031, direct_high=1.08)
        primary = {
            "cells": copy.deepcopy(cells),
            "decision": RUNNER.decision_record(copy.deepcopy(cells)),
        }
        reverse = copy.deepcopy(primary)
        pooled = copy.deepcopy(cells)
        ratios = {
            "auto": {
                "fre-count-default-threads": {
                    "intention_to_treat": {
                        metric: 1.0 for metric in RUNNER.METRICS
                    }
                }
            }
        }
        go = AUDITOR.combined_decision(primary, reverse, pooled, ratios)
        self.assertEqual("go", go["overall"])
        self.assertTrue(go["enable_new_scanner"])

        run_below = copy.deepcopy(reverse)
        run_below["cells"]["auto"]["fre-count-default-threads"][
            "intention_to_treat"
        ]["metrics"]["R1"]["point"] = 1.029
        self.assertEqual(
            "no_go",
            AUDITOR.combined_decision(
                primary, run_below, pooled, ratios
            )["overall"],
        )
        unstable = copy.deepcopy(ratios)
        unstable["auto"]["fre-count-default-threads"][
            "intention_to_treat"
        ]["S"] = 1.051
        self.assertEqual(
            "inconclusive",
            AUDITOR.combined_decision(
                primary, reverse, pooled, unstable
            )["overall"],
        )
        direction_failure = copy.deepcopy(primary)
        direction_failure["decision"]["requirements"][
            "background_direction_ratio_in_0_95_1_05"
        ] = False
        self.assertEqual(
            "inconclusive",
            AUDITOR.combined_decision(
                direction_failure, reverse, pooled, ratios
            )["overall"],
        )
        control_failure = copy.deepcopy(pooled)
        control_failure["auto"]["fre-count-default-threads"][
            "intention_to_treat"
        ]["metrics"]["C"]["point"] = 1.031
        self.assertEqual(
            "inconclusive",
            AUDITOR.combined_decision(
                primary, reverse, control_failure, ratios
            )["overall"],
        )


if __name__ == "__main__":
    unittest.main()

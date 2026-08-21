#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "background_aot_representative_harness", HERE / "harness.py"
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class HarnessTests(unittest.TestCase):
    def test_unordered_output_preserves_duplicate_records(self) -> None:
        base = {"status": 0, "stderr_raw": b"", "stdout_raw": b"a\nb\na\n"}
        reordered = {
            "status": 0,
            "stderr_raw": b"",
            "stdout_raw": b"b\na\na\n",
        }
        missing = {"status": 0, "stderr_raw": b"", "stdout_raw": b"b\na\n"}
        self.assertTrue(
            HARNESS.outputs_equal(base, reordered, "unordered_lf_records")
        )
        self.assertFalse(
            HARNESS.outputs_equal(base, missing, "unordered_lf_records")
        )
        self.assertEqual(
            HARNESS.semantic_stdout_sha256(
                base["stdout_raw"], "unordered_lf_records"
            ),
            HARNESS.semantic_stdout_sha256(
                reordered["stdout_raw"], "unordered_lf_records"
            ),
        )
        self.assertNotEqual(
            HARNESS.semantic_stdout_sha256(
                base["stdout_raw"], "unordered_lf_records"
            ),
            HARNESS.semantic_stdout_sha256(
                missing["stdout_raw"], "unordered_lf_records"
            ),
        )

    def test_error_exit_is_not_a_timing_sample(self) -> None:
        result = {
            "timed_out": False,
            "status": 2,
            "elapsed_ns": 10,
        }
        summary = HARNESS.pair_case_summary(
            [{
                "normal": result,
                "background": result,
                "stock": result,
                "exact_normal_background": True,
                "exact_stock_normal": True,
            }]
        )
        self.assertEqual(0, summary["usable_pairs"])
        self.assertIsNone(summary["paired_ratio_median"])

    def test_requested_profile_is_checked_when_structured_field_exists(self) -> None:
        receipt = {
            "schema": HARNESS.RECEIPT_SCHEMA,
            "outcome": "declined",
            "publication_stage": "compile",
            "publication_refusal_class": "profile_fixed_strings",
            "direct_native_only": True,
            "external_linker_invocations": 0,
            "target_feature_profile": "auto",
            "requested_target_feature_bits": 7 << 32,
            "host_target_feature_bits": 7 << 32,
            "target_feature_bits": 7 << 32,
            "runtime_helper_required": False,
        }
        for field in (
            "compile_ns", "publish_ns", "prepare_ns", "stock_files",
            "fre_aot_files", "mixed_engine_files", "total_file_attempts",
            "stock_windows", "fre_aot_windows", "stock_window_bytes",
            "stock_committed_bytes", "fre_aot_window_bytes",
            "native_call_failures", "test_min_stock_bytes",
        ):
            receipt[field] = 0
        self.assertIn(
            "target_profile_mismatch",
            HARNESS.validate_receipt(receipt, "sve"),
        )
        receipt.update({
            "target_feature_profile": "sve",
            "requested_target_feature_bits": 1 << 33,
            "target_feature_bits": 1 << 33,
        })
        self.assertEqual([], HARNESS.validate_receipt(receipt, "sve"))
        receipt["requested_target_feature_bits"] = 0
        self.assertIn(
            "requested_target_feature_bits_mismatch",
            HARNESS.validate_receipt(receipt, "sve"),
        )
        receipt.update({
            "publication_stage": "profile_gate",
            "requested_target_feature_bits": 1 << 33,
            "host_target_feature_bits": None,
            "target_feature_bits": None,
        })
        self.assertEqual([], HARNESS.validate_receipt(receipt, "sve"))

    def test_unfinished_pre_detection_receipt_allows_missing_host(self) -> None:
        receipt = {
            "schema": HARNESS.RECEIPT_SCHEMA,
            "outcome": "unfinished",
            "publication_stage": "not_started",
            "publication_refusal_class": None,
            "direct_native_only": True,
            "external_linker_invocations": 0,
            "target_feature_profile": "auto",
            "requested_target_feature_bits": None,
            "host_target_feature_bits": None,
            "target_feature_bits": None,
            "runtime_helper_required": False,
        }
        for field in (
            "compile_ns", "publish_ns", "prepare_ns", "stock_files",
            "fre_aot_files", "mixed_engine_files", "total_file_attempts",
            "stock_windows", "fre_aot_windows", "stock_window_bytes",
            "stock_committed_bytes", "fre_aot_window_bytes",
            "native_call_failures", "test_min_stock_bytes",
        ):
            receipt[field] = 0
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))
        receipt.update({
            "outcome": "declined",
            "publication_stage": "target_detection",
            "publication_refusal_class": "unsupported_host",
        })
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("missing_host_target_feature_bits", failures)

    def test_matrix_requires_one_qualified_receipt_per_profile(self) -> None:
        host = 7 << 32

        def row(profile, requested, target):
            return {
                "cpu_profile": profile,
                "background": {"receipt": {
                    "target_feature_profile": profile,
                    "requested_target_feature_bits": requested,
                    "host_target_feature_bits": host,
                    "target_feature_bits": target,
                    "publication_refusal_class": None,
                }},
            }

        rows = [row("auto", host, host), row("sve", 1 << 33, 1 << 33)]
        matrix = HARNESS.target_validation_matrix(rows, ["auto", "sve"])
        self.assertTrue(matrix["qualified"])
        self.assertEqual(
            1,
            matrix["per_profile"]["sve"]["fully_target_validated_receipts"],
        )
        self.assertFalse(
            HARNESS.target_validation_matrix(rows[:1], ["auto", "sve"])[
                "qualified"
            ]
        )

    def test_standalone_selection_manifest_round_trips(self) -> None:
        semantics = {
            "matcher_mode": "regex",
            "regex_engine_request": "default",
            "case": "case_sensitive",
        }
        oot = [
            HARNESS.QueryCase(
                private_id=f"oot-{index:04d}",
                cohort="frozen-oot-84",
                pattern=f"oot pattern {index}",
                occurrence_weight=2 if index == 1 else 1,
                suffix=".rs" if index <= 8 else None,
                semantics=semantics,
            )
            for index in range(1, 85)
        ]
        wider = [
            HARNESS.QueryCase(
                private_id=f"wider-{index:04d}",
                cohort="frozen-unique-sample-2",
                pattern=f"wider pattern {index}",
                occurrence_weight=1,
                suffix=None,
                semantics=semantics,
            )
            for index in range(1, 3)
        ]
        manifest = HARNESS.case_manifest([*oot, *wider])
        document = {
            "schema": f"{HARNESS.RESULT_SCHEMA}.selection.v1",
            "oot_end_unix": HARNESS.OOT_END_UNIX,
            "oot_expected_counts": HARNESS.EXPECTED_OOT,
            "wider_sample_size": 2,
            "wider_sample_seed": 7,
            "frozen_private_source_sha256": (
                HARNESS.EXPECTED_PRIVATE["source_sha256"]
            ),
            "selection_manifest_sha256": HARNESS.manifest_digest(manifest),
            "selection_manifest": manifest,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selection.json"
            path.write_text(json.dumps(document))
            loaded_oot, loaded_wider = HARNESS.load_selection_manifest(
                path, wider_sample_size=2, wider_sample_seed=7
            )
            self.assertEqual(manifest, HARNESS.case_manifest([
                *loaded_oot, *loaded_wider,
            ]))
            document["selection_manifest_sha256"] = "0" * 64
            path.write_text(json.dumps(document))
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.load_selection_manifest(
                    path, wider_sample_size=2, wider_sample_seed=7
                )
            document["schema"] = (
                f"{HARNESS.RESULT_SCHEMA}.probe.private.v1"
            )
            document["selection_manifest_sha256"] = (
                HARNESS.manifest_digest(manifest)
            )
            path.write_text(json.dumps(document))
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.load_selection_manifest(
                    path, wider_sample_size=2, wider_sample_seed=7
                )

    def test_private_probe_matrix_is_recomputed(self) -> None:
        semantics = {
            "matcher_mode": "regex",
            "regex_engine_request": "default",
            "case": "case_sensitive",
        }
        oot = HARNESS.QueryCase(
            "oot-0001", "frozen-oot-84", "oot", 1, None, semantics
        )
        wider = HARNESS.QueryCase(
            "wider-0001", "frozen-unique-sample-1", "wider", 1,
            None, semantics,
        )
        empty = HARNESS.output_record(b"")

        def result():
            return {
                "elapsed_ns": 1,
                "user_ns": 0,
                "system_ns": 0,
                "timed_out": False,
                "status": 1,
                "stdout": empty,
                "stderr": empty,
                "receipt": None,
                "receipt_parse_error": False,
                "unexpected_temporary_artifacts": 0,
            }

        comparison = {
            "status": 1,
            "stderr_sha256": empty["sha256"],
            "semantic_stdout_sha256": empty["sha256"],
        }
        rows = []
        for panel, cases in (
            ("ripgrep-default-output", [oot]),
            ("fre-count-default-threads", [oot, wider]),
            ("fre-count-thread1", [oot, wider]),
        ):
            for case in cases:
                identity = HARNESS.case_manifest([case])[0]
                rows.append({
                    **identity,
                    "cpu_profile": "auto",
                    "panel": panel,
                    "normalization": [],
                    "exact_normal_background": True,
                    "exact_stock_normal": True,
                    "receipt_failures": ["missing_receipt"],
                    "comparison_records": {
                        "normal": comparison,
                        "background": comparison,
                        "stock": comparison,
                    },
                    "normal": result(),
                    "background": result(),
                    "stock": result(),
                })
        panels, _ = HARNESS.validate_and_aggregate_private_probe(
            {"rows": rows}, cpu_profiles=["auto"], oot=[oot], wider=[wider]
        )
        self.assertEqual(5, sum(
            panel["all_selected"]["cases"] for panel in panels.values()
        ))
        tampered = [dict(row) for row in rows]
        tampered[0]["exact_stock_normal"] = False
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.validate_and_aggregate_private_probe(
                {"rows": tampered}, cpu_profiles=["auto"],
                oot=[oot], wider=[wider],
            )
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.validate_and_aggregate_private_probe(
                {"rows": [*rows, rows[0]]}, cpu_profiles=["auto"],
                oot=[oot], wider=[wider],
            )

    def test_grouped_aggregate_keeps_primary_separate(self) -> None:
        cases = {
            "one": HARNESS.QueryCase("one", "primary", "raw-one", 1, None, {}),
            "two": HARNESS.QueryCase("two", "secondary", "raw-two", 1, None, {}),
        }

        def count(rows, ignored):
            return {"count": len(rows)}

        result = HARNESS.aggregate_groups(
            [
                {"private_id": "one", "cohort": "primary"},
                {"private_id": "two", "cohort": "secondary"},
            ],
            cases,
            count,
        )
        self.assertEqual(2, result["all_selected"]["count"])
        self.assertEqual({"count": 1}, result["by_cohort"]["primary"])
        self.assertNotIn("raw-one", repr(result))

    def test_complete_summary_reports_order_effect_and_stock_ratio(self) -> None:
        def timed(elapsed):
            return {"timed_out": False, "status": 1, "elapsed_ns": elapsed}

        orders = (
            ("stock", "normal", "background"),
            ("normal", "background", "stock"),
            ("stock", "background", "normal"),
            ("background", "normal", "stock"),
        )
        pairs = [
            {
                "order": list(order),
                "normal": timed(100),
                "background": timed(80),
                "stock": timed(120),
                "exact_normal_background": True,
                "exact_stock_normal": True,
            }
            for order in orders
        ]
        summary = HARNESS.pair_case_summary(pairs)
        self.assertTrue(summary["complete"])
        self.assertEqual(1.25, summary["paired_ratio_median"])
        self.assertEqual(1.5, summary["stock_background_ratio_median"])
        self.assertEqual(
            1.0,
            summary["order_effect_normal_first_over_background_first"],
        )
        pairs[0]["normal"] = {"timed_out": True, "status": None, "elapsed_ns": 1}
        self.assertIsNone(
            HARNESS.pair_case_summary(pairs)["paired_ratio_median"]
        )


if __name__ == "__main__":
    unittest.main()

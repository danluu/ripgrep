#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "background_aot_representative_harness", HERE / "harness.py"
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def receipt_fixture(**overrides):
    receipt = {
        "schema": HARNESS.RECEIPT_SCHEMA,
        "outcome": "declined",
        "decline_reason": "unsupported profile",
        "publication_stage": "compile",
        "publication_refusal_class": "profile_fixed_strings",
        "direct_native_only": True,
        "external_linker_invocations": 0,
        "target_feature_profile": "auto",
        "requested_target_feature_bits": 7 << 32,
        "host_target_feature_bits": 7 << 32,
        "target_feature_bits": 7 << 32,
        "compiler_engine": None,
        "engine_selection_reason": None,
        "start_accelerator": None,
        "compiled_output_contract": None,
        "compiled_entry_abi": None,
        "compiled_state_source": None,
        "compiled_forward_states": None,
        "compiled_reverse_states": None,
        "compiled_reverse_start_recovery": None,
        "compiled_primary_native_route": None,
        "exact_finite_selected_end_teddy_aot": None,
        "wait_requested": False,
        "compiler_settled": True,
        "runtime_helper_required": False,
        "published_code_bytes": None,
        "published_read_only_data_bytes": None,
        "published_total_mapped_bytes": None,
        "ready_ns_since_start": None,
        "compile_ns": 0,
        "publish_ns": 0,
        "prepare_ns": 0,
        "total_file_attempts": 0,
        "native_call_failures": 0,
        "test_min_stock_bytes": 0,
        "first_candidate_midscan_cutover_file_ordinal": None,
        "first_candidate_midscan_cutover_ns_since_start": None,
        "first_candidate_midscan_cutover_stock_committed_bytes": None,
    }
    for field in (
        *HARNESS.CANDIDATE_DISCOVERY_COUNTER_FIELDS,
        *HARNESS.STOCK_WORK_COUNTER_FIELDS,
    ):
        receipt[field] = 0
    receipt.update(overrides)
    return receipt


def ready_receipt(**overrides):
    receipt = receipt_fixture(
        outcome="ready",
        decline_reason=None,
        publication_stage="published",
        publication_refusal_class=None,
        compiler_engine="ordered_dfa",
        engine_selection_reason="complete_dfa",
        start_accelerator="aarch64_sve2",
        compiled_output_contract=HARNESS.COMPILED_OUTPUT_CONTRACT,
        compiled_entry_abi=HARNESS.COMPILED_ENTRY_ABI,
        compiled_state_source="semantic_dfa",
        compiled_forward_states=17,
        compiled_reverse_states=0,
        compiled_reverse_start_recovery=False,
        compiled_primary_native_route="ordered_dfa",
        published_code_bytes=4096,
        published_read_only_data_bytes=1024,
        published_total_mapped_bytes=8192,
        ready_ns_since_start=10,
        compile_ns=5,
        publish_ns=2,
        prepare_ns=7,
    )
    receipt.update(overrides)
    return receipt


def exact_teddy_report_fixture(**overrides):
    digest = "1" * 64
    report = {
        "authenticated_compiler_report": True,
        "artifact_identity_sha256": digest,
        "output_contract": HARNESS.COMPILED_OUTPUT_CONTRACT,
        "literal_sha256": "2" * 64,
        "prefix_plan_sha256": "3" * 64,
        "native_code_sha256": "4" * 64,
        "native_data_sha256": "5" * 64,
        "relocations_sha256": "6" * 64,
        "source_count": 4,
        "source_bytes": 20,
        "minimum_width": 4,
        "maximum_width": 7,
        "root_members": [1, 1 << 33, 0, 0],
        "columns": 4,
        "bucket_count": 4,
        "literal_count": 4,
        "candidate_fingerprint_upper_bound": 10,
        "candidate_frequency_upper_bound": 20,
        "fingerprint_space": 1 << 32,
        "plan_scan_instruction_units": 31,
        "emitted_scan_instruction_units": 27,
        "guaranteed_vector_bytes": 16,
        "gate_table_bytes": 128,
        "selected_target_tier": "aarch64_sve2",
        "emitted_isa": "aarch64_sve",
        "scanner": "aarch64_sve",
        "target": {
            "architecture": "aarch64",
            "operating_system": "linux",
            "abi": "aapcs64",
            "feature_bits": 7 << 32,
        },
        "input_floor_bytes": 4096,
        "selection_horizon_bytes": 4096,
        "selection_gate_cost_units_decimal": "6914",
        "selection_expected_verification_cost_units_decimal": "1",
        "selection_full_cost_units_decimal": "27657",
        "selection_incumbent_cost_units_decimal": "57344",
        "selection_root_frequency_units": 25,
        "selection_no_candidate_numerator_decimal": "4294885376",
        "selection_probability_denominator_decimal": "4294967296",
        "runtime_verification_budget": 64,
        "table_base": 128,
        "table_end": 256,
        "bucket_ordinal_masks_offset": 256,
        "literal_descriptors_offset": 320,
        "literal_bytes_offset": 352,
        "literal_bytes_end": 372,
        "native_data_bytes": 372,
        "incumbent": {
            "semantic_dfa_sha256": "7" * 64,
            "forward_states": 23,
            "alphabet_classes": 9,
            "transition_cells": 207,
            "minimum_native_data_bytes": 64,
            "native_data_bytes": 128,
            "hot_loads_per_byte": 2,
            "hot_branches_per_byte": 2,
            "has_accelerator": False,
            "scanner": "none",
            "native_code_sha256": "8" * 64,
            "native_data_sha256": "9" * 64,
            "relocations_sha256": "a" * 64,
            "native_code_offset": 100,
            "native_code_bytes": 50,
            "relocation_count": 0,
        },
    }
    report.update(overrides)
    return report


def exact_teddy_ready_receipt(**overrides):
    receipt = ready_receipt(
        start_accelerator="aarch64_sve",
        compiled_state_source=(
            "exact_finite_selected_end_teddy_incumbent"
        ),
        compiled_forward_states=23,
        compiled_reverse_states=0,
        compiled_primary_native_route=HARNESS.EXACT_TEDDY_PRIMARY_ROUTE,
        exact_finite_selected_end_teddy_aot=exact_teddy_report_fixture(),
        published_read_only_data_bytes=372,
    )
    receipt.update(overrides)
    return receipt


class HarnessTests(unittest.TestCase):
    def test_run_once_scrubs_control_environment(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            executable = root / "inspect-env"
            executable.write_text(
                "#!/bin/sh\n"
                "printf '%s|%s|%s|%s|%s\\n' "
                '"${RG_FRE_AOT_BACKGROUND_RECEIPT+set}" '
                '"${RG_FRE_AOT_BACKGROUND_RECEIPT_WAIT_FOR_COMPILER-unset}" '
                '"${RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES-unset}" '
                '"${RG_FRE_AOT_BACKGROUND_CPU_PROFILE-unset}" '
                '"${RIPGREP_CONFIG_PATH-unset}"\n'
            )
            executable.chmod(0o700)
            inherited = {
                HARNESS.RECEIPT_ENV: "inherited-receipt",
                HARNESS.RECEIPT_WAIT_FOR_COMPILER_ENV: "inherited-wait",
                HARNESS.CORRECTNESS_GATE_ENV: "inherited-gate",
                HARNESS.CPU_PROFILE_ENV: "inherited-profile",
                "RIPGREP_CONFIG_PATH": "inherited-config",
            }
            with mock.patch.dict(os.environ, inherited):
                normal = HARNESS.run_once(
                    binary=executable,
                    args=[],
                    cwd=root,
                    background=False,
                    capture_receipt=False,
                    cpu_profile="auto",
                    timeout_seconds=5.0,
                    test_min_stock_bytes=123,
                    collect_timing=False,
                )
                background = HARNESS.run_once(
                    binary=executable,
                    args=[],
                    cwd=root,
                    background=True,
                    capture_receipt=False,
                    cpu_profile="sve",
                    timeout_seconds=5.0,
                    test_min_stock_bytes=123,
                    collect_timing=False,
                )
                settlement = HARNESS.run_once(
                    binary=executable,
                    args=[],
                    cwd=root,
                    background=True,
                    capture_receipt=True,
                    cpu_profile="auto",
                    timeout_seconds=5.0,
                    collect_timing=False,
                    wait_for_compiler_settlement=True,
                )
        self.assertEqual(
            b"|unset|unset|unset|unset\n", normal["stdout_raw"]
        )
        self.assertEqual(
            b"|unset|123|sve|unset\n", background["stdout_raw"]
        )
        self.assertEqual(
            b"set|1|unset|auto|unset\n", settlement["stdout_raw"]
        )

    def test_settlement_mode_requires_a_background_receipt(self) -> None:
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.run_once(
                binary=Path("unused"),
                args=[],
                cwd=Path("."),
                background=False,
                capture_receipt=False,
                cpu_profile="auto",
                timeout_seconds=1.0,
                collect_timing=False,
                wait_for_compiler_settlement=True,
            )

    def test_run_once_can_omit_timing_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "success"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            with (
                mock.patch.object(
                    HARNESS.time,
                    "perf_counter_ns",
                    side_effect=AssertionError("wall clock sampled"),
                ),
                mock.patch.object(
                    HARNESS.resource,
                    "getrusage",
                    side_effect=AssertionError("child CPU sampled"),
                ),
            ):
                result = HARNESS.run_once(
                    binary=executable,
                    args=[],
                    cwd=root,
                    background=False,
                    capture_receipt=False,
                    cpu_profile="auto",
                    timeout_seconds=5.0,
                    collect_timing=False,
                )
        self.assertEqual(0, result["status"])
        self.assertNotIn("elapsed_ns", result)
        self.assertNotIn("user_ns", result)
        self.assertNotIn("system_ns", result)

    def test_non_object_receipt_is_rejected_without_crashing(self) -> None:
        self.assertEqual(
            ["receipt_not_object"], HARNESS.validate_receipt([], "auto")
        )
        case = HARNESS.QueryCase("q", "test", "raw", 1, None, {})
        row = {
            "private_id": "q",
            "exact_normal_background": True,
            "exact_stock_normal": True,
            "receipt_failures": ["malformed_receipt"],
            "normalization": [],
            "normal": {"status": 1},
            "background": {"timed_out": False, "receipt": None},
        }
        aggregate = HARNESS.aggregate_observations([row], {"q": case})
        self.assertEqual({"no_receipt": 1}, aggregate["routing"])

    def test_public_result_binds_exact_private_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "result.private.json"
            public = root / "result.public.json"
            HARNESS.write_bound_result_pair(
                private,
                public,
                {"schema": "private", "rows": [1, 2, 3]},
                {"schema": "public", "aggregate_only": True},
            )
            public_value = json.loads(public.read_text())
            self.assertEqual(
                HARNESS.sha256_file(private),
                public_value["private_result_sha256"],
            )
            self.assertEqual(0o600, private.stat().st_mode & 0o777)
            self.assertEqual(0o644, public.stat().st_mode & 0o777)

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
        receipt = receipt_fixture()
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
        receipt = receipt_fixture(
            outcome="unfinished",
            publication_stage="not_started",
            publication_refusal_class=None,
            requested_target_feature_bits=None,
            host_target_feature_bits=None,
            target_feature_bits=None,
        )
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))
        receipt.update({
            "outcome": "declined",
            "publication_stage": "target_detection",
            "publication_refusal_class": "unsupported_host",
        })
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("missing_host_target_feature_bits", failures)

    def test_v4_receipt_requires_candidate_discovery_fields(self) -> None:
        receipt = ready_receipt()
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))

        receipt["schema"] = "ripgrep.fre-aot-background.v3"
        self.assertIn("schema", HARNESS.validate_receipt(receipt, "auto"))

        receipt = ready_receipt(stock_windows=1)
        del receipt["candidate_stock_windows"]
        self.assertIn(
            "invalid_candidate_stock_windows",
            HARNESS.validate_receipt(receipt, "auto"),
        )

    def test_compiled_selected_end_contract_is_validated(self) -> None:
        changes_and_failures = (
            (
                {"compiled_output_contract": "span"},
                "invalid_compiled_output_contract",
            ),
            (
                {"compiled_entry_abi": "span_search_v1"},
                "invalid_compiled_entry_abi",
            ),
            (
                {"compiled_forward_states": -1},
                "invalid_compiled_forward_states",
            ),
            (
                {"compiled_forward_states": 0},
                "compiled_forward_states_zero",
            ),
            (
                {"compiled_reverse_states": None},
                "missing_compiled_reverse_states",
            ),
            (
                {"compiled_reverse_start_recovery": True},
                "selected_end_reverse_start_recovery_present",
            ),
        )
        for changes, failure in changes_and_failures:
            with self.subTest(failure=failure):
                self.assertIn(
                    failure,
                    HARNESS.validate_receipt(
                        ready_receipt(**changes), "auto"
                    ),
                )

        nfa = ready_receipt(
            compiler_engine="ordered_nfa",
            engine_selection_reason="determinization_resource_limit",
            compiled_forward_states=None,
            compiled_reverse_states=None,
            compiled_state_source=None,
            compiled_primary_native_route="ordered_nfa",
        )
        self.assertEqual([], HARNESS.validate_receipt(nfa, "auto"))
        nfa["compiled_forward_states"] = 1
        self.assertIn(
            "incomplete_compiled_state_geometry",
            HARNESS.validate_receipt(nfa, "auto"),
        )
        nfa["compiled_reverse_states"] = 0
        nfa["compiled_state_source"] = "slow_aot"
        nfa["compiled_primary_native_route"] = "slow_dfa"
        self.assertEqual([], HARNESS.validate_receipt(nfa, "auto"))

        finite = ready_receipt(
            compiled_state_source="ordered_finite_language",
            compiled_forward_states=9,
            compiled_reverse_states=0,
            compiled_primary_native_route="ordered_finite_language",
        )
        self.assertEqual([], HARNESS.validate_receipt(finite, "auto"))

        contextual = ready_receipt(
            compiler_engine="ordered_context_dfa",
            engine_selection_reason="complete_context_dfa",
            compiled_state_source="context_determinization",
            compiled_forward_states=11,
            compiled_reverse_states=7,
            compiled_reverse_start_recovery=False,
            compiled_primary_native_route="ordered_context_dfa",
        )
        self.assertEqual([], HARNESS.validate_receipt(contextual, "auto"))

    def test_precompile_receipt_requires_nullable_compiled_fields(self) -> None:
        receipt = receipt_fixture()
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))
        del receipt["compiled_entry_abi"]
        self.assertIn(
            "missing_compiled_entry_abi",
            HARNESS.validate_receipt(receipt, "auto"),
        )

    def test_v5_exact_teddy_route_and_incumbent_are_unambiguous(self) -> None:
        receipt = exact_teddy_ready_receipt()
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))

        receipt["compiled_primary_native_route"] = "ordered_dfa"
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("primary_native_route_state_mismatch", failures)
        self.assertIn("exact_teddy_report_on_non_teddy_route", failures)

        receipt = exact_teddy_ready_receipt()
        receipt["exact_finite_selected_end_teddy_aot"]["incumbent"][
            "semantic_dfa_sha256"
        ] = "0" * 64
        self.assertIn(
            "invalid_exact_teddy_incumbent_semantic_dfa_sha256",
            HARNESS.validate_receipt(receipt, "auto"),
        )

    def test_exact_teddy_report_rejects_selection_boundaries(self) -> None:
        cases = (
            ("source_low", {"source_count": 3},
             "exact_teddy_source_count_range"),
            ("source_high", {"source_count": 65},
             "exact_teddy_source_count_range"),
            ("width_below_three", {"minimum_width": 2},
             "exact_teddy_width_geometry"),
            ("width_below_columns", {"minimum_width": 3},
             "exact_teddy_width_geometry"),
            ("source_bytes", {"source_bytes": 15},
             "exact_teddy_source_bytes_bounds"),
            ("fingerprint_space", {"fingerprint_space": (1 << 32) - 1},
             "exact_teddy_fingerprint_space"),
            ("input_floor", {"input_floor_bytes": 4095},
             "exact_teddy_input_floor"),
            ("horizon", {"selection_horizon_bytes": 4097},
             "exact_teddy_selection_horizon"),
            ("budget", {"runtime_verification_budget": 63},
             "exact_teddy_runtime_verification_budget"),
            ("plan_units", {"plan_scan_instruction_units": 30},
             "exact_teddy_plan_scan_units"),
            ("sve2_emission", {"emitted_isa": "aarch64_sve2"},
             "exact_teddy_emitted_isa_scanner_mismatch"),
            ("gate_cost", {"selection_gate_cost_units_decimal": "6915"},
             "exact_teddy_gate_cost_equation"),
            ("full_cost", {"selection_full_cost_units_decimal": "27658"},
             "exact_teddy_full_cost_equation"),
            ("margin", {"selection_incumbent_cost_units_decimal": "30000"},
             "exact_teddy_incumbent_cost_equation"),
            ("layout", {"literal_bytes_end": 373},
             "exact_teddy_native_data_layout"),
        )
        for name, changed, expected in cases:
            with self.subTest(name=name):
                receipt = exact_teddy_ready_receipt()
                receipt["exact_finite_selected_end_teddy_aot"].update(changed)
                self.assertIn(
                    expected, HARNESS.validate_receipt(receipt, "auto")
                )

    def test_exact_teddy_report_binds_incumbent_geometry(self) -> None:
        mutations = (
            ("transition_cells", 206,
             "exact_teddy_incumbent_transition_geometry"),
            ("has_accelerator", True,
             "exact_teddy_incumbent_has_accelerator"),
            ("scanner", "scalar", "exact_teddy_incumbent_scanner"),
        )
        for field, value, expected in mutations:
            with self.subTest(field=field):
                receipt = copy.deepcopy(exact_teddy_ready_receipt())
                receipt["exact_finite_selected_end_teddy_aot"][
                    "incumbent"
                ][field] = value
                self.assertIn(
                    expected, HARNESS.validate_receipt(receipt, "auto")
                )
        receipt = exact_teddy_ready_receipt(compiled_forward_states=22)
        self.assertIn(
            "exact_teddy_top_nested_forward_states",
            HARNESS.validate_receipt(receipt, "auto"),
        )

    def test_legacy_v4_receipt_evidence_remains_readable(self) -> None:
        receipt = ready_receipt(schema=HARNESS.LEGACY_RECEIPT_SCHEMA)
        del receipt["compiled_primary_native_route"]
        del receipt["exact_finite_selected_end_teddy_aot"]
        del receipt["wait_requested"]
        del receipt["compiler_settled"]
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))
        self.assertIn(
            "current_receipt_schema_required",
            HARNESS.validate_receipt(
                receipt, "auto", require_current_schema=True
            ),
        )

        case = HARNESS.QueryCase("q", "test", "raw", 1, None, {})
        row = {
            "private_id": "q",
            "exact_normal_background": True,
            "exact_stock_normal": True,
            "receipt_failures": [],
            "normalization": [],
            "normal": {"status": 0},
            "background": {"timed_out": False, "receipt": receipt},
        }
        classification = HARNESS.aggregate_observations(
            [row], {"q": case}
        )["receipt_classification"]
        self.assertNotIn("primary_native_routes", classification)
        self.assertNotIn("exact_teddy_target_tiers", classification)

    def test_exact_teddy_census_uses_only_authenticated_primary_route(self) -> None:
        cases = [
            HARNESS.QueryCase("q1", "first", "raw-one", 1, None, {}),
            HARNESS.QueryCase("q2", "second", "raw-two", 1, None, {}),
        ]

        def row(case, receipt, failures=None):
            return {
                "private_id": case.private_id,
                "cohort": case.cohort,
                "cpu_profile": "auto",
                "panel": HARNESS.EXACT_TEDDY_CENSUS_PANEL,
                "receipt_failures": failures or [],
                "background": {"receipt": receipt},
            }

        private, public = HARNESS.exact_teddy_diagnostic_census(
            [
                row(cases[0], exact_teddy_ready_receipt(
                    wait_requested=True, compiler_settled=True,
                )),
                row(cases[1], ready_receipt(
                    wait_requested=True, compiler_settled=True,
                )),
            ],
            cases,
            ["auto"],
        )
        profile = private["per_profile"]["auto"]
        self.assertEqual(1, profile["compiler_selected_exact_teddy"])
        self.assertEqual(1, profile["published_exact_teddy"])
        self.assertEqual(
            ["auto/first/q1"],
            profile[
                "compiler_selected_exact_teddy_fully_qualified_ids"
            ],
        )
        self.assertFalse(public["contains_query_ids"])
        self.assertNotIn(
            "compiler_selected_exact_teddy_fully_qualified_ids",
            public["per_profile"]["auto"],
        )

        unsettled_private, _ = HARNESS.exact_teddy_diagnostic_census(
            [row(cases[0], exact_teddy_ready_receipt())],
            [cases[0]],
            ["auto"],
        )
        unsettled = unsettled_private["per_profile"]["auto"]
        self.assertEqual(0, unsettled["compiler_selected_exact_teddy"])
        self.assertEqual(1, unsettled["invalid_receipts"])

    def test_settlement_receipt_requires_definitive_outcome(self) -> None:
        settled = ready_receipt(
            wait_requested=True, compiler_settled=True
        )
        self.assertEqual(
            [],
            HARNESS.validate_receipt(
                settled,
                "auto",
                require_current_schema=True,
                require_compiler_settlement=True,
            ),
        )
        unfinished = receipt_fixture(
            outcome="unfinished",
            decline_reason="search finished before background compilation",
            wait_requested=True,
            compiler_settled=False,
        )
        failures = HARNESS.validate_receipt(
            unfinished,
            "auto",
            require_current_schema=True,
            require_compiler_settlement=True,
        )
        self.assertIn("requested_compiler_not_settled", failures)
        self.assertIn("compiler_not_settled", failures)
        self.assertIn("compiler_outcome_unfinished", failures)

    def test_first_candidate_midscan_cutover_is_strict(self) -> None:
        receipt = ready_receipt(
            total_file_attempts=2,
            candidate_stock_files=1,
            candidate_fre_aot_files=1,
            candidate_mixed_engine_files=1,
            candidate_midscan_cutover_files=1,
            candidate_stock_windows=1,
            candidate_fre_aot_windows=1,
            candidate_stock_window_bytes=1024,
            candidate_stock_committed_bytes=1024,
            candidate_fre_aot_window_bytes=1024,
            first_candidate_midscan_cutover_file_ordinal=2,
            first_candidate_midscan_cutover_ns_since_start=50,
            first_candidate_midscan_cutover_stock_committed_bytes=1024,
        )
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))
        receipt["first_candidate_midscan_cutover_ns_since_start"] = None
        self.assertIn(
            "incomplete_first_candidate_midscan_cutover",
            HARNESS.validate_receipt(receipt, "auto"),
        )
        del receipt["first_candidate_midscan_cutover_file_ordinal"]
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn(
            "missing_first_candidate_midscan_cutover_file_ordinal", failures
        )

    def test_candidate_accounting_closure_is_enforced(self) -> None:
        impossible = ready_receipt(
            total_file_attempts=2,
            candidate_mixed_engine_files=1,
            candidate_midscan_cutover_files=1,
        )
        failures = HARNESS.validate_receipt(impossible, "auto")
        self.assertIn("candidate_mixed_file_count_impossible", failures)
        self.assertIn("candidate_midscan_first_witness_mismatch", failures)

        overcommitted = ready_receipt(
            total_file_attempts=1,
            candidate_stock_files=1,
            candidate_stock_windows=1,
            candidate_stock_window_bytes=8,
            candidate_stock_committed_bytes=9,
        )
        self.assertIn(
            "candidate_committed_bytes_exceed_stock_windows",
            HARNESS.validate_receipt(overcommitted, "auto"),
        )

        zero_byte_aot = ready_receipt(
            total_file_attempts=1,
            candidate_fre_aot_files=1,
            candidate_fre_aot_windows=1,
            candidate_fre_aot_window_bytes=0,
        )
        self.assertIn(
            "candidate_aot_window_byte_mismatch",
            HARNESS.validate_receipt(zero_byte_aot, "auto"),
        )

    def test_forced_midscan_gate_is_recomputed_from_evidence(self) -> None:
        receipt = ready_receipt(
            test_min_stock_bytes=HARNESS.FORCED_MIDSCAN_STOCK_BYTES,
            total_file_attempts=1,
            candidate_stock_files=1,
            candidate_fre_aot_files=1,
            candidate_mixed_engine_files=1,
            candidate_midscan_cutover_files=1,
            candidate_stock_windows=4,
            candidate_fre_aot_windows=1,
            candidate_stock_window_bytes=5 * 1024 * 1024,
            candidate_stock_committed_bytes=4 * 1024 * 1024,
            candidate_fre_aot_window_bytes=12 * 1024 * 1024,
            first_candidate_midscan_cutover_file_ordinal=1,
            first_candidate_midscan_cutover_ns_since_start=20,
            first_candidate_midscan_cutover_stock_committed_bytes=(
                HARNESS.FORCED_MIDSCAN_STOCK_BYTES
            ),
        )
        expected_stdout = HARNESS.output_record(
            HARNESS.forced_midscan_expected_stdout()
        )
        expected_stderr = HARNESS.output_record(b"")
        comparison = {
            "status": 0,
            "stderr_sha256": expected_stderr["sha256"],
            "semantic_stdout_sha256": expected_stdout["sha256"],
        }
        arm = {
            "status": 0,
            "stdout": expected_stdout,
            "stderr": expected_stderr,
        }
        gate = {
            "cpu_profile": "auto",
            "exact_normal_background": True,
            "exact_stock_normal": True,
            "comparison_records": {
                "normal": comparison,
                "background": comparison,
                "stock": comparison,
            },
            "normal": dict(arm),
            "background": {
                **arm,
                "receipt": receipt,
                "receipt_parse_error": False,
                "unexpected_temporary_artifacts": 0,
            },
            "stock": dict(arm),
        }
        self.assertEqual(
            [], HARNESS.validate_forced_midscan_gate_record(gate, "auto")
        )
        gate["normal"]["status"] = 1
        self.assertIn(
            "forced_midscan_normal_evidence_mismatch",
            HARNESS.validate_forced_midscan_gate_record(gate, "auto"),
        )
        gate["normal"]["status"] = 0
        gate["normal"]["stdout"] = HARNESS.output_record(b"wrong\n")
        failures = HARNESS.validate_forced_midscan_gate_record(gate, "auto")
        self.assertIn("forced_midscan_normal_evidence_mismatch", failures)
        self.assertIn("forced_midscan_normal_unexpected_stdout", failures)

    def test_ready_receipt_requires_publication_timestamp(self) -> None:
        receipt = ready_receipt(ready_ns_since_start=None)
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("ready_missing_ready_ns_since_start", failures)

        receipt = ready_receipt(ready_ns_since_start="late")
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("invalid_ready_ns_since_start", failures)

    def test_routing_uses_only_candidate_discovery_work(self) -> None:
        receipt = ready_receipt(
            total_file_attempts=2,
            candidate_fre_aot_files=1,
            candidate_fre_aot_windows=1,
            stock_span_calls=3,
            stock_span_bytes=300,
            stock_capture_calls=2,
            stock_capture_bytes=200,
        )
        self.assertEqual("aot_only", HARNESS.route_class(receipt))
        receipt.update({
            "candidate_stock_files": 1,
            "candidate_stock_windows": 1,
        })
        self.assertEqual("cross_file_split", HARNESS.route_class(receipt))
        receipt["candidate_mixed_engine_files"] = 1
        self.assertEqual(
            "same_file_operation_mix", HARNESS.route_class(receipt)
        )
        receipt.update({
            "candidate_midscan_cutover_files": 1,
            "candidate_stock_window_bytes": 3,
            "candidate_stock_committed_bytes": 3,
            "first_candidate_midscan_cutover_file_ordinal": 1,
            "first_candidate_midscan_cutover_ns_since_start": 5,
            "first_candidate_midscan_cutover_stock_committed_bytes": 3,
        })
        self.assertEqual(
            "same_file_midscan_cutover", HARNESS.route_class(receipt)
        )

        stock_work_only = ready_receipt(stock_span_calls=1, stock_span_bytes=3)
        self.assertEqual(
            "no_candidate_windows", HARNESS.route_class(stock_work_only)
        )

    def test_v4_accounting_is_aggregated_separately(self) -> None:
        cases = {
            "dfa": HARNESS.QueryCase("dfa", "test", "raw", 1, None, {}),
            "nfa": HARNESS.QueryCase("nfa", "test", "raw", 2, None, {}),
        }

        def row(private_id, receipt):
            return {
                "private_id": private_id,
                "exact_normal_background": True,
                "exact_stock_normal": True,
                "receipt_failures": [],
                "normalization": [],
                "normal": {"status": 0},
                "background": {
                    "timed_out": False,
                    "receipt": receipt,
                },
            }

        dfa = ready_receipt(
            candidate_stock_files=1,
            candidate_fre_aot_files=1,
            candidate_mixed_engine_files=1,
            candidate_midscan_cutover_files=1,
            total_file_attempts=1,
            candidate_stock_windows=2,
            candidate_fre_aot_windows=3,
            candidate_stock_window_bytes=200,
            candidate_stock_committed_bytes=150,
            candidate_fre_aot_window_bytes=300,
            stock_span_calls=4,
            stock_span_bytes=40,
            first_candidate_midscan_cutover_file_ordinal=1,
            first_candidate_midscan_cutover_ns_since_start=5,
            first_candidate_midscan_cutover_stock_committed_bytes=150,
        )
        nfa = ready_receipt(
            compiler_engine="ordered_nfa",
            engine_selection_reason="determinization_resource_limit",
            compiled_forward_states=None,
            compiled_reverse_states=None,
            compiled_state_source=None,
            total_file_attempts=1,
            candidate_fre_aot_files=1,
            candidate_fre_aot_windows=2,
            candidate_fre_aot_window_bytes=250,
            stock_capture_calls=2,
            stock_capture_bytes=20,
        )
        aggregate = HARNESS.aggregate_observations(
            [row("dfa", dfa), row("nfa", nfa)], cases
        )
        self.assertEqual(
            {"aot_only": 1, "same_file_midscan_cutover": 1},
            aggregate["routing"],
        )
        self.assertEqual(
            5,
            aggregate["candidate_discovery_accounting"][
                "candidate_fre_aot_windows"
            ],
        )
        self.assertEqual(
            1,
            aggregate["candidate_discovery_accounting"][
                "receipts_with_first_candidate_midscan_cutover"
            ],
        )
        self.assertEqual(
            4,
            aggregate["stock_matcher_work_accounting"]["stock_span_calls"],
        )
        self.assertEqual(
            2,
            aggregate["stock_matcher_work_accounting"][
                "stock_capture_calls"
            ],
        )
        classification = aggregate["receipt_classification"]
        self.assertEqual(
            {HARNESS.COMPILED_OUTPUT_CONTRACT: 2},
            classification["compiled_output_contracts"],
        )
        self.assertEqual(
            {
                "complete_machine_reported": 1,
                "no_complete_machine_report": 1,
            },
            classification["compiled_state_reporting"],
        )
        self.assertEqual(
            17, classification["compiled_forward_states"]["total"]
        )

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

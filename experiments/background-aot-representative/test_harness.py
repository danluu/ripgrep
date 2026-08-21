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
        "exact_finite_selected_end_teddy_policy_v2_request": (
            "not_requested"
        ),
        "compile_receipt_v2": None,
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


def forced_exact_teddy_v2_ready_receipt(**overrides):
    lowering = exact_teddy_report_fixture()
    lowering["incumbent"].update({
        "has_accelerator": True,
        "scanner": "aarch64_sve",
    })
    report = {
        "authenticated_compiler_report": True,
        "schema_version": HARNESS.EXACT_TEDDY_V2_SCHEMA_VERSION,
        "requested_policy": "force_structurally_eligible",
        "selection_basis": "forced_structural_eligibility",
        "incumbent_source": "ordinary_public_complete_dfa",
        "incumbent_start_accelerator": "aarch64_sve",
        "incumbent_anchored_prefix_filter_bytes": 0,
        "performance_admission_bypassed": True,
        "tail_enters_exact_incumbent": True,
        "route_binding_sha256": "0" * 64,
        "lowering": lowering,
    }
    report["route_binding_sha256"] = (
        HARNESS.exact_teddy_v2_route_binding_sha256(report)
    )
    receipt = ready_receipt(
        exact_finite_selected_end_teddy_policy_v2_request=(
            "force_structurally_eligible"
        ),
        compile_receipt_v2={
            "schema_version": HARNESS.EXACT_TEDDY_V2_SCHEMA_VERSION,
            "optimizer_version": HARNESS.EXACT_TEDDY_V2_OPTIMIZER_VERSION,
            "exact_finite_selected_end_teddy_policy": (
                "force_structurally_eligible"
            ),
            "exact_finite_selected_end_teddy_aot_v2": report,
        },
        start_accelerator="aarch64_sve",
        compiled_state_source=(
            "exact_finite_selected_end_teddy_incumbent"
        ),
        compiled_forward_states=23,
        compiled_reverse_states=0,
        compiled_primary_native_route=HARNESS.EXACT_TEDDY_PRIMARY_ROUTE,
        exact_finite_selected_end_teddy_aot=None,
        published_read_only_data_bytes=372,
    )
    receipt.update(overrides)
    return receipt


def forced_exact_teddy_v2_nonselected_ready_receipt(**overrides):
    receipt = ready_receipt(
        exact_finite_selected_end_teddy_policy_v2_request=(
            "force_structurally_eligible"
        ),
        compile_receipt_v2={
            "schema_version": HARNESS.EXACT_TEDDY_V2_SCHEMA_VERSION,
            "optimizer_version": HARNESS.EXACT_TEDDY_V2_OPTIMIZER_VERSION,
            "exact_finite_selected_end_teddy_policy": (
                "force_structurally_eligible"
            ),
            "exact_finite_selected_end_teddy_aot_v2": None,
        },
        wait_requested=True,
        compiler_settled=True,
    )
    receipt.update(overrides)
    return receipt


def forced_exact_teddy_v2_compile_decline_receipt(**overrides):
    receipt = receipt_fixture(
        decline_reason="compile_object",
        publication_stage="compile",
        publication_refusal_class="compile_object",
        exact_finite_selected_end_teddy_policy_v2_request=(
            "force_structurally_eligible"
        ),
        compile_receipt_v2=None,
        wait_requested=True,
        compiler_settled=True,
    )
    receipt.update(overrides)
    return receipt


def synthetic_frozen_exact_teddy_v2_cases():
    semantics = {
        "matcher_mode": "regex",
        "regex_engine_request": "default",
        "case": "case_sensitive",
        "unicode": True,
    }
    return [
        HARNESS.QueryCase(
            private_id,
            (
                "frozen-oot-84"
                if private_id.startswith("oot-")
                else "frozen-unique-sample-128"
            ),
            "alpha|bravo|charlie|delta",
            1,
            None,
            semantics,
        )
        for private_id in sorted(
            HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_PRIVATE_IDS
        )
    ]


def run_result(receipt=None):
    empty = HARNESS.output_record(b"")
    return {
        "timed_out": False,
        "status": 1,
        "stdout": empty,
        "stderr": empty,
        "stdout_raw": b"",
        "stderr_raw": b"",
        "receipt": receipt,
        "receipt_parse_error": False,
        "unexpected_temporary_artifacts": 0,
    }


class HarnessTests(unittest.TestCase):
    def test_run_once_scrubs_control_environment(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            executable = root / "inspect-env"
            executable.write_text(
                "#!/bin/sh\n"
                "printf '%s|%s|%s|%s|%s|%s\\n' "
                '"${RG_FRE_AOT_BACKGROUND_RECEIPT+set}" '
                '"${RG_FRE_AOT_BACKGROUND_RECEIPT_WAIT_FOR_COMPILER-unset}" '
                '"${RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES-unset}" '
                '"${RG_FRE_AOT_BACKGROUND_CPU_PROFILE-unset}" '
                '"${RG_FRE_AOT_BACKGROUND_EXACT_TEDDY_POLICY_V2-unset}" '
                '"${RIPGREP_CONFIG_PATH-unset}"\n'
            )
            executable.chmod(0o700)
            inherited = {
                HARNESS.RECEIPT_ENV: "inherited-receipt",
                HARNESS.RECEIPT_WAIT_FOR_COMPILER_ENV: "inherited-wait",
                HARNESS.CORRECTNESS_GATE_ENV: "inherited-gate",
                HARNESS.CPU_PROFILE_ENV: "inherited-profile",
                HARNESS.EXACT_TEDDY_POLICY_V2_ENV: "inherited-force",
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
                forced = HARNESS.run_once(
                    binary=executable,
                    args=[],
                    cwd=root,
                    background=True,
                    capture_receipt=False,
                    cpu_profile="sve2",
                    timeout_seconds=5.0,
                    collect_timing=False,
                    exact_teddy_policy_v2=(
                        "force-structurally-eligible"
                    ),
                )
        self.assertEqual(
            b"|unset|unset|unset|unset|unset\n", normal["stdout_raw"]
        )
        self.assertEqual(
            b"|unset|123|sve|unset|unset\n", background["stdout_raw"]
        )
        self.assertEqual(
            b"set|1|unset|auto|unset|unset\n", settlement["stdout_raw"]
        )
        self.assertEqual(
            b"|unset|unset|sve2|force-structurally-eligible|unset\n",
            forced["stdout_raw"],
        )

    def test_v2_policy_cannot_be_set_on_a_nonbackground_arm(self) -> None:
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
                exact_teddy_policy_v2="automatic",
            )

    def test_timed_campaign_policy_is_only_on_the_background_arm(self) -> None:
        panel = HARNESS.Panel(
            HARNESS.EXACT_TEDDY_CENSUS_PANEL,
            Path("/unused-corpus"),
            "literal",
            None,
            True,
            1,
        )
        with mock.patch.object(
            HARNESS, "run_once", side_effect=lambda **kwargs: run_result()
        ) as run:
            HARNESS.run_pair(
                HARNESS.forced_exact_teddy_v2_gate_case(),
                panel,
                pair_index=0,
                candidate=Path("candidate"),
                stock=Path("stock"),
                cwd=Path("."),
                cpu_profile="auto",
                timeout_seconds=1.0,
                exact_teddy_policy_v2="force-structurally-eligible",
            )
        self.assertEqual(3, run.call_count)
        for call in run.call_args_list:
            if call.kwargs["background"]:
                self.assertEqual(
                    "force-structurally-eligible",
                    call.kwargs["exact_teddy_policy_v2"],
                )
            else:
                self.assertIsNone(call.kwargs["exact_teddy_policy_v2"])

    def test_fixed_v2_gate_is_untimed_settled_and_strict_for_force(self) -> None:
        panel = HARNESS.Panel(
            HARNESS.EXACT_TEDDY_CENSUS_PANEL,
            Path("/unused-corpus"),
            "literal",
            None,
            True,
            1,
        )

        def invoke(**kwargs):
            receipt = None
            if kwargs["background"]:
                receipt = forced_exact_teddy_v2_ready_receipt(
                    wait_requested=True,
                    compiler_settled=True,
                )
            return run_result(receipt)

        with mock.patch.object(
            HARNESS, "run_once", side_effect=invoke
        ) as run:
            gate = HARNESS.run_exact_teddy_v2_gate(
                panel=panel,
                candidate=Path("candidate"),
                stock=Path("stock"),
                cwd=Path("."),
                cpu_profile="auto",
                timeout_seconds=1.0,
                exact_teddy_policy_v2="force-structurally-eligible",
            )
        self.assertEqual(HARNESS.FORCED_EXACT_TEDDY_V2_GATE_PATTERN, gate["pattern"])
        self.assertEqual([], gate["failures"])
        for call in run.call_args_list:
            self.assertFalse(call.kwargs["collect_timing"])
            if call.kwargs["background"]:
                self.assertTrue(call.kwargs["wait_for_compiler_settlement"])
                self.assertEqual(
                    "force-structurally-eligible",
                    call.kwargs["exact_teddy_policy_v2"],
                )
            else:
                self.assertNotIn("exact_teddy_policy_v2", call.kwargs)
        for arm in ("normal", "background", "stock"):
            self.assertNotIn("elapsed_ns", gate[arm])

        gate["background"]["receipt"]["compile_receipt_v2"][
            "exact_finite_selected_end_teddy_aot_v2"
        ]["lowering"]["incumbent"]["has_accelerator"] = False
        self.assertIn(
            "exact_teddy_v2_incumbent_not_accelerated",
            HARNESS.validate_exact_teddy_v2_gate_record(
                gate, "auto", "force-structurally-eligible"
            ),
        )

    def test_provenance_subprocesses_also_scrub_v2_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(b"fixture")
            completed = mock.Mock(returncode=0, stdout="version\n")
            with (
                mock.patch.dict(
                    os.environ,
                    {HARNESS.EXACT_TEDDY_POLICY_V2_ENV: "inherited"},
                ),
                mock.patch.object(
                    HARNESS.subprocess, "run", return_value=completed
                ) as run,
            ):
                HARNESS.git_text(Path(directory), ("rev-parse", "HEAD"))
                HARNESS.binary_record(binary)
                HARNESS.command_version("rustc")
        self.assertEqual(3, run.call_count)
        for call in run.call_args_list:
            self.assertNotIn(
                HARNESS.EXACT_TEDDY_POLICY_V2_ENV,
                call.kwargs["env"],
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

    def test_structural_classifier_is_narrow_and_case_sensitive(self) -> None:
        gate = HARNESS.forced_exact_teddy_v2_gate_case()
        self.assertEqual(
            (b"samwise", b"samw", b"frodo", b"pippin"),
            HARNESS.structural_exact_teddy_v2_literals(gate),
        )
        self.assertEqual(
            (b"one.x", b"two(y", b"three]", b"four|z"),
            HARNESS.simple_exact_alternation_literals(
                r"one\.x|two\(y|three\]|four\|z"
            ),
        )
        rejected = (
            "alpha|bravo|charlie",
            "alpha||charlie|delta",
            "aa|bbb|ccc|ddd",
            "a.*b|bravo|charlie|delta",
            "(alpha|bravo|charlie|delta)",
            "[abc]|bravo|charlie|delta",
        )
        for pattern in rejected:
            with self.subTest(pattern=pattern):
                self.assertIsNone(
                    HARNESS.simple_exact_alternation_literals(pattern)
                )
        insensitive = HARNESS.QueryCase(
            "test", "test", HARNESS.FORCED_EXACT_TEDDY_V2_GATE_PATTERN,
            1, None, {"matcher_mode": "regex", "case": "ignore_case"},
        )
        self.assertIsNone(
            HARNESS.structural_exact_teddy_v2_literals(insensitive)
        )

    def test_frozen_structural_cohort_uses_immutable_ids_and_counts(self) -> None:
        source = synthetic_frozen_exact_teddy_v2_cases()
        semantics = source[0].semantics
        source.append(HARNESS.QueryCase(
            "oot-0001", "frozen-oot-84", "three|arms|only",
            1, None, semantics,
        ))
        expected_cohort = source[:-1]
        source_digest = HARNESS.manifest_digest(
            HARNESS.case_manifest(source)
        )
        cohort_digest = HARNESS.manifest_digest(
            HARNESS.case_manifest(expected_cohort)
        )
        with mock.patch.multiple(
            HARNESS,
            FROZEN_EXACT_TEDDY_V2_SOURCE_MANIFEST_SHA256=source_digest,
            FROZEN_EXACT_TEDDY_V2_STRUCTURAL_MANIFEST_SHA256=cohort_digest,
        ):
            cohort = HARNESS.frozen_exact_teddy_v2_structural_cohort(
                source
            )
            self.assertEqual(
                HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_COUNTS["total"],
                len(cohort),
            )
            self.assertEqual(
                HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_PRIVATE_IDS,
                {case.private_id for case in cohort},
            )
            self.assertEqual(
                HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_COUNTS["oot"],
                sum(case.private_id.startswith("oot-") for case in cohort),
            )
            self.assertEqual(
                HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_COUNTS["wider"],
                sum(case.private_id.startswith("wider-") for case in cohort),
            )

            changed = list(cohort)
            first = changed[0]
            changed[0] = HARNESS.QueryCase(
                first.private_id, first.cohort, first.pattern,
                first.occurrence_weight + 1, first.suffix, first.semantics,
                first.target_kind, first.extension_class,
            )
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.validate_frozen_exact_teddy_v2_structural_cohort(
                    changed
                )

            changed_source = list(source)
            last = changed_source[-1]
            changed_source[-1] = HARNESS.QueryCase(
                last.private_id, last.cohort, last.pattern,
                last.occurrence_weight + 1, last.suffix, last.semantics,
                last.target_kind, last.extension_class,
            )
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.frozen_exact_teddy_v2_structural_cohort(
                    changed_source
                )

    def test_force_stratum_id_digests_and_counts_recompute(self) -> None:
        selected = HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_PRIVATE_IDS
        nonselected = (
            HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_PRIVATE_IDS
        )
        self.assertFalse(selected & nonselected)
        self.assertEqual(
            HARNESS.FROZEN_EXACT_TEDDY_V2_STRUCTURAL_PRIVATE_IDS,
            selected | nonselected,
        )
        self.assertEqual(
            HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_IDS_SHA256,
            HARNESS.frozen_private_ids_digest(selected),
        )
        self.assertEqual(
            HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_IDS_SHA256,
            HARNESS.frozen_private_ids_digest(nonselected),
        )
        for private_ids, counts in (
            (
                selected,
                HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_COUNTS,
            ),
            (
                nonselected,
                HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_COUNTS,
            ),
        ):
            self.assertEqual(counts["total"], len(private_ids))
            self.assertEqual(
                counts["oot"],
                sum(value.startswith("oot-") for value in private_ids),
            )
            self.assertEqual(
                counts["wider"],
                sum(value.startswith("wider-") for value in private_ids),
            )

    def test_policy_campaign_record_binds_policy_and_exact_frozen_manifest(self) -> None:
        cases = synthetic_frozen_exact_teddy_v2_cases()
        manifest_sha256 = HARNESS.manifest_digest(
            HARNESS.case_manifest(cases)
        )
        selected_manifest_sha256 = HARNESS.manifest_digest(
            HARNESS.case_manifest([
                case for case in cases
                if case.private_id in (
                    HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_PRIVATE_IDS
                )
            ])
        )
        nonselected_manifest_sha256 = HARNESS.manifest_digest(
            HARNESS.case_manifest([
                case for case in cases
                if case.private_id in (
                    HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_PRIVATE_IDS
                )
            ])
        )
        with mock.patch.multiple(
            HARNESS,
            FROZEN_EXACT_TEDDY_V2_STRUCTURAL_MANIFEST_SHA256=(
                manifest_sha256
            ),
            FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_MANIFEST_SHA256=(
                selected_manifest_sha256
            ),
            FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_MANIFEST_SHA256=(
                nonselected_manifest_sha256
            ),
        ):
            automatic = HARNESS.exact_teddy_v2_campaign_record(
                "automatic", cases
            )
            forced = HARNESS.exact_teddy_v2_campaign_record(
                "force-structurally-eligible", cases
            )
        self.assertEqual(44, forced["selected_patterns"])
        self.assertEqual(
            manifest_sha256,
            forced["selection_manifest_sha256"],
        )
        self.assertEqual(
            HARNESS.FROZEN_EXACT_TEDDY_V2_SOURCE_MANIFEST_SHA256,
            forced["source_selection_manifest_sha256"],
        )
        self.assertNotEqual(
            automatic["exact_teddy_policy_v2"],
            forced["exact_teddy_policy_v2"],
        )
        self.assertEqual(
            "fixed_44_intention_to_treat", forced["primary_analysis"]
        )
        self.assertTrue(forced["result_blind"])
        self.assertFalse(forced["secondary_strata_result_blind"])
        self.assertEqual(
            34,
            forced["secondary_compiler_fact_strata"]
            [HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_COHORT]
            ["patterns"],
        )
        self.assertEqual(
            10,
            forced["secondary_compiler_fact_strata"]
            [HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_COHORT]
            ["patterns"],
        )
        oot = [case for case in cases if case.private_id.startswith("oot-")]
        wider = [
            case for case in cases if case.private_id.startswith("wider-")
        ]
        self.assertEqual(
            oot,
            HARNESS.cases_for_panel(
                "ripgrep-default-output", oot, wider, "automatic"
            ),
        )
        self.assertEqual(
            cases,
            HARNESS.cases_for_panel(
                HARNESS.EXACT_TEDDY_CENSUS_PANEL,
                oot,
                wider,
                "force-structurally-eligible",
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

    def test_v6_forced_teddy_receipt_requires_full_v2_attestation(self) -> None:
        receipt = forced_exact_teddy_v2_ready_receipt()
        self.assertEqual(
            [],
            HARNESS.validate_receipt(
                receipt,
                "auto",
                expected_exact_teddy_policy_v2=(
                    "force-structurally-eligible"
                ),
                require_forced_exact_teddy_v2=True,
            ),
        )
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.validate_receipt(
                receipt,
                "auto",
                require_forced_exact_teddy_v2=True,
            )
        corrupted_policy = copy.deepcopy(receipt)
        corrupted_policy[
            "exact_finite_selected_end_teddy_policy_v2_request"
        ] = "automatic"
        corrupted_failures = HARNESS.validate_receipt(
            corrupted_policy,
            "auto",
            expected_exact_teddy_policy_v2=(
                "force-structurally-eligible"
            ),
            require_forced_exact_teddy_v2=True,
        )
        self.assertIn(
            "exact_teddy_policy_v2_request_mismatch",
            corrupted_failures,
        )
        self.assertIn(
            "forced_exact_teddy_v2_policy_mismatch",
            corrupted_failures,
        )

        mutations = (
            (
                ("compile_receipt_v2", "optimizer_version"), 24,
                "compile_receipt_v2_optimizer_version",
            ),
            (
                (
                    "compile_receipt_v2",
                    "exact_finite_selected_end_teddy_aot_v2",
                    "selection_basis",
                ),
                "automatic_v1",
                "exact_teddy_v2_selection_basis_mismatch",
            ),
            (
                (
                    "compile_receipt_v2",
                    "exact_finite_selected_end_teddy_aot_v2",
                    "incumbent_source",
                ),
                "private_shortcut",
                "exact_teddy_v2_incumbent_source",
            ),
            (
                (
                    "compile_receipt_v2",
                    "exact_finite_selected_end_teddy_aot_v2",
                    "performance_admission_bypassed",
                ),
                False,
                "exact_teddy_v2_performance_bypass_attestation",
            ),
            (
                (
                    "compile_receipt_v2",
                    "exact_finite_selected_end_teddy_aot_v2",
                    "tail_enters_exact_incumbent",
                ),
                False,
                "exact_teddy_v2_tail_attestation",
            ),
            (
                (
                    "compile_receipt_v2",
                    "exact_finite_selected_end_teddy_aot_v2",
                    "lowering", "incumbent", "has_accelerator",
                ),
                False,
                "exact_teddy_v2_incumbent_not_accelerated",
            ),
        )
        for path, value, expected in mutations:
            with self.subTest(expected=expected):
                changed = copy.deepcopy(receipt)
                owner = changed
                for field in path[:-1]:
                    owner = owner[field]
                owner[path[-1]] = value
                self.assertIn(
                    expected,
                    HARNESS.validate_receipt(
                        changed,
                        "auto",
                        expected_exact_teddy_policy_v2=(
                            "force-structurally-eligible"
                        ),
                        require_forced_exact_teddy_v2=True,
                    ),
                )

    def test_v6_force_accepts_only_definitive_expected_nonselection(self) -> None:
        validation = {
            "require_current_schema": True,
            "require_compiler_settlement": True,
            "expected_exact_teddy_policy_v2": (
                "force-structurally-eligible"
            ),
            "require_forced_exact_teddy_v2_nonselection": True,
        }
        for receipt in (
            forced_exact_teddy_v2_nonselected_ready_receipt(),
            forced_exact_teddy_v2_compile_decline_receipt(),
        ):
            with self.subTest(outcome=receipt["outcome"]):
                self.assertEqual(
                    [], HARNESS.validate_receipt(receipt, "auto", **validation)
                )
                self.assertTrue(
                    HARNESS.definitive_forced_exact_teddy_v2_nonselection(
                        receipt
                    )
                )

        selected = forced_exact_teddy_v2_ready_receipt(
            wait_requested=True, compiler_settled=True,
        )
        failures = HARNESS.validate_receipt(
            selected, "auto", **validation
        )
        self.assertIn(
            "unexpected_forced_exact_teddy_v2_selection", failures
        )
        self.assertIn(
            "forced_exact_teddy_v2_nonselection_not_definitive", failures
        )

        ambiguous = forced_exact_teddy_v2_compile_decline_receipt(
            publication_stage="profile_gate",
            publication_refusal_class="target_profile_unavailable",
        )
        self.assertIn(
            "forced_exact_teddy_v2_nonselection_not_definitive",
            HARNESS.validate_receipt(ambiguous, "auto", **validation),
        )

        ready_case = HARNESS.QueryCase(
            "oot-0002", "frozen-oot-84", "private", 1, None, {}
        )
        decline_case = HARNESS.QueryCase(
            "wider-0121", "frozen-unique-sample-128", "private",
            1, None, {},
        )
        ready = forced_exact_teddy_v2_nonselected_ready_receipt()
        declined = forced_exact_teddy_v2_compile_decline_receipt()
        self.assertEqual(
            [],
            HARNESS.validate_frozen_forced_exact_teddy_v2_nonselection(
                ready_case, ready
            ),
        )
        self.assertEqual(
            [],
            HARNESS.validate_frozen_forced_exact_teddy_v2_nonselection(
                decline_case, declined
            ),
        )
        self.assertIn(
            "forced_exact_teddy_v2_expected_ready_ordered_dfa",
            HARNESS.validate_frozen_forced_exact_teddy_v2_nonselection(
                ready_case, declined
            ),
        )
        self.assertIn(
            "forced_exact_teddy_v2_expected_compile_object_decline",
            HARNESS.validate_frozen_forced_exact_teddy_v2_nonselection(
                decline_case, ready
            ),
        )

    def test_v6_forced_teddy_rejects_v1_leakage_and_binding_changes(self) -> None:
        receipt = forced_exact_teddy_v2_ready_receipt()
        receipt["exact_finite_selected_end_teddy_aot"] = (
            exact_teddy_report_fixture()
        )
        self.assertIn(
            "forced_exact_teddy_v1_receipt_leakage",
            HARNESS.validate_receipt(
                receipt,
                "auto",
                expected_exact_teddy_policy_v2=(
                    "force-structurally-eligible"
                ),
                require_forced_exact_teddy_v2=True,
            ),
        )

    def test_v6_explicit_policy_allows_only_precompile_null_supplement(self) -> None:
        early_decline = receipt_fixture(
            exact_finite_selected_end_teddy_policy_v2_request=(
                "force_structurally_eligible"
            ),
        )
        self.assertEqual(
            [],
            HARNESS.validate_receipt(
                early_decline,
                "auto",
                expected_exact_teddy_policy_v2=(
                    "force-structurally-eligible"
                ),
            ),
        )
        compiled_without_supplement = ready_receipt(
            exact_finite_selected_end_teddy_policy_v2_request=(
                "automatic"
            ),
            compile_receipt_v2=None,
        )
        self.assertIn(
            "compile_receipt_v2_required_after_compile",
            HARNESS.validate_receipt(
                compiled_without_supplement,
                "auto",
                expected_exact_teddy_policy_v2="automatic",
            ),
        )

        receipt = forced_exact_teddy_v2_ready_receipt()
        receipt["compile_receipt_v2"][
            "exact_finite_selected_end_teddy_aot_v2"
        ]["route_binding_sha256"] = "f" * 64
        self.assertIn(
            "exact_teddy_v2_route_binding_mismatch",
            HARNESS.validate_receipt(
                receipt,
                "auto",
                expected_exact_teddy_policy_v2=(
                    "force-structurally-eligible"
                ),
                require_forced_exact_teddy_v2=True,
            ),
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

    def test_legacy_v5_receipt_keeps_all_v5_invariants(self) -> None:
        receipt = exact_teddy_ready_receipt(
            schema=HARNESS.V5_RECEIPT_SCHEMA,
        )
        del receipt[
            "exact_finite_selected_end_teddy_policy_v2_request"
        ]
        del receipt["compile_receipt_v2"]
        self.assertEqual([], HARNESS.validate_receipt(receipt, "auto"))

        receipt["wait_requested"] = True
        receipt["compiler_settled"] = False
        receipt["compiled_primary_native_route"] = "ordered_dfa"
        failures = HARNESS.validate_receipt(receipt, "auto")
        self.assertIn("requested_compiler_not_settled", failures)
        self.assertIn("primary_native_route_state_mismatch", failures)
        self.assertIn("exact_teddy_report_on_non_teddy_route", failures)

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

    def test_exact_teddy_census_aborts_on_validation_failure(self) -> None:
        HARNESS.require_valid_exact_teddy_census_rows([
            {"private_id": "q1", "receipt_failures": []},
        ])
        with self.assertRaisesRegex(
            HARNESS.HarnessError, "malformed or unexpected"
        ):
            HARNESS.require_valid_exact_teddy_census_rows([
                {
                    "private_id": "q1",
                    "receipt_failures": ["malformed_receipt"],
                },
            ])

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

    def test_forced_midscan_gate_is_clock_free_and_still_validated(self) -> None:
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
        stdout_raw = HARNESS.forced_midscan_expected_stdout()
        stderr_raw = b""

        def invoke(**kwargs):
            return {
                "timed_out": False,
                "status": 0,
                "stdout": HARNESS.output_record(stdout_raw),
                "stderr": HARNESS.output_record(stderr_raw),
                "stdout_raw": stdout_raw,
                "stderr_raw": stderr_raw,
                "receipt": receipt if kwargs["background"] else None,
                "receipt_parse_error": False,
                "unexpected_temporary_artifacts": 0,
            }

        with mock.patch.object(
            HARNESS, "run_once", side_effect=invoke
        ) as run:
            gate = HARNESS.run_forced_midscan_gate(
                corpus=Path("corpus"),
                candidate=Path("candidate"),
                stock=Path("stock"),
                cwd=Path("."),
                cpu_profile="auto",
                timeout_seconds=1.0,
            )

        self.assertEqual(3, run.call_count)
        for call in run.call_args_list:
            self.assertIs(False, call.kwargs["collect_timing"])
        for arm in ("normal", "background", "stock"):
            for field in ("elapsed_ns", "user_ns", "system_ns"):
                self.assertNotIn(field, gate[arm])
        self.assertEqual([], gate["failures"])
        self.assertEqual(
            [], HARNESS.validate_forced_midscan_gate_record(gate, "auto")
        )

        gate["stock"]["stdout"] = HARNESS.output_record(b"wrong\n")
        self.assertIn(
            "forced_midscan_stock_evidence_mismatch",
            HARNESS.validate_forced_midscan_gate_record(gate, "auto"),
        )

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

    def test_v2_aggregate_keeps_fixed44_itt_and_both_strata(self) -> None:
        cases = synthetic_frozen_exact_teddy_v2_cases()
        by_id = {case.private_id: case for case in cases}

        def count(rows, ignored):
            return {"count": len(rows)}

        def aggregate(selected_cases):
            return HARNESS.aggregate_groups(
                [
                    {
                        "private_id": case.private_id,
                        "cohort": case.cohort,
                    }
                    for case in selected_cases
                ],
                by_id,
                count,
                include_exact_teddy_v2_force_strata=True,
            )

        all_rows = aggregate(cases)
        self.assertEqual(44, all_rows["all_selected"]["count"])
        strata = all_rows["by_compiler_fact_stratum"]
        self.assertEqual(
            34,
            strata[HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_COHORT]
            ["all_selected"]["count"],
        )
        self.assertEqual(
            10,
            strata[
                HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_COHORT
            ]["all_selected"]["count"],
        )

        oot_rows = aggregate([
            case for case in cases if case.private_id.startswith("oot-")
        ])["by_compiler_fact_stratum"]
        self.assertEqual(
            11,
            oot_rows[HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_SELECTED_COHORT]
            ["all_selected"]["count"],
        )
        self.assertEqual(
            3,
            oot_rows[
                HARNESS.FROZEN_EXACT_TEDDY_V2_FORCE_NONSELECTED_COHORT
            ]["all_selected"]["count"],
        )

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

import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from hai_mr05 import cli, dependency_runtime, local_orchestration, source_acquisition, verifier


class LocalOrchestrationRuntimeTests(unittest.TestCase):
    @staticmethod
    def _task():
        return {
            "schema_version": "1.0.0",
            "task_id": "mr22d-local-prepare",
            "task_type": "EVIDENCE_REVIEW",
            "task_text": "Review one explicitly supplied local public evidence file.",
            "requested_output_type": "EVIDENCE_REVIEW",
            "allowed_scope": ["inspect supplied data"],
            "prohibited_scope": ["execute external actions"],
            "human_constraints": {
                "approval_required": True,
                "no_execution": True,
                "no_external_side_effects": True,
                "trust_level": "LEVEL 0",
                "live_cloud_allowed": False,
                "local_model_source_authority": False,
            },
            "source_scope": {
                "approved_source_aliases": ["fixture"],
                "allowed_source_types": ["LOCAL_FILE"],
            },
            "risk_class_if_known": "UNKNOWN",
        }

    @staticmethod
    def _budget():
        return {
            "budget_identity": "c" * 64,
            "max_raw_bytes": 100000,
            "max_normalized_bytes": 100000,
            "max_package_bytes": 100000,
            "max_cloud_context_bytes": 100000,
            "byte_budget_policy_version": "1.0.0",
            "overflow_policy": "BLOCK_OR_DETERMINISTIC_REPACK",
            "silent_truncation": False,
        }

    @staticmethod
    def _token_metadata():
        return {
            "estimator_name": "non_whitespace_groups_div4",
            "estimator_version": "1.0.0",
            "input_bytes": 0,
            "estimated_tokens": 0,
            "confidence": "ADVISORY",
            "authority": "ADVISORY_ONLY",
        }

    @staticmethod
    def _pass_rule_ids():
        return tuple(sorted(rule.rule_id for rule in verifier.RULE_CATALOG))

    @classmethod
    def _kwargs(cls, root):
        return {
            "approved_source_root": str(root),
            "source_relative_path": "evidence.json",
            "source_alias": "fixture",
            "provenance_owner": "mr22d-test",
            "task": cls._task(),
            "classification": "PUBLIC",
            "content_kind": None,
            "source_observational_metadata": None,
            "discovery_max_bytes": 100000,
            "phase_id": "MR22D",
            "artifact_type": "EVIDENCE",
            "current_validity": "VALID",
            "supersession": "NONE",
            "mandatory": True,
            "metrics_raw_estimated_tokens": 0,
            "metrics_cloud_estimated_tokens": 0,
            "mr03_result_identity": "4" * 64,
            "mr04_result_identity": "5" * 64,
            "frozen_run_byte_budget": cls._budget(),
            "frozen_run_state": "VERIFIED_PASS_FOR_REVIEW",
            "frozen_run_observational_metadata": None,
            "disclosure_classification": "PUBLIC",
            "disclosure_findings": (),
            "disclosure_observational_metadata": None,
            "model_identifier": "openai/gpt-5.6-luna",
            "human_authorization_reference": "human-auth:mr22d-test",
            "estimated_token_metadata": cls._token_metadata(),
            "authorized_provider_identifier": "provider-fixture",
            "authorized_account_boundary_reference": "account://mr22d-fixture",
            "authorization_observational_metadata": None,
            "legacy_verifier_pass_rule_ids": cls._pass_rule_ids(),
        }

    def test_local_source_reaches_zero_send_prepare_with_exact_single_source_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "evidence.json").write_bytes(b'{"mr22d":1}')
            with mock.patch.object(
                source_acquisition,
                "capture_source",
                wraps=source_acquisition.capture_source,
            ) as capture, mock.patch.object(
                dependency_runtime,
                "invoke_mr03",
                side_effect=AssertionError("MR03 execution is not authorized"),
            ), mock.patch.object(
                dependency_runtime,
                "invoke_mr04",
                side_effect=AssertionError("MR04 execution is not authorized"),
            ):
                result = local_orchestration.orchestrate_local_prepare(**self._kwargs(root))
            self.assertEqual(capture.call_count, 1)
            self.assertEqual(result.prepared_workflow.execution_authority, "NONE")
            self.assertEqual(
                result.materialization_result.bounded_context_identity,
                result.prepared_workflow.bounded_context_record.context_identity,
            )
            self.assertEqual(
                result.materialization_result.frozen_run_identity,
                result.prepared_workflow.run_record.run_identity,
            )
            self.assertEqual(
                result.handoff_identity,
                result.prepared_workflow.cloud_execution_handoff_record.handoff_identity,
            )

    def test_local_orchestration_is_repeatable_for_unchanged_root_and_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "evidence.json").write_bytes(b'{"mr22d":1}')
            first = local_orchestration.orchestrate_local_prepare(**self._kwargs(root))
            second = local_orchestration.orchestrate_local_prepare(**self._kwargs(root))
            self.assertEqual(first.orchestration_identity, second.orchestration_identity)
            self.assertEqual(first.pre_send_identity, second.pre_send_identity)
            self.assertEqual(first.to_dict(), second.to_dict())

    def test_non_public_material_fails_before_source_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "evidence.json").write_bytes(b'{"mr22d":1}')
            kwargs = self._kwargs(root)
            kwargs["classification"] = "INTERNAL"
            with mock.patch.object(source_acquisition, "capture_source") as capture, self.assertRaises(
                local_orchestration.LocalPrepareOrchestrationError
            ):
                local_orchestration.orchestrate_local_prepare(**kwargs)
            capture.assert_not_called()

    def test_incomplete_verifier_pass_assertions_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "evidence.json").write_bytes(b'{"mr22d":1}')
            kwargs = self._kwargs(root)
            kwargs["legacy_verifier_pass_rule_ids"] = self._pass_rule_ids()[:-1]
            with self.assertRaisesRegex(
                local_orchestration.LocalPrepareOrchestrationError,
                "exact frozen rule catalog",
            ):
                local_orchestration.orchestrate_local_prepare(**kwargs)

    def test_local_prepare_cli_emits_zero_send_package(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "evidence.json").write_bytes(b'{"mr22d":1}')
            request = {
                "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
                "operation": cli.LOCAL_PREPARE_CLI_OPERATION,
                "local_prepare_arguments": self._kwargs(root),
            }
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = cli.main(
                [cli.LOCAL_PREPARE_CLI_COMMAND],
                stdin=io.StringIO(json.dumps(request)),
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(code, 0, stderr.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "PASS")
            self.assertEqual(payload["operation"], cli.LOCAL_PREPARE_CLI_OPERATION)
            self.assertEqual(payload["execution_authority"], "NONE")
            self.assertEqual(payload["filesystem_source_read_authority"], "APPROVED_ROOT_SINGLE_FILE_ONLY")
            self.assertFalse(payload["network_authority"])
            self.assertFalse(payload["model_provider_authority"])
            self.assertFalse(payload["dependency_execution_authority"])

    def test_authority_and_execution_counters_remain_bounded(self):
        self.assertEqual(local_orchestration.FILESYSTEM_SOURCE_READ_COUNT, 1)
        for name in (
            "FILESYSTEM_WRITE_COUNT",
            "DEPENDENCY_EXECUTION_COUNT",
            "SUBPROCESS_EXECUTION_COUNT",
            "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "HUMAN_APPROVAL_EXECUTION_COUNT",
            "HUMAN_DECISION_SIDE_EFFECT_COUNT",
            "STATE_TRANSITION_EXECUTION_COUNT",
            "GIT_OPERATION_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT",
        ):
            self.assertEqual(getattr(local_orchestration, name), 0, name)


if __name__ == "__main__":
    unittest.main()

import base64
import io
import json
from pathlib import Path
import tempfile
import unittest

from hai_mr05 import cli, proposal
from hai_mr05.failures import MR05PhaseNotImplementedError
import tests.test_final_result_runtime as _final_fixture_module


class OfflineCLIRuntimeTests(unittest.TestCase):
    @staticmethod
    def _request(approved_root: str) -> dict[str, object]:
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        proposal_record = chain["proposal"]
        raw = proposal.canonical_cloud_proposal_bytes(proposal_record)
        metadata = proposal_record.proposer_metadata
        verification = chain["verification"]
        disclosure_record = chain["disclosure"]
        metric_record = chain["metric"]
        arguments = {
            "run_record": chain["run"].to_dict(),
            "bounded_context_record": chain["bounded_context"].to_dict(),
            "disclosure_classification": disclosure_record.classification,
            "disclosure_findings": [item.to_dict() for item in disclosure_record.findings],
            "disclosure_observational_metadata": (
                None
                if disclosure_record.observational_metadata is None
                else dict(disclosure_record.observational_metadata)
            ),
            "metrics_raw_source_bytes": metric_record.raw_source_bytes,
            "metrics_normalized_bytes": metric_record.normalized_bytes,
            "metrics_package_bytes": metric_record.package_bytes,
            "metrics_cloud_context_bytes": metric_record.cloud_context_bytes,
            "metrics_raw_estimated_tokens": metric_record.raw_estimated_tokens,
            "metrics_cloud_estimated_tokens": metric_record.cloud_estimated_tokens,
            "metrics_model_call_count": metric_record.model_call_count,
            "metrics_model_retry_count": metric_record.model_retry_count,
            "metrics_failure_count": metric_record.failure_count,
            "metrics_source_ref_count": metric_record.source_ref_count,
            "metrics_missing_source_ref_count": metric_record.missing_source_ref_count,
            "metrics_identity_mismatch_count": metric_record.identity_mismatch_count,
            "metrics_observational_metadata": (
                None
                if not metric_record.observational_metadata
                else dict(metric_record.observational_metadata)
            ),
            "model_identifier": "openai/gpt-5.6-luna",
            "human_authorization_reference": "human-auth:offline-cli-fixture",
            "estimated_token_metadata": _final_fixture_module.FinalResultRuntimeTests._token_metadata(),
            "authorized_provider_identifier": "provider-fixture",
            "authorized_account_boundary_reference": "account://workflow-fixture",
            "authorization_observational_metadata": None,
            "provider_identifier": "provider-fixture",
            "actual_model_identifier": metadata.model_identifier,
            "provider_request_id": metadata.provider_request_id,
            "account_boundary_reference": "account://workflow-fixture",
            "provider_usage_if_available": (
                None
                if metadata.usage_if_available is None
                else dict(metadata.usage_if_available)
            ),
            "error_metadata": None,
            "legacy_verifier_checks": [item.to_dict() for item in chain["legacy"].checks],
            "verification_result": verification.verification_result,
            "verification_reason_codes": list(verification.reason_codes),
            "verification_reason_details": [item.to_dict() for item in verification.reason_details],
            "verification_verified_source_refs": [
                item.to_dict() for item in verification.verified_source_refs
            ],
            "verification_unsupported_claims": list(verification.unsupported_claims),
            "verification_missing_refs": list(verification.missing_refs),
            "verification_protected_content_findings": [
                item.to_dict() for item in verification.protected_content_findings
            ],
            "verification_identity_findings": [
                item.to_dict() for item in verification.identity_findings
            ],
            "verification_observational_metadata": (
                None
                if verification.observational_metadata is None
                else dict(verification.observational_metadata)
            ),
            "approved_root": approved_root,
            "manifest_relative_path": "offline/manifest.json",
            "final_result_relative_path": "offline/final.json",
            "verifier_failure_records": [item.to_dict() for item in chain["verifier_failures"]],
        }
        return {
            "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
            "operation": cli.OFFLINE_CLI_OPERATION,
            "workflow_arguments": arguments,
            "raw_provider_response_base64": base64.b64encode(raw).decode("ascii"),
        }

    def test_explicit_offline_command_composes_existing_workflow_and_persists_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "offline").mkdir()
            request = self._request(tmp)
            stdin = io.StringIO(json.dumps(request, ensure_ascii=False))
            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(cli.main(["offline"], stdin=stdin, stdout=stdout, stderr=stderr), 0)
            self.assertEqual(stderr.getvalue(), "")
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["status"], "PASS")
            self.assertEqual(summary["operation"], cli.OFFLINE_CLI_OPERATION)
            self.assertEqual(summary["execution_authority"], "NONE")
            self.assertFalse(summary["network_authority"])
            self.assertFalse(summary["model_provider_authority"])
            self.assertFalse(summary["human_approval_execution_authority"])
            self.assertFalse(summary["state_transition_execution_authority"])
            self.assertTrue(Path(tmp, "offline", "manifest.json").is_file())
            self.assertTrue(Path(tmp, "offline", "final.json").is_file())
            self.assertEqual(len(summary["final_result_identity"]), 64)
            self.assertEqual(len(summary["manifest_identity"]), 64)

    def test_offline_command_rejects_unknown_top_level_field_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = self._request(tmp)
            request["unexpected"] = True
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = cli.main(
                ["offline"],
                stdin=io.StringIO(json.dumps(request)),
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            failure = json.loads(stderr.getvalue())
            self.assertEqual(failure["status"], "FAIL_CLOSED")
            self.assertEqual(failure["error_type"], "OfflineCLIValidationError")
            self.assertFalse(Path(tmp, "offline", "manifest.json").exists())

    def test_offline_command_rejects_noncanonical_or_injected_raw_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = self._request(tmp)
            request["raw_provider_response_base64"] += "\n"
            stderr = io.StringIO()
            self.assertEqual(
                cli.main(
                    ["offline"],
                    stdin=io.StringIO(json.dumps(request)),
                    stdout=io.StringIO(),
                    stderr=stderr,
                ),
                2,
            )
            self.assertEqual(json.loads(stderr.getvalue())["status"], "FAIL_CLOSED")

        with tempfile.TemporaryDirectory() as tmp:
            request = self._request(tmp)
            request["workflow_arguments"]["raw_provider_response"] = "forbidden"
            stderr = io.StringIO()
            self.assertEqual(
                cli.main(
                    ["offline"],
                    stdin=io.StringIO(json.dumps(request)),
                    stdout=io.StringIO(),
                    stderr=stderr,
                ),
                2,
            )
            self.assertEqual(json.loads(stderr.getvalue())["status"], "FAIL_CLOSED")

    def test_legacy_cli_without_explicit_offline_command_remains_unavailable(self):
        with self.assertRaises(MR05PhaseNotImplementedError):
            cli.main([])

    def test_offline_cli_authority_surface_is_zero(self):
        self.assertEqual(cli.OFFLINE_CLI_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(cli.OFFLINE_CLI_INPUT_TRANSPORT, "STDIN_JSON_ONLY")
        self.assertEqual(cli.OFFLINE_CLI_RAW_RESPONSE_ENCODING, "BASE64_EXACT_BYTES")
        for name in (
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
            "DIRECT_FILESYSTEM_READ_COUNT",
            "DIRECT_FILESYSTEM_WRITE_COUNT",
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(cli, name), 0)


if __name__ == "__main__":
    unittest.main()

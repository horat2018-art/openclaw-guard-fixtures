import inspect
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import cloud_boundary, disclosure, evidence, failures, proposal, workflow
try:
    import tests.test_final_result_runtime as _final_fixture_module
except ModuleNotFoundError:
    import test_final_result_runtime as _final_fixture_module


class WorkflowRuntimeTests(unittest.TestCase):
    @staticmethod
    def _transport(chain, *, proposal_record=None):
        proposal_record = chain["proposal"] if proposal_record is None else proposal_record
        raw = proposal.canonical_cloud_proposal_bytes(proposal_record)
        metadata = proposal_record.proposer_metadata
        transport_metadata = {
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
        }
        return raw, transport_metadata

    @staticmethod
    def _compose(chain, **overrides):
        raw, transport_metadata = WorkflowRuntimeTests._transport(chain)
        args = {
            "run_record": chain["run"], "bounded_context_record": chain["bounded_context"],
            "disclosure_record": chain["disclosure"], "metrics_record": chain["metric"],
            "model_identifier": "openai/gpt-5.6-luna",
            "human_authorization_reference": "human-auth:final-result-fixture",
            "estimated_token_metadata": _final_fixture_module.FinalResultRuntimeTests._token_metadata(),
            "authorized_provider_identifier": "provider-fixture",
            "authorized_account_boundary_reference": "account://workflow-fixture",
            "authorization_observational_metadata": None,
            "raw_provider_response": raw,
            **transport_metadata,
            "legacy_verifier_result": chain["legacy"], "verification_record": chain["verification"],
            "manifest_relative_path": "manifest.json", "final_result_relative_path": "final.json",
            "verifier_failure_records": chain["verifier_failures"],
            "human_gate_record": chain["gate"], "human_decision_record": chain["decision"],
            "failure_record": chain["failure"],
        }
        if "approved_root" in overrides:
            args.update(overrides)
            return workflow.compose_top_level_workflow(**args)
        with tempfile.TemporaryDirectory() as tmp:
            args["approved_root"] = tmp
            args.update(overrides)
            return workflow.compose_top_level_workflow(**args)

    def test_exact_pass_chain_admits_transport_and_matches_authoritative_final_chain(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        expected = _final_fixture_module.FinalResultRuntimeTests._final(chain, composed.evidence_manifest)
        self.assertEqual(composed.cloud_context_record.context_identity, chain["cloud_context"].context_identity)
        self.assertEqual(composed.cloud_request_record.request_identity, chain["cloud_request"].request_identity)
        self.assertEqual(composed.proposal_record, chain["proposal"])
        self.assertEqual(composed.final_result.final_result_identity, expected.final_result_identity)
        self.assertEqual(composed.final_result.evidence_manifest_identity, composed.evidence_manifest.manifest_identity)
        self.assertEqual(composed.final_result.terminal_state, "VERIFIED_PASS_FOR_REVIEW")
        artifacts = {item.relative_path: item for item in composed.evidence_manifest.artifacts}
        self.assertEqual(artifacts["cloud/execution_authorization.json"].artifact_type, "mr05.cloud_execution_authorization")
        self.assertEqual(artifacts["cloud/response.json"].artifact_type, "mr05.cloud_response")
        self.assertEqual(artifacts["cloud/response.raw.json"].artifact_type, "mr05.cloud_proposal")
        self.assertEqual(artifacts["cloud/response.raw.json"].sha256, composed.cloud_response_record.raw_response_sha256)
        self.assertEqual(artifacts["cloud/response.raw.json"].byte_size, composed.cloud_response_record.raw_response_size_bytes)

    def test_governed_execution_authorization_builder_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = cloud_boundary.build_cloud_execution_authorization
        with mock.patch.object(
            cloud_boundary,
            "build_cloud_execution_authorization",
            side_effect=original,
        ) as delegated:
            composed = self._compose(
                chain,
                authorization_observational_metadata={"note": "workflow-bound"},
            )
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertEqual(call.args[0], composed.cloud_request_record)
        self.assertEqual(call.kwargs["provider_identifier"], "provider-fixture")
        self.assertEqual(
            call.kwargs["account_boundary_reference"],
            "account://workflow-fixture",
        )
        self.assertEqual(
            call.kwargs["observational_metadata"],
            {"note": "workflow-bound"},
        )
        self.assertEqual(
            dict(composed.cloud_execution_authorization_record.observational_metadata),
            {"note": "workflow-bound"},
        )

    def test_governed_external_transport_adapter_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = cloud_boundary.adapt_governed_external_transport_response
        with mock.patch.object(
            cloud_boundary,
            "adapt_governed_external_transport_response",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        self.assertEqual(composed.proposal_record, chain["proposal"])

    def test_final_evidence_persistence_is_exact_single_delegation_and_observational_only(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        calls = []
        original = evidence.persist_final_evidence_records

        def capture(**kwargs):
            calls.append(kwargs)
            return original(**kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "records").mkdir()
            with mock.patch.object(evidence, "persist_final_evidence_records", side_effect=capture) as delegated:
                composed = self._compose(
                    chain, approved_root=tmp,
                    manifest_relative_path="records/manifest.json",
                    final_result_relative_path="records/final.json",
                )
            delegated.assert_called_once()
            self.assertEqual(len(calls), 1)
            self.assertIs(calls[0]["manifest"], composed.evidence_manifest)
            self.assertIs(calls[0]["final_result"], composed.final_result)
            observed = composed.final_evidence_persistence_result
            self.assertIsInstance(observed, evidence.FinalEvidencePersistenceResult)
            self.assertEqual(observed.manifest_identity, composed.evidence_manifest.manifest_identity)
            self.assertEqual(observed.final_result_identity, composed.final_result.final_result_identity)
            self.assertEqual(Path(tmp, "records/manifest.json").read_bytes(), composed.evidence_manifest.canonical_bytes())
            final_bytes = evidence.canonical_final_result_bytes(
                composed.final_result, manifest=composed.evidence_manifest,
                **_final_fixture_module.FinalResultRuntimeTests._evidence_args(chain),
            )
            self.assertEqual(Path(tmp, "records/final.json").read_bytes(), final_bytes)
            self.assertFalse(
                observed.human_approval or observed.state_transition_authority
                or observed.source_write_authority or observed.git_authority
                or observed.model_provider_authority
            )

    def test_human_approved_chain_consumes_only_explicit_supplied_decision(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        composed = self._compose(chain)
        self.assertEqual(composed.human_decision_record.decision, "APPROVE")
        self.assertEqual(composed.final_result.human_decision_if_any, "APPROVE")
        self.assertEqual(composed.final_result.final_result_identity, _final_fixture_module.FinalResultRuntimeTests._final(chain, composed.evidence_manifest).final_result_identity)

    def test_human_terminal_state_without_explicit_decision_fails_closed(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaises(workflow.WorkflowCompositionError): self._compose(chain, human_decision_record=None)

    def test_verified_terminal_state_rejects_unsolicited_human_records(self):
        verified = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        human = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaises(workflow.WorkflowCompositionError): self._compose(verified, human_gate_record=human["gate"], human_decision_record=human["decision"])

    def test_legacy_controller_runrecord_is_never_implicitly_bridged(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        legacy_run = evidence.build_run_record(repository_commit="a"*40, task_identity="b"*64, contract_identities=("c"*64,), dependency_identities=("d"*64,), input_identities=("e"*64,))
        with self.assertRaisesRegex(workflow.WorkflowCompositionError, "controller RunRecord"): self._compose(chain, run_record=legacy_run)
        with self.assertRaises(workflow.WorkflowCompositionError): self._compose(chain, run_record=legacy_run.to_dict())

    def test_raw_proposal_request_binding_mismatch_preserves_admission_failure(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        wrong = _final_fixture_module.FinalResultRuntimeTests._proposal_with(chain["proposal"], request_identity="f"*64)
        raw, transport_metadata = self._transport(
            chain, proposal_record=wrong
        )
        with self.assertRaises(proposal.ProposalValidationError) as caught:
            self._compose(
                chain,
                raw_provider_response=raw,
                **transport_metadata,
            )
        self.assertEqual(caught.exception.failure_code, failures.FailureCode.PROPOSAL_PACKAGE_BINDING_MISMATCH.value)

    def test_authorized_provider_and_account_are_distinct_from_actual_transport_metadata(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        mutations = (
            ("authorized_provider_identifier", "provider-other"),
            ("authorized_account_boundary_reference", "account://workflow-other"),
        )
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(
                cloud_boundary.CloudResponseValidationError
            ) as caught:
                self._compose(chain, **{field: value})
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.MR05_MODEL_PROVIDER_ERROR.value,
            )

    def test_governed_transport_binding_mismatches_preserve_provider_error(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        mutations = (
            ("provider_identifier", "provider-other"),
            ("actual_model_identifier", "openai/gpt-other"),
            ("account_boundary_reference", "account://workflow-other"),
            ("error_metadata", {"provider_error": "denied"}),
        )
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(
                cloud_boundary.CloudResponseValidationError
            ) as caught:
                self._compose(chain, **{field: value})
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.MR05_MODEL_PROVIDER_ERROR.value,
            )

    def test_invalid_provider_bytes_fail_closed(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        raw = proposal.canonical_cloud_proposal_bytes(chain["proposal"])
        with self.assertRaises(cloud_boundary.CloudResponseValidationError) as caught:
            self._compose(chain, raw_provider_response=bytearray(raw))
        self.assertEqual(
            caught.exception.failure_code,
            failures.FailureCode.MR05_MODEL_PROVIDER_ERROR.value,
        )
        with self.assertRaises(proposal.ProposalValidationError):
            self._compose(chain, raw_provider_response=b"{not-valid-json")

    def test_transport_metadata_mismatch_preserves_proposal_binding_failure(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        mutations = (
            ("provider_request_id", "provider-request-other"),
            ("provider_usage_if_available", {"input_tokens": 999}),
        )
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(
                proposal.ProposalValidationError
            ) as caught:
                self._compose(chain, **{field: value})
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.PROPOSAL_PACKAGE_BINDING_MISMATCH.value,
            )

    def test_remaining_mr03_binding_is_still_enforced_by_workflow(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        wrong = _final_fixture_module.FinalResultRuntimeTests._proposal_with(chain["proposal"], bound_mr03_package_identity="f"*64)
        raw, transport_metadata = self._transport(
            chain, proposal_record=wrong
        )
        with self.assertRaisesRegex(
            workflow.WorkflowCompositionError, "bound_mr03_package_identity"
        ):
            self._compose(
                chain,
                raw_provider_response=raw,
                **transport_metadata,
            )

    def test_disclosure_denial_fails_before_cloud_request_composition(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain(); denied = disclosure.build_disclosure(classification="INTERNAL")
        with self.assertRaises(cloud_boundary.CloudContextAdmissionValidationError): self._compose(chain, disclosure_record=denied)

    def test_composition_is_repeatable_and_has_zero_execution_authority(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain(); first = self._compose(chain); second = self._compose(chain)
        self.assertEqual(first.final_result.final_result_identity, second.final_result.final_result_identity); self.assertEqual(first.evidence_manifest.manifest_identity, second.evidence_manifest.manifest_identity)
        for name in ("WORKFLOW_EXECUTION_COUNT","LIVE_CLOUD_EXECUTION_COUNT","NETWORK_IMPLEMENTATION_COUNT","PROVIDER_CLIENT_IMPLEMENTATION_COUNT","MODEL_CALL_IMPLEMENTATION_COUNT","MODEL_ROUTING_IMPLEMENTATION_COUNT","AUTH_IMPLEMENTATION_COUNT","AUTO_RETRY_IMPLEMENTATION_COUNT","AUTO_FALLBACK_IMPLEMENTATION_COUNT","HUMAN_APPROVAL_EXECUTION_COUNT","HUMAN_DECISION_SIDE_EFFECT_COUNT","STATE_TRANSITION_EXECUTION_COUNT"): self.assertEqual(getattr(workflow,name),0)
        self.assertEqual(workflow.WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT,1)

    def test_external_discontinuities_are_required_parameters(self):
        signature = inspect.signature(workflow.compose_top_level_workflow)
        self.assertNotIn("proposal_record", signature.parameters)
        self.assertNotIn("cloud_response_record", signature.parameters)
        self.assertNotIn("cloud_execution_authorization_record", signature.parameters)
        for name in (
            "authorized_provider_identifier",
            "authorized_account_boundary_reference",
            "authorization_observational_metadata",
            "raw_provider_response",
            "provider_identifier",
            "actual_model_identifier",
            "provider_request_id",
            "account_boundary_reference",
            "provider_usage_if_available",
            "error_metadata",
            "human_authorization_reference",
            "model_identifier",
            "verification_record",
            "approved_root",
            "manifest_relative_path",
            "final_result_relative_path",
        ):
            self.assertIs(signature.parameters[name].default, inspect.Parameter.empty)


if __name__ == "__main__":
    unittest.main()

import inspect
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import cloud_boundary, disclosure, evidence, failures, human_gate, proposal, verifier, workflow
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
        verification = chain["verification"]
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
            "legacy_verifier_result": chain["legacy"],
            "verification_result": verification.verification_result,
            "verification_reason_codes": verification.reason_codes,
            "verification_reason_details": tuple(
                item.to_dict() for item in verification.reason_details
            ),
            "verification_verified_source_refs": tuple(
                item.to_dict() for item in verification.verified_source_refs
            ),
            "verification_unsupported_claims": verification.unsupported_claims,
            "verification_missing_refs": verification.missing_refs,
            "verification_protected_content_findings": tuple(
                item.to_dict() for item in verification.protected_content_findings
            ),
            "verification_identity_findings": tuple(
                item.to_dict() for item in verification.identity_findings
            ),
            "verification_observational_metadata": (
                None
                if verification.observational_metadata is None
                else dict(verification.observational_metadata)
            ),
            "manifest_relative_path": "manifest.json", "final_result_relative_path": "final.json",
            "verifier_failure_records": chain["verifier_failures"],
            "failure_record": chain["failure"],
        }
        if chain["gate"] is not None:
            gate = chain["gate"]
            args.update({
                "human_gate_task_summary": gate.task_summary,
                "human_gate_proposal_summary": gate.proposal_summary,
                "human_gate_uncertainties": gate.uncertainties,
                "human_gate_evidence_pointers": gate.evidence_pointers,
                "human_gate_observational_metadata": (
                    None
                    if gate.observational_metadata is None
                    else dict(gate.observational_metadata)
                ),
            })
        if chain["decision"] is not None:
            decision = chain["decision"]
            args.update({
                "human_decision": decision.decision,
                "human_decision_reason": decision.decision_reason,
                "human_decision_scope": decision.decision_scope,
                "human_decision_authority_reference": decision.human_authority_reference,
                "human_decision_observational_metadata": (
                    None
                    if decision.observational_metadata is None
                    else dict(decision.observational_metadata)
                ),
            })
        if "approved_root" in overrides:
            args.update(overrides)
            return workflow.compose_top_level_workflow(**args)
        with tempfile.TemporaryDirectory() as tmp:
            args["approved_root"] = tmp
            args.update(overrides)
            return workflow.compose_top_level_workflow(**args)

    @staticmethod
    def _human_discontinuities(chain):
        supplied_gate = chain["gate"]
        supplied_decision = chain["decision"]
        if supplied_gate is None or supplied_decision is None:
            raise AssertionError("human discontinuity fixture requires gate and decision")
        proposal_record = chain["proposal"]
        verification_record = chain["verification"]
        context_record = chain["cloud_context"]
        gate_fields = {
            "run_identity": chain["run"].run_identity,
            "task_identity": proposal_record.task_identity,
            "proposal_identity": proposal_record.proposal_identity,
            "verification_identity": verification_record.verification_identity,
            "package_identity": proposal_record.bound_package_identity,
            "context_identity": context_record.context_identity,
            "task_summary": supplied_gate.task_summary,
            "proposal_summary": supplied_gate.proposal_summary,
            "verification_result": verification_record.verification_result,
            "reason_codes": verification_record.reason_codes,
            "source_refs": tuple(
                ref.to_dict() for ref in verification_record.verified_source_refs
            ),
            "uncertainties": supplied_gate.uncertainties,
            "evidence_pointers": supplied_gate.evidence_pointers,
        }
        if supplied_gate.observational_metadata is not None:
            gate_fields["observational_metadata"] = dict(
                supplied_gate.observational_metadata
            )
        expected_gate = human_gate.build_human_gate(**gate_fields)
        decision_fields = {
            "decision": supplied_decision.decision,
            "decision_reason": supplied_decision.decision_reason,
            "decision_scope": supplied_decision.decision_scope,
            "human_authority_reference": supplied_decision.human_authority_reference,
        }
        if supplied_decision.observational_metadata is not None:
            decision_fields["observational_metadata"] = dict(
                supplied_decision.observational_metadata
            )
        decision = human_gate.build_human_decision(
            human_gate=expected_gate,
            **decision_fields,
        )
        return expected_gate, decision

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

    def test_public_verification_builder_is_exact_single_delegation_and_adapter_receives_it(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original_builder = verifier.build_verification_record
        original_adapter = verifier.validate_verification_adapter
        with mock.patch.object(
            verifier,
            "build_verification_record",
            side_effect=original_builder,
        ) as builder, mock.patch.object(
            verifier,
            "validate_verification_adapter",
            side_effect=original_adapter,
        ) as adapter:
            composed = self._compose(chain)
        builder.assert_called_once()
        self.assertGreaterEqual(adapter.call_count, 1)
        build_call = builder.call_args
        self.assertFalse(build_call.args)
        self.assertEqual(build_call.kwargs["proposal"], composed.proposal_record)
        self.assertEqual(
            build_call.kwargs["verification_result"],
            chain["verification"].verification_result,
        )
        self.assertNotIn("proposal_identity", build_call.kwargs)
        self.assertEqual(composed.verification_record, chain["verification"])
        first_adapter_call = adapter.call_args_list[0]
        self.assertIs(first_adapter_call.args[0], composed.verification_record)
        self.assertEqual(first_adapter_call.kwargs["proposal"], composed.proposal_record)
        self.assertEqual(first_adapter_call.kwargs["context"], composed.cloud_context_record)

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

    def test_human_gate_builder_is_exact_single_delegation_for_human_terminal_state(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        expected_gate, _ = self._human_discontinuities(chain)
        original = human_gate.build_human_gate
        with mock.patch.object(
            human_gate,
            "build_human_gate",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertFalse(call.args)
        self.assertEqual(call.kwargs["run_identity"], chain["run"].run_identity)
        self.assertEqual(call.kwargs["proposal_identity"], composed.proposal_record.proposal_identity)
        self.assertEqual(call.kwargs["verification_identity"], composed.verification_record.verification_identity)
        self.assertEqual(call.kwargs["context_identity"], composed.cloud_context_record.context_identity)
        self.assertNotIn("human_action_options", call.kwargs)
        self.assertEqual(composed.human_gate_record, expected_gate)

    def test_verified_terminal_state_never_constructs_human_gate(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        with mock.patch.object(human_gate, "build_human_gate") as delegated:
            composed = self._compose(chain)
        delegated.assert_not_called()
        self.assertIsNone(composed.human_gate_record)

    def test_human_decision_builder_is_exact_single_delegation_for_human_terminal_state(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        expected_gate, expected_decision = self._human_discontinuities(chain)
        original = human_gate.build_human_decision
        with mock.patch.object(
            human_gate,
            "build_human_decision",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertFalse(call.args)
        self.assertEqual(call.kwargs["human_gate"], expected_gate)
        self.assertEqual(call.kwargs["decision"], expected_decision.decision)
        self.assertEqual(call.kwargs["decision_reason"], expected_decision.decision_reason)
        self.assertEqual(call.kwargs["decision_scope"], expected_decision.decision_scope)
        self.assertEqual(
            call.kwargs["human_authority_reference"],
            expected_decision.human_authority_reference,
        )
        self.assertNotIn("human_gate_identity", call.kwargs)
        self.assertEqual(composed.human_decision_record, expected_decision)

    def test_human_approved_chain_constructs_deterministic_decision(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        expected_gate, expected_decision = self._human_discontinuities(chain)
        composed = self._compose(chain)
        self.assertEqual(composed.human_gate_record, expected_gate)
        self.assertEqual(composed.human_decision_record, expected_decision)
        self.assertEqual(composed.human_decision_record.decision, "APPROVE")
        self.assertEqual(composed.final_result.human_decision_if_any, "APPROVE")
        expected_chain = dict(chain)
        expected_chain["gate"] = expected_gate
        expected_chain["decision"] = expected_decision
        self.assertEqual(
            composed.final_result.final_result_identity,
            _final_fixture_module.FinalResultRuntimeTests._final(
                expected_chain, composed.evidence_manifest
            ).final_result_identity,
        )

    def test_remaining_human_terminal_states_construct_bound_decisions(self):
        cases = (
            ("HUMAN_REJECTED", "REJECT"),
            ("HUMAN_REWORK", "REQUEST_REWORK"),
            ("HUMAN_MORE_EVIDENCE", "REQUEST_MORE_EVIDENCE"),
        )
        for state, action in cases:
            with self.subTest(state=state):
                chain = _final_fixture_module.FinalResultRuntimeTests._full_chain(state)
                expected_gate, expected_decision = self._human_discontinuities(chain)
                with mock.patch.object(
                    human_gate, "build_human_gate",
                    wraps=human_gate.build_human_gate,
                ) as gate_builder, mock.patch.object(
                    human_gate,
                    "build_human_decision",
                    wraps=human_gate.build_human_decision,
                ) as decision_builder:
                    composed = self._compose(chain)
                gate_builder.assert_called_once()
                decision_builder.assert_called_once()
                self.assertEqual(composed.human_gate_record, expected_gate)
                self.assertEqual(composed.human_decision_record, expected_decision)
                self.assertEqual(
                    composed.human_decision_record.human_gate_identity,
                    composed.human_gate_record.human_gate_identity,
                )
                self.assertEqual(composed.human_decision_record.decision, action)
                self.assertEqual(composed.final_result.terminal_state, state)
                self.assertEqual(composed.final_result.human_decision_if_any, action)
                expected_chain = dict(
                    chain,
                    gate=expected_gate,
                    decision=expected_decision,
                )
                expected_final = _final_fixture_module.FinalResultRuntimeTests._final(
                    expected_chain, composed.evidence_manifest
                )
                self.assertEqual(
                    composed.final_result.final_result_identity,
                    expected_final.final_result_identity,
                )

    def test_human_terminal_state_requires_complete_decision_construction_material(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with mock.patch.object(evidence, "persist_final_evidence_records") as persistence:
            for field in (
                "human_decision",
                "human_decision_reason",
                "human_decision_scope",
                "human_decision_authority_reference",
            ):
                with self.subTest(missing_field=field):
                    with self.assertRaisesRegex(
                        workflow.WorkflowCompositionError,
                        "complete Human Decision construction material",
                    ):
                        self._compose(chain, **{field: None})
            persistence.assert_not_called()

    def test_human_terminal_state_requires_complete_gate_construction_material(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaisesRegex(
            workflow.WorkflowCompositionError, "complete Human Gate construction material"
        ):
            self._compose(chain, human_gate_evidence_pointers=None)

    def test_verified_terminal_state_never_constructs_human_decision(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        with mock.patch.object(human_gate, "build_human_decision") as delegated:
            composed = self._compose(chain)
        delegated.assert_not_called()
        self.assertIsNone(composed.human_decision_record)

    def test_verified_terminal_state_rejects_human_gate_and_decision_material(self):
        verified = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        human = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaisesRegex(
            workflow.WorkflowCompositionError, "Human Gate construction material"
        ):
            self._compose(
                verified,
                human_gate_task_summary=human["gate"].task_summary,
            )
        with self.assertRaisesRegex(
            workflow.WorkflowCompositionError, "Human Decision construction material"
        ):
            self._compose(
                verified,
                human_decision=human["decision"].decision,
            )

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
        self.assertNotIn("human_gate_record", signature.parameters)
        self.assertNotIn("human_decision_record", signature.parameters)
        self.assertNotIn("verification_record", signature.parameters)
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
            "verification_result",
            "verification_reason_codes",
            "verification_reason_details",
            "verification_verified_source_refs",
            "verification_unsupported_claims",
            "verification_missing_refs",
            "verification_protected_content_findings",
            "verification_identity_findings",
            "verification_observational_metadata",
            "approved_root",
            "manifest_relative_path",
            "final_result_relative_path",
        ):
            self.assertIs(signature.parameters[name].default, inspect.Parameter.empty)


if __name__ == "__main__":
    unittest.main()

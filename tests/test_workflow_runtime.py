import inspect
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import canonical, cloud_boundary, disclosure, evidence, failures, human_gate, identity, metrics, proposal, verifier, workflow
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
        disclosure_record = chain["disclosure"]
        metric_record = chain["metric"]
        args = {
            "run_record": chain["run"], "bounded_context_record": chain["bounded_context"],
            "disclosure_classification": disclosure_record.classification,
            "disclosure_findings": tuple(item.to_dict() for item in disclosure_record.findings),
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
            "human_authorization_reference": "human-auth:final-result-fixture",
            "estimated_token_metadata": _final_fixture_module.FinalResultRuntimeTests._token_metadata(),
            "authorized_provider_identifier": "provider-fixture",
            "authorized_account_boundary_reference": "account://workflow-fixture",
            "authorization_observational_metadata": None,
            "raw_provider_response": raw,
            **transport_metadata,
            "legacy_verifier_checks": tuple(
                item.to_dict() for item in chain["legacy"].checks
            ),
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
        self.assertEqual(artifacts["cloud/execution_handoff.json"].artifact_type, "mr05.cloud_execution_handoff")
        self.assertEqual(
            artifacts["cloud/execution_handoff.json"].sha256,
            identity.sha256_bytes(composed.cloud_execution_handoff_record.canonical_bytes()),
        )
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

    def test_execution_handoff_builder_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = cloud_boundary.build_cloud_execution_handoff
        with mock.patch.object(
            cloud_boundary,
            "build_cloud_execution_handoff",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertEqual(call.args[0], composed.cloud_request_record)
        self.assertEqual(
            call.args[1], composed.cloud_execution_authorization_record
        )
        self.assertEqual(
            composed.cloud_execution_handoff_record.request_identity,
            composed.cloud_request_record.request_identity,
        )
        self.assertEqual(
            composed.cloud_execution_handoff_record.authorization_identity,
            composed.cloud_execution_authorization_record.authorization_identity,
        )
        self.assertEqual(
            composed.cloud_execution_handoff_record.execution_authority,
            "NONE",
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
        call = delegated.call_args
        self.assertEqual(call.args[0], composed.cloud_request_record)
        self.assertEqual(call.args[1], composed.cloud_execution_authorization_record)
        self.assertEqual(call.args[2], composed.cloud_execution_handoff_record)
        self.assertEqual(composed.proposal_record, chain["proposal"])

    def test_proposal_admission_is_exact_single_delegation_and_receives_handoff(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = proposal.admit_cloud_response_proposal
        with mock.patch.object(
            proposal,
            "admit_cloud_response_proposal",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertEqual(call.args[1], composed.cloud_response_record)
        self.assertEqual(call.args[2], composed.cloud_request_record)
        self.assertEqual(call.args[3], composed.cloud_execution_authorization_record)
        self.assertEqual(call.args[4], composed.cloud_execution_handoff_record)

    def test_disclosure_builder_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = disclosure.build_disclosure
        with mock.patch.object(
            disclosure,
            "build_disclosure",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertFalse(call.args)
        self.assertEqual(call.kwargs["classification"], chain["disclosure"].classification)
        self.assertEqual(
            call.kwargs["findings"],
            tuple(item.to_dict() for item in chain["disclosure"].findings),
        )
        self.assertEqual(composed.cloud_context_record.disclosure_result, "ALLOW")

    def test_metrics_builder_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = metrics.build_metrics
        with mock.patch.object(
            metrics,
            "build_metrics",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertFalse(call.args)
        self.assertEqual(call.kwargs["raw_source_bytes"], chain["metric"].raw_source_bytes)
        self.assertEqual(call.kwargs["cloud_context_bytes"], chain["metric"].cloud_context_bytes)
        self.assertNotIn("metrics_identity", call.kwargs)
        self.assertEqual(composed.final_result.metrics_identity, chain["metric"].metrics_identity)

    def test_legacy_verifier_builder_is_exact_single_delegation_and_derives_bindings(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = verifier.build_verifier_result
        with mock.patch.object(
            verifier,
            "build_verifier_result",
            side_effect=original,
        ) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        call = delegated.call_args
        self.assertFalse(call.args)
        expected_inputs = dict(chain["bounded_context"].input_identities)
        expected_inputs["context_identity"] = composed.cloud_context_record.context_identity
        self.assertEqual(call.kwargs["input_identities"], expected_inputs)
        self.assertEqual(
            call.kwargs["dependency_binding_identities"],
            chain["bounded_context"].dependency_binding_identities,
        )
        self.assertEqual(
            call.kwargs["provenance_identity"],
            chain["bounded_context"].provenance_identity,
        )
        self.assertEqual(call.kwargs["metrics_identity"], chain["metric"].metrics_identity)
        self.assertEqual(call.kwargs["contract_identities"], verifier.FROZEN_CONTRACT_IDENTITIES)
        self.assertEqual(
            call.kwargs["checks"],
            tuple(item.to_dict() for item in chain["legacy"].checks),
        )
        self.assertEqual(call.kwargs["failure_records"], chain["verifier_failures"])
        for forbidden in ("decision", "decision_reason_code", "verifier_identity"):
            self.assertNotIn(forbidden, call.kwargs)
        self.assertEqual(composed.final_result.metrics_identity, chain["legacy"].metrics_identity)

    def test_metrics_context_mismatch_fails_before_cloud_request_composition(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        with mock.patch.object(
            cloud_boundary,
            "build_cloud_request",
            wraps=cloud_boundary.build_cloud_request,
        ) as delegated:
            with self.assertRaisesRegex(workflow.WorkflowCompositionError, "Metrics"):
                self._compose(
                    chain,
                    metrics_raw_source_bytes=chain["metric"].raw_source_bytes + 1,
                )
        delegated.assert_not_called()

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
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        with self.assertRaises(cloud_boundary.CloudContextAdmissionValidationError):
            self._compose(chain, disclosure_classification="INTERNAL")

    def test_composition_is_repeatable_and_has_zero_execution_authority(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain(); first = self._compose(chain); second = self._compose(chain)
        self.assertEqual(first.final_result.final_result_identity, second.final_result.final_result_identity); self.assertEqual(first.evidence_manifest.manifest_identity, second.evidence_manifest.manifest_identity)
        for name in ("WORKFLOW_EXECUTION_COUNT","LIVE_CLOUD_EXECUTION_COUNT","NETWORK_IMPLEMENTATION_COUNT","PROVIDER_CLIENT_IMPLEMENTATION_COUNT","MODEL_CALL_IMPLEMENTATION_COUNT","MODEL_ROUTING_IMPLEMENTATION_COUNT","AUTH_IMPLEMENTATION_COUNT","AUTO_RETRY_IMPLEMENTATION_COUNT","AUTO_FALLBACK_IMPLEMENTATION_COUNT","HUMAN_APPROVAL_EXECUTION_COUNT","HUMAN_DECISION_SIDE_EFFECT_COUNT","STATE_TRANSITION_EXECUTION_COUNT"): self.assertEqual(getattr(workflow,name),0)
        self.assertEqual(workflow.WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT,1)

    def test_workflow_composition_validator_accepts_exact_composed_result(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        self.assertIs(workflow.validate_workflow_composition_result(composed), composed)
        self.assertEqual(workflow.WORKFLOW_COMPOSITION_VALIDATION_IMPLEMENTATION_COUNT, 1)

    def test_workflow_composition_validator_is_exact_single_delegation(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        original = workflow.validate_workflow_composition_result
        with mock.patch.object(workflow, "validate_workflow_composition_result", side_effect=original) as delegated:
            composed = self._compose(chain)
        delegated.assert_called_once()
        self.assertIs(delegated.call_args.args[0], composed)

    def test_workflow_composition_validator_rejects_cross_bound_handoff(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        other_authorization = cloud_boundary.build_cloud_execution_authorization(
            composed.cloud_request_record,
            provider_identifier="provider-other",
            account_boundary_reference="account://workflow-fixture",
        )
        other_handoff = cloud_boundary.build_cloud_execution_handoff(composed.cloud_request_record, other_authorization)
        tampered = replace(composed, cloud_execution_handoff_record=other_handoff)
        with self.assertRaises(workflow.WorkflowCompositionError):
            workflow.validate_workflow_composition_result(tampered)

    def test_workflow_composition_validator_rejects_handoff_manifest_tamper(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        artifacts=list(composed.evidence_manifest.artifacts)
        index=next(i for i,a in enumerate(artifacts) if a.relative_path == "cloud/execution_handoff.json")
        current=artifacts[index]
        artifacts[index]=evidence.FrozenEvidenceArtifact(relative_path=current.relative_path, byte_size=current.byte_size, sha256="f"*64, artifact_type=current.artifact_type, schema_version=current.schema_version)
        tampered_manifest=evidence.FrozenEvidenceManifest(run_identity=composed.evidence_manifest.run_identity, artifacts=tuple(artifacts), observational_metadata=dict(composed.evidence_manifest.observational_metadata))
        tampered=replace(composed, evidence_manifest=tampered_manifest)
        with self.assertRaises(workflow.WorkflowCompositionError):
            workflow.validate_workflow_composition_result(tampered)

    def test_workflow_composition_validator_rejects_persistence_identity_tamper(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        tampered_persistence=replace(composed.final_evidence_persistence_result, manifest_identity="f"*64)
        tampered=replace(composed, final_evidence_persistence_result=tampered_persistence)
        with self.assertRaises(workflow.WorkflowCompositionError):
            workflow.validate_workflow_composition_result(tampered)

    @staticmethod
    def _reseal_composed_result_for_manifest(composed, manifest):
        original = composed.final_result
        final_result = evidence.FinalResultRecord(
            run_identity=original.run_identity,
            terminal_state=original.terminal_state,
            verification_result=original.verification_result,
            human_decision_if_any=original.human_decision_if_any,
            failure_if_any=original.failure_if_any,
            proposal_identity_if_any=original.proposal_identity_if_any,
            evidence_manifest_identity=manifest.manifest_identity,
            metrics_identity=original.metrics_identity,
            observational_metadata=dict(original.observational_metadata),
            schema_version=original.schema_version,
        )
        manifest_bytes = manifest.canonical_bytes()
        final_bytes = canonical.canonical_json_bytes(final_result.to_dict(), identity_critical=False)
        persistence = replace(
            composed.final_evidence_persistence_result,
            manifest_identity=manifest.manifest_identity,
            final_result_identity=final_result.final_result_identity,
            manifest_content_sha256=identity.sha256_bytes(manifest_bytes),
            manifest_byte_count=len(manifest_bytes),
            final_result_content_sha256=identity.sha256_bytes(final_bytes),
            final_result_byte_count=len(final_bytes),
        )
        return replace(
            composed,
            evidence_manifest=manifest,
            final_result=final_result,
            final_evidence_persistence_result=persistence,
        )

    def test_workflow_validator_rejects_resealed_exposed_record_manifest_tamper(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        for target in (
            "run/run.json",
            "cloud/context.json",
            "cloud/request.json",
            "proposal/proposal.json",
            "verification/verification.json",
        ):
            with self.subTest(target=target):
                artifacts=list(composed.evidence_manifest.artifacts)
                index=next(i for i,a in enumerate(artifacts) if a.relative_path == target)
                current=artifacts[index]
                forged_sha="0"*64 if current.sha256 != "0"*64 else "1"*64
                artifacts[index]=evidence.FrozenEvidenceArtifact(
                    relative_path=current.relative_path,
                    byte_size=current.byte_size,
                    sha256=forged_sha,
                    artifact_type=current.artifact_type,
                    schema_version=current.schema_version,
                )
                manifest=evidence.FrozenEvidenceManifest(
                    run_identity=composed.evidence_manifest.run_identity,
                    artifacts=tuple(artifacts),
                    observational_metadata=dict(composed.evidence_manifest.observational_metadata),
                )
                tampered=self._reseal_composed_result_for_manifest(composed, manifest)
                with self.assertRaises(workflow.WorkflowCompositionError):
                    workflow.validate_workflow_composition_result(tampered)

    def test_workflow_validator_rejects_resealed_human_manifest_tamper(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        composed = self._compose(chain)
        for target in ("human_gate/human_gate.json", "human_gate/human_decision.json"):
            with self.subTest(target=target):
                artifacts=list(composed.evidence_manifest.artifacts)
                index=next(i for i,a in enumerate(artifacts) if a.relative_path == target)
                current=artifacts[index]
                forged_sha="0"*64 if current.sha256 != "0"*64 else "1"*64
                artifacts[index]=evidence.FrozenEvidenceArtifact(
                    relative_path=current.relative_path,
                    byte_size=current.byte_size,
                    sha256=forged_sha,
                    artifact_type=current.artifact_type,
                    schema_version=current.schema_version,
                )
                manifest=evidence.FrozenEvidenceManifest(
                    run_identity=composed.evidence_manifest.run_identity,
                    artifacts=tuple(artifacts),
                    observational_metadata=dict(composed.evidence_manifest.observational_metadata),
                )
                tampered=self._reseal_composed_result_for_manifest(composed, manifest)
                with self.assertRaises(workflow.WorkflowCompositionError):
                    workflow.validate_workflow_composition_result(tampered)

    def test_external_discontinuities_are_required_parameters(self):
        signature = inspect.signature(workflow.compose_top_level_workflow)
        self.assertNotIn("proposal_record", signature.parameters)
        self.assertNotIn("cloud_response_record", signature.parameters)
        self.assertNotIn("cloud_execution_authorization_record", signature.parameters)
        self.assertNotIn("human_gate_record", signature.parameters)
        self.assertNotIn("human_decision_record", signature.parameters)
        self.assertNotIn("verification_record", signature.parameters)
        self.assertNotIn("disclosure_record", signature.parameters)
        self.assertNotIn("metrics_record", signature.parameters)
        self.assertNotIn("legacy_verifier_result", signature.parameters)
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
            "disclosure_classification",
            "disclosure_findings",
            "disclosure_observational_metadata",
            "metrics_raw_source_bytes",
            "metrics_normalized_bytes",
            "metrics_package_bytes",
            "metrics_cloud_context_bytes",
            "metrics_raw_estimated_tokens",
            "metrics_cloud_estimated_tokens",
            "metrics_model_call_count",
            "metrics_model_retry_count",
            "metrics_failure_count",
            "metrics_source_ref_count",
            "metrics_missing_source_ref_count",
            "metrics_identity_mismatch_count",
            "metrics_observational_metadata",
            "legacy_verifier_checks",
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

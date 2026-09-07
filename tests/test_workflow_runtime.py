import inspect
import unittest

from hai_mr05 import cloud_boundary, disclosure, evidence, workflow
try:
    import tests.test_final_result_runtime as _final_fixture_module
except ModuleNotFoundError:
    import test_final_result_runtime as _final_fixture_module


class WorkflowRuntimeTests(unittest.TestCase):
    @staticmethod
    def _compose(chain, **overrides):
        args = {
            "run_record": chain["run"],
            "bounded_context_record": chain["bounded_context"],
            "disclosure_record": chain["disclosure"],
            "metrics_record": chain["metric"],
            "model_identifier": "openai/gpt-5.6-luna",
            "human_authorization_reference": "human-auth:final-result-fixture",
            "estimated_token_metadata": _final_fixture_module.FinalResultRuntimeTests._token_metadata(),
            "proposal_record": chain["proposal"],
            "legacy_verifier_result": chain["legacy"],
            "verification_record": chain["verification"],
            "verifier_failure_records": chain["verifier_failures"],
            "human_gate_record": chain["gate"],
            "human_decision_record": chain["decision"],
            "failure_record": chain["failure"],
        }
        args.update(overrides)
        return workflow.compose_top_level_workflow(**args)

    def test_exact_pass_chain_matches_existing_authoritative_chain(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        composed = self._compose(chain)
        expected = _final_fixture_module.FinalResultRuntimeTests._final(chain)
        self.assertEqual(composed.cloud_context_record.context_identity, chain["cloud_context"].context_identity)
        self.assertEqual(composed.cloud_request_record.request_identity, chain["cloud_request"].request_identity)
        self.assertEqual(composed.evidence_manifest.manifest_identity, _final_fixture_module.FinalResultRuntimeTests._manifest(chain).manifest_identity)
        self.assertEqual(composed.final_result.final_result_identity, expected.final_result_identity)
        self.assertEqual(composed.final_result.terminal_state, "VERIFIED_PASS_FOR_REVIEW")

    def test_human_approved_chain_consumes_only_explicit_supplied_decision(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        composed = self._compose(chain)
        self.assertEqual(composed.human_decision_record.decision, "APPROVE")
        self.assertEqual(composed.final_result.human_decision_if_any, "APPROVE")
        self.assertEqual(composed.final_result.final_result_identity, _final_fixture_module.FinalResultRuntimeTests._final(chain).final_result_identity)

    def test_human_terminal_state_without_explicit_decision_fails_closed(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaises(workflow.WorkflowCompositionError):
            self._compose(chain, human_decision_record=None)

    def test_verified_terminal_state_rejects_unsolicited_human_records(self):
        verified = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        human = _final_fixture_module.FinalResultRuntimeTests._full_chain("HUMAN_APPROVED")
        with self.assertRaises(workflow.WorkflowCompositionError):
            self._compose(
                verified,
                human_gate_record=human["gate"],
                human_decision_record=human["decision"],
            )

    def test_legacy_controller_runrecord_is_never_implicitly_bridged(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        legacy_run = evidence.build_run_record(
            repository_commit="a" * 40,
            task_identity="b" * 64,
            contract_identities=("c" * 64,),
            dependency_identities=("d" * 64,),
            input_identities=("e" * 64,),
        )
        with self.assertRaisesRegex(workflow.WorkflowCompositionError, "controller RunRecord"):
            self._compose(chain, run_record=legacy_run)
        with self.assertRaises(workflow.WorkflowCompositionError):
            self._compose(chain, run_record=legacy_run.to_dict())

    def test_supplied_proposal_must_bind_to_composed_request(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        wrong = _final_fixture_module.FinalResultRuntimeTests._proposal_with(chain["proposal"], request_identity="f" * 64)
        with self.assertRaisesRegex(workflow.WorkflowCompositionError, "request_identity"):
            self._compose(chain, proposal_record=wrong)

    def test_disclosure_denial_fails_before_cloud_request_composition(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        denied = disclosure.build_disclosure(classification="INTERNAL")
        with self.assertRaises(cloud_boundary.CloudContextAdmissionValidationError):
            self._compose(chain, disclosure_record=denied)

    def test_composition_is_repeatable_and_has_zero_execution_authority(self):
        chain = _final_fixture_module.FinalResultRuntimeTests._full_chain()
        first = self._compose(chain)
        second = self._compose(chain)
        self.assertEqual(first.final_result.final_result_identity, second.final_result.final_result_identity)
        self.assertEqual(first.evidence_manifest.manifest_identity, second.evidence_manifest.manifest_identity)
        for name in (
            "WORKFLOW_EXECUTION_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT",
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
        ):
            self.assertEqual(getattr(workflow, name), 0)
        self.assertEqual(workflow.WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT, 1)

    def test_external_discontinuities_are_required_parameters(self):
        signature = inspect.signature(workflow.compose_top_level_workflow)
        self.assertIs(signature.parameters["proposal_record"].default, inspect.Parameter.empty)
        self.assertIs(signature.parameters["human_authorization_reference"].default, inspect.Parameter.empty)
        self.assertIs(signature.parameters["model_identifier"].default, inspect.Parameter.empty)
        self.assertIs(signature.parameters["verification_record"].default, inspect.Parameter.empty)


if __name__ == "__main__":
    unittest.main()
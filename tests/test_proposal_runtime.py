import copy
import inspect
import json
import unittest

from hai_mr05 import failures, identity, proposal


class ProposalRuntimeTests(unittest.TestCase):
    def _source_ref(self, digit: str, locator: str):
        return {
            "source_id": digit * 64,
            "canonical_locator": locator,
            "content_sha256": ("a" if digit != "a" else "b") * 64,
            "content_size_bytes": 100,
            "source_set_identity": "8" * 64,
        }

    def _semantic(self):
        ref1 = self._source_ref("1", "capture/a.json")
        ref2 = self._source_ref("2", "capture/b.json")
        return {
            "schema_version": "1.0.0",
            "request_identity": "1" * 64,
            "run_identity": "2" * 64,
            "task_identity": "3" * 64,
            "bound_mr03_package_identity": "4" * 64,
            "bound_mr04_result_identity": "5" * 64,
            "bound_context_identity": "6" * 64,
            "claims": [
                {
                    "claim_id": "claim-001",
                    "claim_type": "FACT",
                    "claim_text_or_structured_value": {"value": "alpha"},
                    "source_refs": [copy.deepcopy(ref1)],
                    "confidence_or_uncertainty": {"level": "HIGH", "basis": "structured evidence"},
                },
                {
                    "claim_id": "claim-002",
                    "claim_type": "FACT",
                    "claim_text_or_structured_value": ["beta", {"value": 2}],
                    "source_refs": [copy.deepcopy(ref2)],
                    "confidence_or_uncertainty": {"level": "MEDIUM", "basis": "bounded evidence"},
                },
            ],
            "source_refs": [copy.deepcopy(ref1), copy.deepcopy(ref2)],
            "recommendation": {"kind": "SUMMARY", "content": {"next": "review"}},
            "uncertainty": {"level": "LOW", "items": ["presentation-only nuance"]},
            "escalation_flags": ["EVIDENCE_GAP", "HUMAN_REVIEW"],
        }

    def _record(self, **overrides):
        semantic = self._semantic()
        for key, value in overrides.items():
            if key in semantic:
                semantic[key] = copy.deepcopy(value)
        proposal_identity = identity.sha256_canonical(semantic)
        record = copy.deepcopy(semantic)
        record.update({
            "proposal_id": proposal_identity,
            "proposal_identity": proposal_identity,
            "bound_package_identity": overrides.get("bound_package_identity", "7" * 64),
            "proposer_metadata": copy.deepcopy(overrides.get("proposer_metadata", {
                "model_identifier": "openai/gpt-5.6-luna",
                "provider_request_id": "provider-request-1",
                "attempt_number": 1,
                "usage_if_available": {"input_tokens": 10, "ratio": 0.5},
            })),
            "free_form_prose": overrides.get("free_form_prose", "presentation only"),
            "observational_metadata": copy.deepcopy(overrides.get("observational_metadata", {"latency_ms": 12})),
        })
        return record

    def test_exact_frozen_record_and_authoritative_identity_preimage(self):
        record = proposal.CloudProposal.from_mapping(self._record())
        self.assertEqual(set(record.to_dict()), {
            "schema_version", "proposal_id", "proposal_identity", "request_identity",
            "run_identity", "task_identity", "bound_package_identity",
            "bound_context_identity", "bound_mr03_package_identity",
            "bound_mr04_result_identity", "claims", "source_refs", "recommendation",
            "uncertainty", "escalation_flags", "proposer_metadata", "free_form_prose",
            "observational_metadata",
        })
        self.assertEqual(tuple(record.identity_payload), proposal.PROPOSAL_IDENTITY_PREIMAGE)
        self.assertEqual(record.proposal_identity, identity.sha256_canonical(record.identity_payload))
        self.assertEqual(record.proposal_id, record.proposal_identity)
        self.assertEqual(proposal.compute_proposal_identity(record), record.proposal_identity)
        for field in proposal.PROPOSAL_IDENTITY_EXCLUSIONS:
            self.assertNotIn(field, record.identity_payload)

    def test_excluded_record_and_transport_metadata_do_not_change_identity(self):
        first = proposal.CloudProposal.from_mapping(self._record())
        second = proposal.CloudProposal.from_mapping(self._record(
            bound_package_identity="f" * 64,
            proposer_metadata={
                "model_identifier": "other-model",
                "provider_request_id": "other-provider-id",
                "attempt_number": 9,
                "usage_if_available": {"cost_ratio": 1.25},
            },
            free_form_prose="different presentation",
            observational_metadata={"latency_ms": 999, "fraction": 0.25},
        ))
        self.assertEqual(first.proposal_identity, second.proposal_identity)
        self.assertNotEqual(first.canonical_bytes(), second.canonical_bytes())

    def test_each_core_binding_or_semantic_mutation_changes_identity(self):
        base = proposal.CloudProposal.from_mapping(self._record())
        mutations = {
            "request_identity": "a" * 64,
            "run_identity": "b" * 64,
            "task_identity": "c" * 64,
            "bound_mr03_package_identity": "d" * 64,
            "bound_mr04_result_identity": "e" * 64,
            "bound_context_identity": "f" * 64,
            "recommendation": {"kind": "NONE", "content": ""},
            "uncertainty": {"level": "HIGH", "items": ["new"]},
            "escalation_flags": ["EVIDENCE_GAP", "HUMAN_REVIEW", "REWORK"],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = proposal.CloudProposal.from_mapping(self._record(**{field: value}))
                self.assertNotEqual(base.proposal_identity, changed.proposal_identity)

    def test_claim_mutation_changes_identity(self):
        base_record = self._record()
        changed_claims = copy.deepcopy(base_record["claims"])
        changed_claims[0]["claim_text_or_structured_value"] = {"value": "changed"}
        changed = proposal.CloudProposal.from_mapping(self._record(claims=changed_claims))
        base = proposal.CloudProposal.from_mapping(base_record)
        self.assertNotEqual(base.proposal_identity, changed.proposal_identity)

    def test_proposal_id_and_identity_must_both_equal_recomputed_identity(self):
        forged_identity = self._record()
        forged_identity["proposal_identity"] = "0" * 64
        with self.assertRaises(proposal.ProposalValidationError) as caught_identity:
            proposal.CloudProposal.from_mapping(forged_identity)
        self.assertEqual(caught_identity.exception.failure_code, failures.FailureCode.HASH_MISMATCH.value)
        forged_id = self._record()
        forged_id["proposal_id"] = "0" * 64
        with self.assertRaises(proposal.ProposalValidationError) as caught_id:
            proposal.CloudProposal.from_mapping(forged_id)
        self.assertEqual(caught_id.exception.failure_code, failures.FailureCode.HASH_MISMATCH.value)

    def test_unknown_missing_extra_and_unknown_major_fail_closed(self):
        extra = self._record()
        extra["approval"] = True
        with self.assertRaises(proposal.ProposalValidationError):
            proposal.CloudProposal.from_mapping(extra)
        missing = self._record()
        del missing["proposer_metadata"]
        with self.assertRaises(proposal.ProposalValidationError):
            proposal.CloudProposal.from_mapping(missing)
        major = self._record()
        major["schema_version"] = "2.0.0"
        with self.assertRaises(proposal.ProposalValidationError) as caught:
            proposal.CloudProposal.from_mapping(major)
        self.assertEqual(caught.exception.failure_code, failures.FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value)

    def test_set_like_arrays_must_arrive_in_frozen_order_without_silent_repair(self):
        for field in ("claims", "source_refs", "escalation_flags"):
            candidate = self._record()
            candidate[field] = list(reversed(candidate[field]))
            with self.subTest(field=field), self.assertRaises(proposal.ProposalValidationError) as caught:
                proposal.CloudProposal.from_mapping(candidate)
            self.assertEqual(caught.exception.failure_code, failures.FailureCode.NONDETERMINISTIC_OUTPUT.value)

    def test_duplicate_set_like_entries_fail_closed(self):
        duplicate_claim = self._record()
        duplicate_claim["claims"] = [duplicate_claim["claims"][0], copy.deepcopy(duplicate_claim["claims"][0])]
        with self.assertRaises(proposal.ProposalValidationError) as claim_caught:
            proposal.CloudProposal.from_mapping(duplicate_claim)
        self.assertEqual(claim_caught.exception.failure_code, failures.FailureCode.NONDETERMINISTIC_OUTPUT.value)
        duplicate_flag = self._record()
        duplicate_flag["escalation_flags"] = ["EVIDENCE_GAP", "EVIDENCE_GAP"]
        with self.assertRaises(proposal.ProposalValidationError) as flag_caught:
            proposal.CloudProposal.from_mapping(duplicate_flag)
        self.assertEqual(flag_caught.exception.failure_code, failures.FailureCode.NONDETERMINISTIC_OUTPUT.value)

    def test_nested_claim_source_ref_order_is_preserved_and_identity_bound(self):
        ordered_claims = copy.deepcopy(self._record()["claims"])
        reversed_claims = copy.deepcopy(self._record()["claims"])
        top_refs = self._record()["source_refs"]
        ordered_claims[0]["source_refs"] = [copy.deepcopy(top_refs[0]), copy.deepcopy(top_refs[1])]
        reversed_claims[0]["source_refs"] = [copy.deepcopy(top_refs[1]), copy.deepcopy(top_refs[0])]
        ordered = proposal.CloudProposal.from_mapping(self._record(claims=ordered_claims))
        reversed_record = proposal.CloudProposal.from_mapping(self._record(claims=reversed_claims))
        self.assertNotEqual(ordered.proposal_identity, reversed_record.proposal_identity)
        self.assertEqual(
            [ref.source_id for ref in reversed_record.claims[0].source_refs],
            ["2" * 64, "1" * 64],
        )

    def test_structural_nested_constraints_fail_closed(self):
        cases = []
        bad_claim = self._record(); bad_claim["claims"][0]["unexpected"] = 1; cases.append(bad_claim)
        bad_kind = self._record(); bad_kind["recommendation"]["kind"] = "APPROVE"; cases.append(bad_kind)
        bad_level = self._record(); bad_level["uncertainty"]["level"] = "CERTAIN"; cases.append(bad_level)
        bad_attempt = self._record(); bad_attempt["proposer_metadata"]["attempt_number"] = 0; cases.append(bad_attempt)
        bad_ref = self._record(); bad_ref["source_refs"][0]["content_size_bytes"] = -1; cases.append(bad_ref)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(proposal.ProposalValidationError):
                proposal.CloudProposal.from_mapping(candidate)

    def test_identity_critical_claim_and_recommendation_reject_float_values(self):
        bad_claim = self._record()
        bad_claim["claims"][0]["claim_text_or_structured_value"] = {"ratio": 0.5}
        with self.assertRaises(proposal.ProposalValidationError):
            proposal.CloudProposal.from_mapping(bad_claim)

        bad_recommendation = self._record()
        bad_recommendation["recommendation"]["content"] = {"ratio": 0.5}
        with self.assertRaises(proposal.ProposalValidationError):
            proposal.CloudProposal.from_mapping(bad_recommendation)

    def test_excluded_metadata_may_contain_finite_floats(self):
        record = proposal.CloudProposal.from_mapping(self._record(
            proposer_metadata={
                "model_identifier": "model-a", "provider_request_id": "request-a",
                "attempt_number": 2, "usage_if_available": {"ratio": 0.5},
            },
            observational_metadata={"ratio": 0.25},
        ))
        self.assertIn(b"0.5", record.canonical_bytes())
        self.assertIn(b"0.25", record.canonical_bytes())

    def test_optional_non_null_fields_may_be_absent(self):
        candidate = self._record()
        del candidate["free_form_prose"]
        del candidate["observational_metadata"]
        del candidate["proposer_metadata"]["usage_if_available"]
        record = proposal.CloudProposal.from_mapping(candidate)
        rendered = record.to_dict()
        self.assertNotIn("free_form_prose", rendered)
        self.assertNotIn("observational_metadata", rendered)
        self.assertNotIn("usage_if_available", rendered["proposer_metadata"])

    def test_optional_non_null_fields_reject_explicit_null_in_mapping(self):
        candidates = []
        free_form = self._record(); free_form["free_form_prose"] = None; candidates.append(("free_form_prose", free_form))
        observational = self._record(); observational["observational_metadata"] = None; candidates.append(("observational_metadata", observational))
        usage = self._record(); usage["proposer_metadata"]["usage_if_available"] = None; candidates.append(("usage_if_available", usage))
        for field, candidate in candidates:
            with self.subTest(field=field), self.assertRaises(proposal.ProposalValidationError) as caught:
                proposal.CloudProposal.from_mapping(candidate)
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.PROPOSER_SCHEMA_INVALID.value,
            )

    def test_json_parser_rejects_explicit_null_optional_non_null_fields(self):
        candidates = []
        free_form = self._record(); free_form["free_form_prose"] = None; candidates.append(("free_form_prose", free_form))
        observational = self._record(); observational["observational_metadata"] = None; candidates.append(("observational_metadata", observational))
        usage = self._record(); usage["proposer_metadata"]["usage_if_available"] = None; candidates.append(("usage_if_available", usage))
        for field, candidate in candidates:
            payload = json.dumps(candidate, separators=(",", ":"))
            with self.subTest(field=field), self.assertRaises(proposal.ProposalValidationError) as caught:
                proposal.parse_cloud_proposal_json(payload)
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.PROPOSER_SCHEMA_INVALID.value,
            )

    def test_json_parser_rejects_duplicate_keys_and_round_trips_canonically(self):
        valid = self._record()
        parsed = proposal.parse_cloud_proposal_json(json.dumps(valid, separators=(",", ":")))
        self.assertEqual(parsed, proposal.parse_cloud_proposal(parsed))
        self.assertEqual(parsed.canonical_bytes(), proposal.canonical_cloud_proposal_bytes(parsed.to_dict()))
        duplicate = '{"schema_version":"1.0.0","schema_version":"1.0.0"}'
        with self.assertRaises(proposal.ProposalValidationError):
            proposal.parse_cloud_proposal_json(duplicate)

    def test_runtime_has_zero_external_verifier_and_human_gate_authority(self):
        self.assertEqual(proposal.PROPOSAL_PARSE_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(proposal.PROPOSAL_IDENTITY_VALIDATION_IMPLEMENTATION_COUNT, 1)
        for name in (
            "FILESYSTEM_SOURCE_READ_COUNT", "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
            "SUBPROCESS_EXECUTION_COUNT", "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT", "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT", "AUTH_IMPLEMENTATION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT", "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT", "VERIFIER_DECISION_IMPLEMENTATION_COUNT",
            "HUMAN_GATE_EXECUTION_COUNT", "STATE_TRANSITION_EXECUTION_COUNT",
            "GIT_OPERATION_COUNT",
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(proposal, name), 0)

    def test_runtime_source_has_no_external_execution_surface(self):
        source = inspect.getsource(proposal)
        for forbidden in (
            "import socket", "import subprocess", "import requests", "import httpx",
            "import urllib", "import openai", "import anthropic", "import boto3",
            "subprocess.", "socket.", "requests.", "httpx.", "urllib.",
            "os.environ", "os.getenv", "pathlib.Path", "open(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_legacy_placeholder_entrypoint_remains_fail_closed(self):
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            proposal.not_implemented()


if __name__ == "__main__":
    unittest.main()

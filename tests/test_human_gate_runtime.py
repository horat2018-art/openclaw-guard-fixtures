import copy
import unittest
from dataclasses import replace

from hai_mr05 import canonical, human_gate, identity


class HumanGateRuntimeTests(unittest.TestCase):
    def gate_fields(self):
        return {
            "run_identity": "1" * 64,
            "task_identity": "2" * 64,
            "proposal_identity": "3" * 64,
            "verification_identity": "4" * 64,
            "package_identity": "5" * 64,
            "context_identity": "6" * 64,
            "task_summary": "review task",
            "proposal_summary": "review proposal",
            "verification_result": "PASS_FOR_REVIEW",
            "reason_codes": ["VERIFIED"],
            "source_refs": [{
                "source_id": "7" * 64,
                "canonical_locator": "fixture/item.json",
                "content_sha256": "8" * 64,
                "content_size_bytes": 12,
                "source_set_identity": "9" * 64,
            }],
            "uncertainties": ["none known"],
            "evidence_pointers": ["evidence/manifest.json"],
        }

    def decision_fields(self):
        return {
            "decision": "APPROVE",
            "decision_reason": "Reviewed supplied evidence",
            "decision_scope": "This exact Human Gate record only",
            "human_authority_reference": "human-auth:fixture-001",
        }

    def test_gate_identity_and_canonical_bytes_are_deterministic(self):
        first = human_gate.build_human_gate(**self.gate_fields())
        second = human_gate.build_human_gate(**copy.deepcopy(self.gate_fields()))
        self.assertEqual(first, second)
        self.assertEqual(tuple(first.identity_payload), human_gate.HUMAN_GATE_IDENTITY_PREIMAGE)
        self.assertEqual(first.human_gate_identity, identity.sha256_canonical(first.identity_payload))
        self.assertEqual(human_gate.canonical_human_gate_bytes(first), canonical.canonical_json_bytes(first.to_dict()))
        self.assertEqual(human_gate.HumanGateRecord.from_mapping(first.to_dict()), first)

    def test_observational_metadata_does_not_change_gate_identity(self):
        first = human_gate.build_human_gate(**self.gate_fields())
        changed = self.gate_fields()
        changed["observational_metadata"] = {"display": "changed"}
        second = human_gate.build_human_gate(**changed)
        self.assertEqual(first.human_gate_identity, second.human_gate_identity)

    def test_decision_is_identity_bound_record_only(self):
        gate = human_gate.build_human_gate(**self.gate_fields())
        decision = human_gate.build_human_decision(
            human_gate=gate,
            **self.decision_fields(),
        )
        self.assertEqual(tuple(decision.identity_payload), human_gate.HUMAN_DECISION_IDENTITY_PREIMAGE)
        self.assertEqual(decision.decision_identity, identity.sha256_canonical(decision.identity_payload))
        self.assertEqual(human_gate.canonical_human_decision_bytes(decision), canonical.canonical_json_bytes(decision.to_dict()))
        self.assertEqual(
            human_gate.HumanDecisionRecord.from_mapping(
                decision.to_dict(), human_gate=gate
            ),
            decision,
        )

    def test_gate_contract_fail_closed_cases(self):
        good = human_gate.build_human_gate(**self.gate_fields()).to_dict()
        cases = []
        missing = copy.deepcopy(good); missing.pop("task_identity"); cases.append(missing)
        extra = copy.deepcopy(good); extra["unexpected"] = True; cases.append(extra)
        bad_sha = copy.deepcopy(good); bad_sha["run_identity"] = "A" * 64; cases.append(bad_sha)
        bad_version = copy.deepcopy(good); bad_version["schema_version"] = "2.0.0"; cases.append(bad_version)
        bad_verification = copy.deepcopy(good); bad_verification["verification_result"] = "APPROVE"; cases.append(bad_verification)
        unsafe_pointer = copy.deepcopy(good); unsafe_pointer["evidence_pointers"] = ["../escape"]; cases.append(unsafe_pointer)
        malformed_source = copy.deepcopy(good); malformed_source["source_refs"][0]["content_size_bytes"] = -1; cases.append(malformed_source)
        mismatch = copy.deepcopy(good); mismatch["task_summary"] = "changed"; cases.append(mismatch)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(human_gate.HumanGateValidationError):
                human_gate.HumanGateRecord.from_mapping(value)

    def test_duplicate_and_unknown_action_options_fail_closed(self):
        duplicate = self.gate_fields(); duplicate["human_action_options"] = ["APPROVE", "APPROVE"]
        unknown = self.gate_fields(); unknown["human_action_options"] = ["EXECUTE"]
        for value in (duplicate, unknown):
            with self.assertRaises(human_gate.HumanGateValidationError):
                human_gate.build_human_gate(**value)

    def test_action_projection_and_identity_exclusion_are_contract_bound(self):
        expected = {
            "DENY": ("REJECT",),
            "ESCALATE": ("REJECT", "REQUEST_REWORK", "REQUEST_MORE_EVIDENCE"),
            "PASS_FOR_REVIEW": (
                "APPROVE", "REJECT", "REQUEST_REWORK", "REQUEST_MORE_EVIDENCE"
            ),
        }
        for verification_result, actions in expected.items():
            fields = self.gate_fields()
            fields["verification_result"] = verification_result
            gate = human_gate.build_human_gate(**fields)
            with self.subTest(verification_result=verification_result):
                self.assertEqual(gate.human_action_options, actions)
                self.assertNotIn("human_action_options", gate.identity_payload)
                self.assertEqual(
                    gate.human_gate_identity,
                    identity.sha256_canonical(gate.identity_payload),
                )
            tampered = gate.to_dict()
            tampered["human_action_options"] = ["APPROVE"]
            if actions != ("APPROVE",):
                with self.subTest(verification_result=verification_result, tamper=True), self.assertRaises(
                    human_gate.HumanGateValidationError
                ) as ctx:
                    human_gate.HumanGateRecord.from_mapping(tampered)
                self.assertEqual(ctx.exception.failure_code, "MR05_HUMAN_GATE_INVALID")

    def test_decision_legality_follows_exact_verification_result(self):
        expected = {
            "DENY": {"REJECT"},
            "ESCALATE": {"REJECT", "REQUEST_REWORK", "REQUEST_MORE_EVIDENCE"},
            "PASS_FOR_REVIEW": set(human_gate.HUMAN_ACTION_VALUES),
        }
        for verification_result, allowed in expected.items():
            fields = self.gate_fields()
            fields["verification_result"] = verification_result
            gate = human_gate.build_human_gate(**fields)
            for decision in human_gate.HUMAN_ACTION_VALUES:
                decision_fields = self.decision_fields()
                decision_fields["decision"] = decision
                if decision in allowed:
                    record = human_gate.build_human_decision(
                        human_gate=gate, **decision_fields
                    )
                    self.assertEqual(record.decision, decision)
                else:
                    with self.subTest(
                        verification_result=verification_result, decision=decision
                    ), self.assertRaises(human_gate.HumanGateValidationError) as ctx:
                        human_gate.build_human_decision(
                            human_gate=gate, **decision_fields
                        )
                    self.assertEqual(
                        ctx.exception.failure_code, "MR05_HUMAN_GATE_INVALID"
                    )

    def test_set_like_gate_arrays_are_canonicalized_before_identity(self):
        first_fields = self.gate_fields()
        first_fields["reason_codes"] = ["Z_REASON", "A_REASON"]
        first_fields["evidence_pointers"] = ["z/evidence.json", "a/evidence.json"]
        first_fields["source_refs"] = [
            {
                "source_id": "b" * 64,
                "canonical_locator": "fixture/z.json",
                "content_sha256": "c" * 64,
                "content_size_bytes": 2,
                "source_set_identity": "d" * 64,
            },
            {
                "source_id": "a" * 64,
                "canonical_locator": "fixture/a.json",
                "content_sha256": "e" * 64,
                "content_size_bytes": 1,
                "source_set_identity": "f" * 64,
            },
        ]
        second_fields = copy.deepcopy(first_fields)
        second_fields["reason_codes"].reverse()
        second_fields["evidence_pointers"].reverse()
        second_fields["source_refs"].reverse()
        first = human_gate.build_human_gate(**first_fields)
        second = human_gate.build_human_gate(**second_fields)
        self.assertEqual(first.human_gate_identity, second.human_gate_identity)
        self.assertEqual(first.reason_codes, ("A_REASON", "Z_REASON"))
        self.assertEqual(first.evidence_pointers, ("a/evidence.json", "z/evidence.json"))
        self.assertEqual(tuple(row["source_id"] for row in first.source_refs), ("a" * 64, "b" * 64))

    def test_builder_missing_field_is_controlled_fail_closed_error(self):
        fields = self.gate_fields()
        fields.pop("task_identity")
        with self.assertRaises(human_gate.HumanGateValidationError) as ctx:
            human_gate.build_human_gate(**fields)
        self.assertEqual(ctx.exception.failure_code, "INVALID_SCHEMA")
        self.assertFalse(ctx.exception.retry_allowed)

    def test_human_decision_fail_closed_and_wrong_gate_binding(self):
        gate = human_gate.build_human_gate(**self.gate_fields())
        good = human_gate.build_human_decision(
            human_gate=gate, **self.decision_fields()
        ).to_dict()
        bad = copy.deepcopy(good); bad["decision"] = "EXECUTE"
        with self.assertRaises(human_gate.HumanGateValidationError) as ctx:
            human_gate.HumanDecisionRecord.from_mapping(bad, human_gate=gate)
        self.assertEqual(ctx.exception.failure_code, "MR05_HUMAN_GATE_INVALID")
        mismatch = copy.deepcopy(good); mismatch["decision_reason"] = "mutated"
        with self.assertRaises(human_gate.HumanGateValidationError) as ctx:
            human_gate.HumanDecisionRecord.from_mapping(mismatch, human_gate=gate)
        self.assertEqual(ctx.exception.failure_code, "HASH_MISMATCH")
        wrong_gate_fields = self.gate_fields()
        wrong_gate_fields["task_summary"] = "different gate"
        wrong_gate = human_gate.build_human_gate(**wrong_gate_fields)
        with self.assertRaises(human_gate.HumanGateValidationError) as ctx:
            human_gate.HumanDecisionRecord.from_mapping(good, human_gate=wrong_gate)
        self.assertEqual(ctx.exception.failure_code, "MR05_HUMAN_GATE_INVALID")
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.build_human_decision(
                human_gate=gate,
                human_gate_identity=gate.human_gate_identity,
                **self.decision_fields(),
            )

    def test_authority_and_side_effect_counters_remain_zero(self):
        self.assertEqual(human_gate.HUMAN_GATE_IMPLEMENTATION_COUNT, 1)
        zero_names = (
            "AUTO_EXECUTE_AFTER_APPROVAL_COUNT", "HUMAN_APPROVAL_EXECUTION_COUNT",
            "HUMAN_DECISION_SIDE_EFFECT_COUNT", "STATE_TRANSITION_EXECUTION_COUNT",
            "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT", "SUBPROCESS_EXECUTION_COUNT",
            "NETWORK_IMPLEMENTATION_COUNT", "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT", "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT", "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT", "GIT_OPERATION_COUNT",
        )
        for name in zero_names:
            with self.subTest(name=name):
                self.assertEqual(getattr(human_gate, name), 0)


    def test_explicit_null_observational_metadata_is_rejected(self):
        gate = human_gate.build_human_gate(**self.gate_fields())
        gate_mapping = gate.to_dict()
        gate_mapping["observational_metadata"] = None
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.HumanGateRecord.from_mapping(gate_mapping)

        gate_fields = self.gate_fields()
        gate_fields["observational_metadata"] = None
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.build_human_gate(**gate_fields)

        decision = human_gate.build_human_decision(
            human_gate=gate, **self.decision_fields()
        )
        decision_mapping = decision.to_dict()
        decision_mapping["observational_metadata"] = None
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.HumanDecisionRecord.from_mapping(
                decision_mapping, human_gate=gate
            )

        decision_fields = self.decision_fields()
        decision_fields["observational_metadata"] = None
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.build_human_decision(
                human_gate=gate, **decision_fields
            )

    def test_schema_permitted_line_breaks_are_preserved(self):
        fields = self.gate_fields()
        fields["task_summary"] = "review\ntask"
        fields["proposal_summary"] = "review\rproposal"
        fields["reason_codes"] = ["VERIFIED\nDETAIL"]
        fields["uncertainties"] = ["line\nbreak", "carriage\rreturn"]
        fields["source_refs"][0]["canonical_locator"] = "fixture/line\nbreak.json"
        fields["evidence_pointers"] = ["evidence/manifest\r.json"]
        gate = human_gate.build_human_gate(**fields)
        self.assertEqual(gate.task_summary, "review\ntask")
        self.assertEqual(gate.proposal_summary, "review\rproposal")
        self.assertEqual(gate.reason_codes, ("VERIFIED\nDETAIL",))
        self.assertEqual(gate.uncertainties, ("line\nbreak", "carriage\rreturn"))
        self.assertEqual(
            gate.source_refs[0]["canonical_locator"],
            "fixture/line\nbreak.json",
        )
        self.assertEqual(gate.evidence_pointers, ("evidence/manifest\r.json",))

        decision_fields = self.decision_fields()
        decision_fields["decision_reason"] = "Reviewed\nsupplied evidence"
        decision_fields["decision_scope"] = "This exact\rHuman Gate record only"
        decision_fields["human_authority_reference"] = "human-auth:\nfixture-001"
        decision = human_gate.build_human_decision(
            human_gate=gate, **decision_fields
        )
        self.assertEqual(decision.decision_reason, "Reviewed\nsupplied evidence")
        self.assertEqual(decision.decision_scope, "This exact\rHuman Gate record only")
        self.assertEqual(
            decision.human_authority_reference,
            "human-auth:\nfixture-001",
        )

    def test_nul_and_unpaired_surrogates_remain_rejected(self):
        for field, value in (
            ("task_summary", "bad\x00text"),
            ("proposal_summary", "bad\ud800text"),
        ):
            fields = self.gate_fields()
            fields[field] = value
            with self.subTest(field=field), self.assertRaises(
                human_gate.HumanGateValidationError
            ):
                human_gate.build_human_gate(**fields)

        fields = self.gate_fields()
        fields["uncertainties"] = ["bad\ud800text"]
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.build_human_gate(**fields)

        fields = self.gate_fields()
        fields["source_refs"][0]["canonical_locator"] = "bad\x00locator"
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.build_human_gate(**fields)

        gate = human_gate.build_human_gate(**self.gate_fields())
        for field, value in (
            ("decision_reason", "bad\x00reason"),
            ("decision_scope", "bad\ud800scope"),
            ("human_authority_reference", "bad\x00authority"),
        ):
            decision_fields = self.decision_fields()
            decision_fields[field] = value
            with self.subTest(field=field), self.assertRaises(
                human_gate.HumanGateValidationError
            ):
                human_gate.build_human_decision(
                    human_gate=gate, **decision_fields
                )

    def test_evidence_pointer_frozen_path_restrictions_are_preserved(self):
        for pointer in (
            "evidence/line\nbreak.json",
            "../escape.json",
            "evidence/../escape.json",
            "/absolute/path.json",
        ):
            fields = self.gate_fields()
            fields["evidence_pointers"] = [pointer]
            with self.subTest(pointer=pointer), self.assertRaises(
                human_gate.HumanGateValidationError
            ):
                human_gate.build_human_gate(**fields)

    def test_observational_float_canonicalizes_without_changing_identity(self):
        base_gate = human_gate.build_human_gate(**self.gate_fields())
        gate_fields = self.gate_fields()
        gate_fields["observational_metadata"] = {"score": 1.25}
        gate = human_gate.build_human_gate(**gate_fields)
        self.assertEqual(base_gate.human_gate_identity, gate.human_gate_identity)
        self.assertIn(b'"score":1.25', human_gate.canonical_human_gate_bytes(gate))

        base_decision = human_gate.build_human_decision(
            human_gate=gate, **self.decision_fields()
        )
        decision_fields = self.decision_fields()
        decision_fields["observational_metadata"] = {"score": 2.5}
        decision = human_gate.build_human_decision(
            human_gate=gate, **decision_fields
        )
        self.assertEqual(base_decision.decision_identity, decision.decision_identity)
        self.assertIn(
            b'"score":2.5',
            human_gate.canonical_human_decision_bytes(decision),
        )

    def test_full_record_canonicalization_requalifies_identity_fields(self):
        gate = human_gate.build_human_gate(**self.gate_fields())
        bad_refs = [dict(row) for row in gate.source_refs]
        bad_refs[0]["content_size_bytes"] = 1.25
        tampered_gate = replace(gate, source_refs=tuple(bad_refs))
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.canonical_human_gate_bytes(tampered_gate)

        tampered_gate_identity = replace(gate, human_gate_identity="a" * 64)
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.canonical_human_gate_bytes(tampered_gate_identity)

        gate_fields = self.gate_fields()
        gate_fields["observational_metadata"] = {"score": 1.25}
        qualified_gate = human_gate.build_human_gate(**gate_fields)
        self.assertIn(
            b'"score":1.25',
            human_gate.canonical_human_gate_bytes(qualified_gate),
        )

        decision = human_gate.build_human_decision(
            human_gate=qualified_gate, **self.decision_fields()
        )
        tampered_decision_type = replace(decision, decision_reason=1.25)
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.canonical_human_decision_bytes(tampered_decision_type)

        tampered_decision_identity = replace(
            decision, decision_identity="b" * 64
        )
        with self.assertRaises(human_gate.HumanGateValidationError):
            human_gate.canonical_human_decision_bytes(tampered_decision_identity)

        decision_fields = self.decision_fields()
        decision_fields["observational_metadata"] = {"score": 2.5}
        qualified_decision = human_gate.build_human_decision(
            human_gate=qualified_gate, **decision_fields
        )
        self.assertIn(
            b'"score":2.5',
            human_gate.canonical_human_decision_bytes(qualified_decision),
        )



if __name__ == "__main__":
    unittest.main()

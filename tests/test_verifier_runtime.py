import json
import unittest

from hai_mr05 import verifier
from hai_mr05.failures import (
    Failure,
    FailureCode,
    FailureOwner,
    FailureSeverity,
    FailureState,
)


TASK = "1" * 64
SOURCE_SET = "2" * 64
DISCOVERY = "3" * 64
NORMALIZATION = "4" * 64
CONTEXT = "5" * 64
RUN = "6" * 64
MR03 = "7" * 64
MR04 = "8" * 64
PROPOSAL = "9" * 64
PROVENANCE = "a" * 64
METRICS = "b" * 64

SOURCE_REF = {
    "source_id": "c" * 64,
    "canonical_locator": "evidence/item.json",
    "content_sha256": "d" * 64,
    "content_size_bytes": 17,
    "source_set_identity": SOURCE_SET,
}


def _context():
    return {
        "context_identity": CONTEXT,
        "task_identity": TASK,
        "run_identity": RUN,
        "source_set_identity": SOURCE_SET,
        "mr03_package_identity": MR03,
        "mr04_result_identity": MR04,
        "source_refs": [dict(SOURCE_REF)],
    }


def _proposal():
    return {
        "proposal_identity": PROPOSAL,
        "bound_context_identity": CONTEXT,
        "task_identity": TASK,
        "run_identity": RUN,
        "bound_mr03_package_identity": MR03,
        "bound_mr04_result_identity": MR04,
        "source_refs": [dict(SOURCE_REF)],
        "claims": [{"claim_id": "claim-1"}],
    }


def _legacy_result(*, failure=None):
    inputs = {
        "task_identity": TASK,
        "source_set_identity": SOURCE_SET,
        "discovery_identity": DISCOVERY,
        "normalization_identity": NORMALIZATION,
        "context_identity": CONTEXT,
    }
    checks = []
    for rule in verifier.RULE_CATALOG:
        if failure is not None and rule.rule_id == "CLAIM_SUPPORT":
            checks.append(
                verifier.build_verifier_check(
                    rule_id=rule.rule_id,
                    input_identity=CONTEXT,
                    check_result="FAIL",
                    failure_identity=failure.failure_identity,
                    decision_reason_code=failure.failure_code.value,
                )
            )
        else:
            checks.append(
                verifier.build_verifier_check(
                    rule_id=rule.rule_id,
                    input_identity=CONTEXT,
                    check_result="PASS",
                )
            )
    failures = () if failure is None else (failure,)
    return verifier.build_verifier_result(
        inputs,
        ("e" * 64, "f" * 64),
        PROVENANCE,
        METRICS,
        verifier.FROZEN_CONTRACT_IDENTITIES,
        checks,
        failures,
    )


def _semantic_pass():
    return {
        "schema_version": "1.0.0",
        "proposal_identity": PROPOSAL,
        "verification_result": "PASS_FOR_REVIEW",
        "reason_codes": [],
        "reason_details": [],
        "verified_source_refs": [dict(SOURCE_REF)],
        "unsupported_claims": [],
        "missing_refs": [],
        "protected_content_findings": [],
        "identity_findings": [],
        "verification_policy_version": "1.0.0",
    }


def _record_from_semantic(semantic):
    result = dict(semantic)
    result["verification_identity"] = verifier.verification_identity_from_preimage(semantic)
    return result


def _unsupported_failure():
    return Failure(
        schema_version="1.0.0",
        failure_code=FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM,
        failure_owner=FailureOwner.PROPOSAL_BINDING,
        severity=FailureSeverity.HIGH,
        state=FailureState.FAILED,
        run_identity=RUN,
        related_identity=PROPOSAL,
        message="claim cannot be tied to bounded evidence",
        human_escalation_required=False,
    )


def _semantic_deny(failure):
    detail = {
        "code": failure.failure_code.value,
        "owner": failure.failure_owner.value,
        "severity": failure.severity.value,
        "explanation": failure.message,
        "related_refs": [failure.related_identity],
    }
    return {
        "schema_version": "1.0.0",
        "proposal_identity": PROPOSAL,
        "verification_result": "DENY",
        "reason_codes": [failure.failure_code.value],
        "reason_details": [detail],
        "verified_source_refs": [dict(SOURCE_REF)],
        "unsupported_claims": ["claim-1"],
        "missing_refs": [],
        "protected_content_findings": [],
        "identity_findings": [],
        "verification_policy_version": "1.0.0",
    }


class VerificationRuntimeTests(unittest.TestCase):
    def test_frozen_public_contract_is_additive_and_identity_binds_reason_details(self):
        self.assertEqual(verifier.PUBLIC_VERIFICATION_SCHEMA_ID, "mr05.verification")
        self.assertEqual(verifier.PUBLIC_VERIFICATION_SCHEMA_VERSION, "1.0.0")
        self.assertIn("reason_details", verifier.VERIFICATION_RECORD_IDENTITY_PREIMAGE)
        self.assertIs(verifier.VerificationResult, verifier.VerifierResult)
        self.assertNotIn("proposal_identity", verifier.VERIFIER_IDENTITY_PREIMAGE)

    def test_valid_public_record_round_trips_and_canonicalizes(self):
        mapping = _record_from_semantic(_semantic_pass())
        record = verifier.VerificationRecord.from_mapping(mapping)
        self.assertEqual(record.to_dict(), mapping)
        self.assertEqual(
            verifier.compute_verification_identity(record), mapping["verification_identity"]
        )
        self.assertEqual(
            verifier.canonical_verification_bytes(record), record.canonical_bytes()
        )

    def test_json_parser_rejects_duplicate_keys_and_explicit_null_metadata(self):
        mapping = _record_from_semantic(_semantic_pass())
        duplicate = '{"schema_version":"1.0.0",' + json.dumps(mapping)[1:]
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.parse_verification_json(duplicate)
        with_null = dict(mapping)
        with_null["observational_metadata"] = None
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.VerificationRecord.from_mapping(with_null)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.parse_verification_json(json.dumps(with_null))

    def test_observational_metadata_allows_float_and_is_identity_excluded(self):
        mapping = _record_from_semantic(_semantic_pass())
        with_metadata = dict(mapping)
        with_metadata["observational_metadata"] = {"ratio": 1.5}
        record = verifier.VerificationRecord.from_mapping(with_metadata)
        self.assertEqual(record.verification_identity, mapping["verification_identity"])
        self.assertEqual(record.to_dict()["observational_metadata"]["ratio"], 1.5)

    def test_reason_detail_mutation_changes_public_identity(self):
        failure = _unsupported_failure()
        semantic = _semantic_deny(failure)
        first = verifier.verification_identity_from_preimage(semantic)
        changed = json.loads(json.dumps(semantic))
        changed["reason_details"][0]["explanation"] += " changed"
        second = verifier.verification_identity_from_preimage(changed)
        self.assertNotEqual(first, second)

    def test_reason_codes_require_severity_then_lexical_order(self):
        semantic = _semantic_deny(_unsupported_failure())
        critical = {
            "code": FailureCode.MR05_VERIFIER_EXCEPTION.value,
            "owner": FailureOwner.VERIFICATION.value,
            "severity": FailureSeverity.CRITICAL.value,
            "explanation": "verifier failed closed",
            "related_refs": [],
        }
        semantic["reason_details"].append(critical)
        semantic["reason_codes"] = [
            FailureCode.MR05_VERIFIER_EXCEPTION.value,
            FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM.value,
        ]
        verifier.verification_identity_from_preimage(semantic)
        semantic["reason_codes"].reverse()
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.verification_identity_from_preimage(semantic)

    def test_verified_source_refs_require_source_id_then_locator_order(self):
        semantic = _semantic_pass()
        second = dict(SOURCE_REF)
        second["source_id"] = "b" * 64
        second["canonical_locator"] = "evidence/a.json"
        semantic["verified_source_refs"] = [second, dict(SOURCE_REF)]
        verifier.verification_identity_from_preimage(semantic)
        semantic["verified_source_refs"].reverse()
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.verification_identity_from_preimage(semantic)

    def test_public_and_legacy_policy_versions_are_separate(self):
        self.assertEqual(verifier.PUBLIC_VERIFICATION_POLICY_VERSION, "1.0.0")
        self.assertEqual(verifier.VERIFICATION_POLICY_VERSION, "MR05-VERIFIER-POLICY-1.0.0")
        self.assertNotEqual(
            verifier.PUBLIC_VERIFICATION_POLICY_VERSION,
            verifier.VERIFICATION_POLICY_VERSION,
        )

    def test_adapter_accepts_exact_pass_bindings_without_generating_findings(self):
        record = _record_from_semantic(_semantic_pass())
        result = verifier.validate_verification_adapter(
            record,
            proposal=_proposal(),
            context=_context(),
            legacy_result=_legacy_result(),
        )
        self.assertEqual(result.verification_result, "PASS_FOR_REVIEW")
        self.assertEqual(result.reason_details, ())
        self.assertEqual(result.unsupported_claims, ())

    def test_adapter_rejects_proposal_and_context_binding_mismatch(self):
        record = _record_from_semantic(_semantic_pass())
        proposal = _proposal()
        proposal["bound_context_identity"] = "f" * 64
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.validate_verification_adapter(
                record,
                proposal=proposal,
                context=_context(),
                legacy_result=_legacy_result(),
            )

    def test_adapter_rejects_fabricated_verified_source_ref(self):
        semantic = _semantic_pass()
        fabricated = dict(SOURCE_REF)
        fabricated["source_id"] = "a" * 64
        semantic["verified_source_refs"] = [fabricated]
        record = _record_from_semantic(semantic)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.validate_verification_adapter(
                record,
                proposal=_proposal(),
                context=_context(),
                legacy_result=_legacy_result(),
            )

    def test_adapter_rejects_fabricated_unsupported_claim_id(self):
        failure = _unsupported_failure()
        semantic = _semantic_deny(failure)
        semantic["unsupported_claims"] = ["not-a-real-claim"]
        record = _record_from_semantic(semantic)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.validate_verification_adapter(
                record,
                proposal=_proposal(),
                context=_context(),
                legacy_result=_legacy_result(failure=failure),
                failure_records=(failure,),
            )

    def test_adapter_accepts_exact_nonpass_failure_evidence(self):
        failure = _unsupported_failure()
        record = _record_from_semantic(_semantic_deny(failure))
        result = verifier.validate_verification_adapter(
            record,
            proposal=_proposal(),
            context=_context(),
            legacy_result=_legacy_result(failure=failure),
            failure_records=(failure,),
        )
        self.assertEqual(result.verification_result, "DENY")
        self.assertEqual(result.reason_codes, (failure.failure_code.value,))

    def test_adapter_rejects_nonpass_without_supplied_failure_record(self):
        failure = _unsupported_failure()
        record = _record_from_semantic(_semantic_deny(failure))
        legacy = _legacy_result(failure=failure)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.validate_verification_adapter(
                record,
                proposal=_proposal(),
                context=_context(),
                legacy_result=legacy,
                failure_records=(),
            )

    def test_adapter_rejects_fabricated_reason_detail(self):
        failure = _unsupported_failure()
        semantic = _semantic_deny(failure)
        semantic["reason_details"][0]["explanation"] = "fabricated explanation"
        record = _record_from_semantic(semantic)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.validate_verification_adapter(
                record,
                proposal=_proposal(),
                context=_context(),
                legacy_result=_legacy_result(failure=failure),
                failure_records=(failure,),
            )

    def test_nullable_nested_fields_follow_frozen_schema(self):
        semantic = _semantic_deny(_unsupported_failure())
        semantic["protected_content_findings"] = [
            {"classification": "UNKNOWN", "action": "ESCALATE", "source_id": None}
        ]
        semantic["identity_findings"] = [
            {"identity_name": "context_identity", "expected": CONTEXT, "observed": None, "action": "BLOCK"}
        ]
        verifier.verification_identity_from_preimage(semantic)

    def test_public_boundary_has_zero_operational_authority(self):
        self.assertEqual(verifier.VERIFICATION_RECORD_PARSE_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(verifier.VERIFICATION_IDENTITY_VALIDATION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(verifier.VERIFICATION_ADAPTER_VALIDATION_IMPLEMENTATION_COUNT, 1)
        for name in (
            "LIVE_VERIFICATION_EXECUTION_COUNT",
            "MR04_VERIFIER_EXECUTION_IMPLEMENTATION_COUNT",
            "SOURCE_DISCOVERY_IMPLEMENTATION_COUNT",
            "FILESYSTEM_SOURCE_READ_COUNT",
            "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
            "SUBPROCESS_EXECUTION_COUNT",
            "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT",
            "HUMAN_APPROVAL_EXECUTION_COUNT",
            "HUMAN_DECISION_EXECUTION_COUNT",
            "STATE_TRANSITION_EXECUTION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "GIT_OPERATION_COUNT",
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(verifier, name), 0)


if __name__ == "__main__":
    unittest.main()

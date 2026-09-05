import unittest

from hai_mr05 import disclosure, failures


class DisclosureRuntimeTests(unittest.TestCase):
    def test_public_without_restrictive_findings_allows(self):
        record = disclosure.build_disclosure(classification="PUBLIC")
        self.assertEqual(record.disclosure_result, "ALLOW")
        self.assertTrue(record.cloud_eligible)
        self.assertEqual(record.findings, ())
        self.assertEqual(
            record.to_dict(),
            {
                "schema_version": "1.0.0",
                "classification": "PUBLIC",
                "disclosure_result": "ALLOW",
                "policy_version": "1.0.0",
                "findings": [],
            },
        )

    def test_public_finding_actions_apply_restrictive_semantics(self):
        cases = (
            ("ALLOW", "ALLOW"),
            ("REDACT", "ESCALATE"),
            ("ESCALATE", "ESCALATE"),
            ("DENY", "DENY"),
        )
        for action, expected in cases:
            with self.subTest(action=action):
                record = disclosure.build_disclosure(
                    classification="PUBLIC",
                    findings=[{"code": f"PUBLIC_{action}", "action": action}],
                )
                self.assertEqual(record.disclosure_result, expected)
                self.assertEqual(record.cloud_eligible, expected == "ALLOW")

    def test_internal_never_auto_allows(self):
        for findings in ([], [{"code": "ALLOW_ONLY", "action": "ALLOW"}]):
            with self.subTest(findings=findings):
                record = disclosure.build_disclosure(
                    classification="INTERNAL",
                    findings=findings,
                )
                self.assertEqual(record.disclosure_result, "ESCALATE")
                self.assertFalse(record.cloud_eligible)

    def test_protected_secret_like_and_unknown_deny(self):
        for classification in ("PROTECTED", "SECRET_LIKE", "UNKNOWN"):
            with self.subTest(classification=classification):
                record = disclosure.build_disclosure(
                    classification=classification,
                    findings=[{"code": "ALLOW_FINDING", "action": "ALLOW"}],
                )
                self.assertEqual(record.disclosure_result, "DENY")
                self.assertFalse(record.cloud_eligible)

    def test_most_restrictive_finding_wins(self):
        record = disclosure.build_disclosure(
            classification="PUBLIC",
            findings=[
                {"code": "ALLOW_FIRST", "action": "ALLOW"},
                {"code": "REDACT_SECOND", "action": "REDACT"},
                {"code": "DENY_THIRD", "action": "DENY"},
                {"code": "ESCALATE_LAST", "action": "ESCALATE"},
            ],
        )
        self.assertEqual(record.disclosure_result, "DENY")

    def test_findings_preserve_declared_order(self):
        source_id = "a" * 64
        record = disclosure.build_disclosure(
            classification="PUBLIC",
            findings=[
                {"code": "Z_FIRST", "action": "ALLOW", "source_id": source_id},
                {"code": "A_SECOND", "action": "REDACT"},
            ],
        )
        self.assertEqual([finding.code for finding in record.findings], ["Z_FIRST", "A_SECOND"])
        self.assertEqual(record.to_dict()["findings"][0]["source_id"], source_id)

    def test_record_round_trip_is_repeatable_and_has_no_disclosure_identity(self):
        original = disclosure.build_disclosure(
            classification="PUBLIC",
            findings=[{"code": "REVIEW", "action": "ESCALATE"}],
            observational_metadata={"display": {"source": "test"}},
        )
        repeated = disclosure.DisclosureRecord.from_mapping(original.to_dict())
        self.assertEqual(repeated, original)
        self.assertEqual(repeated.to_dict(), original.to_dict())
        self.assertNotIn("disclosure_identity", original.to_dict())
        self.assertFalse(hasattr(original, "disclosure_identity"))

    def test_declared_result_must_match_deterministic_projection(self):
        with self.assertRaises(disclosure.DisclosureValidationError) as caught:
            disclosure.DisclosureRecord.from_mapping(
                {
                    "schema_version": "1.0.0",
                    "classification": "PROTECTED",
                    "disclosure_result": "ALLOW",
                    "policy_version": "1.0.0",
                    "findings": [],
                }
            )
        self.assertEqual(caught.exception.failure_code, failures.FailureCode.INVALID_SCHEMA.value)
        self.assertFalse(caught.exception.retry_allowed)

    def test_malformed_record_fails_closed_with_controlled_error(self):
        malformed = (
            {},
            {
                "schema_version": "1.0.0",
                "classification": "PUBLIC",
                "disclosure_result": "ALLOW",
                "policy_version": "1.0.0",
                "findings": [],
                "unexpected": True,
            },
            {
                "schema_version": "1.0.0",
                "classification": "PUBLIC",
                "disclosure_result": "ALLOW",
                "policy_version": "1.0.0",
                "findings": "not-an-array",
            },
        )
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(disclosure.DisclosureValidationError) as caught:
                disclosure.DisclosureRecord.from_mapping(payload)
            self.assertEqual(caught.exception.failure_code, failures.FailureCode.INVALID_SCHEMA.value)
            self.assertFalse(caught.exception.retry_allowed)

    def test_malformed_finding_and_source_id_fail_closed(self):
        cases = (
            [{"code": "MISSING_ACTION"}],
            [{"code": "UNKNOWN", "action": "OTHER"}],
            [{"code": "BAD_SOURCE", "action": "ALLOW", "source_id": "short"}],
        )
        for findings in cases:
            with self.subTest(findings=findings), self.assertRaises(disclosure.DisclosureValidationError) as caught:
                disclosure.build_disclosure(classification="PUBLIC", findings=findings)
            self.assertEqual(caught.exception.failure_code, failures.FailureCode.INVALID_SCHEMA.value)

    def test_schema_and_policy_versions_are_exact(self):
        base = {
            "classification": "PUBLIC",
            "disclosure_result": "ALLOW",
            "findings": [],
        }
        with self.assertRaises(disclosure.DisclosureValidationError) as major:
            disclosure.DisclosureRecord.from_mapping(
                {**base, "schema_version": "2.0.0", "policy_version": "1.0.0"}
            )
        self.assertEqual(major.exception.failure_code, failures.FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value)
        with self.assertRaises(disclosure.DisclosureValidationError) as policy:
            disclosure.DisclosureRecord.from_mapping(
                {**base, "schema_version": "1.0.0", "policy_version": "1.0.1"}
            )
        self.assertEqual(policy.exception.failure_code, failures.FailureCode.INVALID_SCHEMA.value)

    def test_classification_is_exact_and_unknown_values_fail_closed(self):
        for classification in ("public", "PRIVATE", "", None):
            with self.subTest(classification=classification), self.assertRaises(disclosure.DisclosureValidationError):
                disclosure.build_disclosure(classification=classification)

    def test_observational_metadata_is_non_policy_and_frozen(self):
        metadata = {"display": {"labels": ["one", "two"]}}
        first = disclosure.build_disclosure(
            classification="PUBLIC",
            observational_metadata=metadata,
        )
        second = disclosure.build_disclosure(
            classification="PUBLIC",
            observational_metadata={"display": {"labels": ["changed"]}},
        )
        self.assertEqual(first.disclosure_result, second.disclosure_result)
        metadata["display"]["labels"].append("mutated")
        self.assertEqual(first.to_dict()["observational_metadata"]["display"]["labels"], ["one", "two"])

    def test_runtime_has_zero_external_and_progression_authority(self):
        self.assertEqual(disclosure.DISCLOSURE_IMPLEMENTATION_COUNT, 1)
        for name in (
            "FILESYSTEM_SOURCE_READ_COUNT",
            "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
            "SUBPROCESS_EXECUTION_COUNT",
            "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "STATE_TRANSITION_EXECUTION_COUNT",
            "GIT_OPERATION_COUNT",
            "CONTEXT_BUILDER_INTEGRATION_COUNT",
            "CLOUD_REQUEST_BUILD_COUNT",
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(disclosure, name), 0)

    def test_legacy_placeholder_entrypoint_remains_fail_closed(self):
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            disclosure.not_implemented()


if __name__ == "__main__":
    unittest.main()

import copy
import inspect
import unittest

from hai_mr05 import (
    canonical,
    cloud_boundary,
    context_builder,
    disclosure,
    discovery,
    failures,
    identity,
    metrics,
    mr03_adapter,
    mr04_adapter,
    normalization,
    provenance,
)


class CloudBoundaryRuntimeTests(unittest.TestCase):
    @staticmethod
    def _task():
        return {
            "schema_version": "1.0.0",
            "task_id": "mr14b-cloud-admission",
            "task_type": "EVIDENCE_REVIEW",
            "task_text": "Review supplied deterministic evidence.",
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
    def _descriptor(raw=b'{"cloud":1}'):
        payload = {
            "schema_version": "1.0.0",
            "source_type": "LOCAL_FILE",
            "canonical_locator": {
                "source_alias": "fixture",
                "relative_path": "cloud.json",
            },
            "content_identity": {
                "algorithm": "SHA-256",
                "sha256": identity.sha256_bytes(raw),
            },
            "content_size_bytes": len(raw),
            "classification": "PUBLIC",
            "immutability_status": "IMMUTABLE_CAPTURE",
            "availability_status": "AVAILABLE",
            "provenance_owner": "test-fixture",
        }
        return {
            **payload,
            "source_id": discovery.source_descriptor_identity(payload),
        }

    @staticmethod
    def _dependency_record(
        discovered,
        normalized,
        source_ref,
        role,
        upstream=None,
    ):
        if role == "MR03_PACKAGER":
            dependency = {
                "dependency_role": "MR03_PACKAGER",
                "dependency_logical_id": "MR03",
                "expected_dependency_class": "FROZEN_MR03_EVIDENCE_PACKAGER",
                "dependency_contract_identity": None,
                "dependency_version_identity": "MR03-PACKAGE-V1",
                "dependency_content_identity": {
                    "kind": "COMMITTED_FILESET",
                    "sha256": "3e85d8eebc1eef05a5ee6e9f18701e0686cb21c0cec6599df32ec09e1168dc48",
                },
                "dependency_snapshot": {
                    "commit": "945559bf0f1811cb2f88e827ff1412081f1fbd75",
                    "parent": "44ef1ef7f202c8a7ff85cb8f3a329d9ef76fd5e3",
                    "tree": "09dfcd9ff69362ae019b2876a66ec78d54008337",
                    "pathset_sha256": None,
                },
            }
        else:
            dependency = {
                "dependency_role": "MR04_GUARD",
                "dependency_logical_id": "MR04",
                "expected_dependency_class": "FROZEN_MR04_LOWER_LEVEL_COMPOSITION",
                "dependency_contract_identity": "0e110454fdd399db1564a2f7fdc581faabbea190ba0d668fc674243bbb414e32",
                "dependency_version_identity": None,
                "dependency_content_identity": {
                    "kind": "CONTENTSET",
                    "sha256": "a1da9509f5e5acc102be249978323bc9706cc893f178f96b70b9317750687b5f",
                },
                "dependency_snapshot": {
                    "commit": "8ce9eb8a542799e00088a6654e1061405fde7d33",
                    "parent": "85c3f65e23aba4c7307b5870d73c8192a72b46f5",
                    "tree": "a8944259034b699c285e2b8551ad60e3ee79d5c2",
                    "pathset_sha256": "2b58d0ee14b2c8280b608ea9a8717228c68675d15630a80a2d06f63212ba4640",
                },
            }
        dependency.update(
            {
                "schema_version": "1.0.0",
                "source_ref": source_ref,
                "input_binding": {
                    "task_identity": discovered.task_identity,
                    "source_set_identity": discovered.source_set_identity,
                    "discovery_identity": discovered.discovery_identity,
                    "normalization_identity": normalized.normalization_identity,
                    "upstream_dependency_identity": upstream,
                },
            }
        )
        return dependency

    @classmethod
    def _context_package(cls):
        raw = b'{"cloud":1}'
        source = cls._descriptor(raw)
        discovered = discovery.discover(
            cls._task(),
            [source],
            max_item_count=1,
            max_bytes=1000,
        )
        row = normalization.NormalizedItem.from_source(
            discovered.selected_sources[0],
            phase_id="MR14B",
            artifact_type="EVIDENCE",
            current_validity="VALID",
            supersession="NONE",
            classification="PUBLIC",
            mandatory=True,
        )
        normalized = normalization.normalize(discovered, [row])
        source_ref = {
            "schema_version": "1.0.0",
            **discovered.selected_sources[0].to_dict(),
        }
        mr03_record = cls._dependency_record(
            discovered,
            normalized,
            source_ref,
            "MR03_PACKAGER",
        )
        mr03 = mr03_adapter.bind_mr03_dependency(
            mr03_record,
            discovered,
            normalized,
            source_ref,
        )
        mr04_record = cls._dependency_record(
            discovered,
            normalized,
            source_ref,
            "MR04_GUARD",
            mr03.binding_identity,
        )
        mr04 = mr04_adapter.bind_mr04_dependency(
            mr04_record,
            discovered,
            normalized,
            mr03.binding_identity,
            source_ref,
        )
        metric = metrics.Metrics(
            raw_source_bytes=discovered.total_selected_bytes,
            normalized_bytes=normalized.output_bytes,
            package_bytes=normalized.output_bytes,
            source_ref_count=1,
        )
        required = (
            ("TASK_IDENTITY", discovered.task_identity),
            ("SOURCE_SET_IDENTITY", discovered.source_set_identity),
            ("DISCOVERY_IDENTITY", discovered.discovery_identity),
            ("NORMALIZATION_IDENTITY", normalized.normalization_identity),
            ("MR03_BINDING_IDENTITY", mr03.binding_identity),
            ("MR04_BINDING_IDENTITY", mr04.binding_identity),
            ("METRICS_IDENTITY", metric.metrics_identity),
        )
        chain = provenance.ProvenanceChain(
            nodes=tuple(
                provenance.ProvenanceNode(
                    name,
                    value,
                    f"fixture/{name.lower()}",
                )
                for name, value in required
            ),
            edges=(),
        )
        return context_builder.build_context(
            discovered,
            normalized,
            (mr03, mr04),
            chain,
            metric,
            max_context_bytes=100000,
        )

    @staticmethod
    def _budget(max_cloud_context_bytes=100000, budget_identity="1" * 64):
        return {
            "budget_identity": budget_identity,
            "max_cloud_context_bytes": max_cloud_context_bytes,
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

    def _admit(
        self,
        package,
        *,
        max_cloud_context_bytes=100000,
        run_identity="2" * 64,
        mr03_package_identity="3" * 64,
        mr04_result_identity="4" * 64,
        budget_identity="1" * 64,
        prohibited_assumptions=(),
        observational_metadata=None,
    ):
        return cloud_boundary.admit_cloud_context(
            package,
            disclosure.build_disclosure(classification="PUBLIC"),
            run_identity=run_identity,
            mr03_package_identity=mr03_package_identity,
            mr04_result_identity=mr04_result_identity,
            byte_budget=self._budget(max_cloud_context_bytes, budget_identity),
            estimated_token_metadata=self._token_metadata(),
            prohibited_assumptions=prohibited_assumptions,
            observational_metadata=observational_metadata,
        )

    def test_public_allow_emits_exact_frozen_cloud_context_schema(self):
        package = self._context_package()
        record = self._admit(package, prohibited_assumptions=("do not guess",))
        expected_required = {
            "schema_version",
            "run_identity",
            "task_identity",
            "source_set_identity",
            "mr03_package_identity",
            "mr04_result_identity",
            "context_items",
            "source_refs",
            "byte_budget",
            "estimated_token_metadata",
            "provenance_summary",
            "prohibited_assumptions",
            "proposal_schema_version",
            "disclosure_result",
            "context_identity",
        }
        self.assertEqual(set(record.to_dict()), expected_required)
        self.assertEqual(record.schema_version, "1.0.0")
        self.assertEqual(record.disclosure_result, "ALLOW")
        self.assertEqual(record.proposal_schema_version, "1.0.0")
        self.assertNotIn("schema_id", record.to_dict())
        self.assertNotIn("cloud_context_identity", record.to_dict())
        self.assertNotIn("bounded_context_package", record.to_dict())
        self.assertNotIn("context_byte_count", record.to_dict())
        self.assertNotIn("max_cloud_context_bytes", record.to_dict())
        self.assertEqual(
            tuple(record.identity_payload),
            cloud_boundary.CLOUD_CONTEXT_IDENTITY_PREIMAGE,
        )

    def test_context_identity_is_frozen_cloud_envelope_identity_not_inner_identity(self):
        package = self._context_package()
        record = self._admit(package)
        self.assertEqual(
            record.context_identity,
            identity.sha256_canonical(record.identity_payload),
        )
        self.assertNotEqual(record.context_identity, package.context_identity)
        self.assertEqual(
            cloud_boundary.compute_cloud_context_identity(record),
            record.context_identity,
        )

    def test_task_source_items_refs_and_provenance_are_projected_from_validated_package(self):
        package = self._context_package()
        record = self._admit(package)
        self.assertEqual(record.task_identity, package.input_identities["task_identity"])
        self.assertEqual(
            record.source_set_identity,
            package.input_identities["source_set_identity"],
        )
        self.assertEqual(
            [item["item_id"] for item in record.context_items],
            [item.item_identity for item in package.context_items],
        )
        self.assertEqual(record.provenance_summary["coverage_percent"], 100)
        self.assertEqual(
            record.provenance_summary["chain_identity"],
            package.provenance_identity,
        )
        self.assertEqual(
            record.provenance_summary["source_count"],
            len(record.source_refs),
        )
        self.assertEqual(
            dict(record.provenance_summary["dependency_commits"]),
            {
                "MR03": mr03_adapter.MR03_EXPECTED_COMMIT,
                "MR04": mr03_adapter.MR04_EXPECTED_COMMIT,
            },
        )
        for item in record.context_items:
            for source_ref in item["source_refs"]:
                self.assertIn(source_ref, record.source_refs)
                self.assertEqual(
                    source_ref["source_set_identity"],
                    record.source_set_identity,
                )

    def test_round_trip_mapping_order_and_observational_metadata_are_deterministic(self):
        package = self._context_package()
        first = self._admit(
            package,
            observational_metadata={"display": {"ratio": 1.5}},
        )
        repeated = cloud_boundary.CloudContext.from_mapping(
            dict(reversed(list(first.to_dict().items())))
        )
        second = self._admit(
            dict(reversed(list(package.to_dict().items()))),
            observational_metadata={"display": {"ratio": 9.5}},
        )
        self.assertEqual(repeated, first)
        self.assertEqual(first.context_identity, second.context_identity)
        self.assertNotEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(
            cloud_boundary.canonical_cloud_context_bytes(first),
            canonical.canonical_json_bytes(first.to_dict(), identity_critical=False),
        )

    def test_run_mr03_mr04_and_budget_identity_mutations_change_context_identity(self):
        package = self._context_package()
        baseline = self._admit(package)
        variants = (
            self._admit(package, run_identity="5" * 64),
            self._admit(package, mr03_package_identity="6" * 64),
            self._admit(package, mr04_result_identity="7" * 64),
            self._admit(package, budget_identity="8" * 64),
        )
        for variant in variants:
            with self.subTest(identity=variant.context_identity):
                self.assertNotEqual(variant.context_identity, baseline.context_identity)

    def test_final_canonical_cloud_context_bytes_are_budget_authority(self):
        package = self._context_package()
        large = self._admit(package, max_cloud_context_bytes=100000)
        self.assertEqual(
            large.canonical_byte_count,
            len(large.canonical_bytes()),
        )
        self.assertGreater(large.canonical_byte_count, package.context_byte_count)
        with self.assertRaises(
            cloud_boundary.CloudContextAdmissionValidationError
        ) as r2_regression:
            self._admit(
                package,
                max_cloud_context_bytes=package.context_byte_count,
            )
        self.assertEqual(
            r2_regression.exception.failure_code,
            failures.FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET.value,
        )

        budget = large.canonical_byte_count
        for _ in range(4):
            exact = self._admit(package, max_cloud_context_bytes=budget)
            if exact.canonical_byte_count == budget:
                break
            budget = exact.canonical_byte_count
        self.assertEqual(exact.canonical_byte_count, budget)
        with self.assertRaises(
            cloud_boundary.CloudContextAdmissionValidationError
        ) as under:
            self._admit(package, max_cloud_context_bytes=budget - 1)
        self.assertEqual(
            under.exception.failure_code,
            failures.FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET.value,
        )

    def test_disclosure_must_be_allow_without_duplicating_public_classification_policy(self):
        package = self._context_package()
        denied = (
            disclosure.build_disclosure(classification="INTERNAL"),
            disclosure.build_disclosure(classification="PROTECTED"),
            disclosure.build_disclosure(
                classification="PUBLIC",
                findings=[{"code": "REVIEW", "action": "ESCALATE"}],
            ),
        )
        for disclosure_record in denied:
            with self.subTest(result=disclosure_record.disclosure_result), self.assertRaises(
                cloud_boundary.CloudContextAdmissionValidationError
            ) as caught:
                cloud_boundary.admit_cloud_context(
                    package,
                    disclosure_record,
                    run_identity="2" * 64,
                    mr03_package_identity="3" * 64,
                    mr04_result_identity="4" * 64,
                    byte_budget=self._budget(),
                    estimated_token_metadata=self._token_metadata(),
                )
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.MR05_DISCLOSURE_DENIED.value,
            )
            self.assertFalse(caught.exception.retry_allowed)
        source = inspect.getsource(cloud_boundary)
        self.assertNotIn('classification != "PUBLIC"', source)
        self.assertNotIn('classification == "PUBLIC"', source)

    def test_schema_fields_policy_and_context_identity_forgery_fail_closed(self):
        package = self._context_package()
        base = self._admit(package).to_dict()

        unknown_field = copy.deepcopy(base)
        unknown_field["unexpected"] = True
        with self.assertRaises(cloud_boundary.CloudContextAdmissionValidationError):
            cloud_boundary.CloudContext.from_mapping(unknown_field)

        missing_field = copy.deepcopy(base)
        del missing_field["run_identity"]
        with self.assertRaises(cloud_boundary.CloudContextAdmissionValidationError):
            cloud_boundary.CloudContext.from_mapping(missing_field)

        unknown_major = copy.deepcopy(base)
        unknown_major["schema_version"] = "2.0.0"
        with self.assertRaises(
            cloud_boundary.CloudContextAdmissionValidationError
        ) as major_caught:
            cloud_boundary.CloudContext.from_mapping(unknown_major)
        self.assertEqual(
            major_caught.exception.failure_code,
            failures.FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value,
        )

        forged = copy.deepcopy(base)
        forged["context_identity"] = "0" * 64
        with self.assertRaises(
            cloud_boundary.CloudContextAdmissionValidationError
        ) as forged_caught:
            cloud_boundary.CloudContext.from_mapping(forged)
        self.assertEqual(
            forged_caught.exception.failure_code,
            failures.FailureCode.HASH_MISMATCH.value,
        )

    def test_nested_frozen_contracts_reject_invalid_values(self):
        package = self._context_package()
        base = self._admit(package).to_dict()
        mutations = []

        bad_budget = copy.deepcopy(base)
        bad_budget["byte_budget"]["silent_truncation"] = True
        mutations.append(bad_budget)

        bad_overflow = copy.deepcopy(base)
        bad_overflow["byte_budget"]["overflow_policy"] = "TRUNCATE"
        mutations.append(bad_overflow)

        bad_token = copy.deepcopy(base)
        bad_token["estimated_token_metadata"]["authority"] = "AUTHORITATIVE"
        mutations.append(bad_token)

        bad_provenance = copy.deepcopy(base)
        bad_provenance["provenance_summary"]["coverage_percent"] = 99
        mutations.append(bad_provenance)

        bad_proposal = copy.deepcopy(base)
        bad_proposal["proposal_schema_version"] = "9.9.9"
        mutations.append(bad_proposal)

        for candidate in mutations:
            candidate["context_identity"] = identity.sha256_canonical(
                {
                    key: candidate[key]
                    for key in cloud_boundary.CLOUD_CONTEXT_IDENTITY_PREIMAGE
                }
            )
            with self.subTest(candidate=candidate), self.assertRaises(
                cloud_boundary.CloudContextAdmissionValidationError
            ):
                cloud_boundary.CloudContext.from_mapping(candidate)

    def test_prohibited_assumptions_use_frozen_lexical_order(self):
        package = self._context_package()
        ordered = self._admit(
            package,
            prohibited_assumptions=("alpha", "beta"),
        )
        self.assertEqual(ordered.prohibited_assumptions, ("alpha", "beta"))

        candidate = copy.deepcopy(ordered.to_dict())
        candidate["prohibited_assumptions"] = ["beta", "alpha"]
        candidate["context_identity"] = identity.sha256_canonical(
            {
                key: candidate[key]
                for key in cloud_boundary.CLOUD_CONTEXT_IDENTITY_PREIMAGE
            }
        )
        with self.assertRaises(
            cloud_boundary.CloudContextAdmissionValidationError
        ) as caught:
            cloud_boundary.CloudContext.from_mapping(candidate)
        self.assertEqual(
            caught.exception.failure_code,
            failures.FailureCode.NONDETERMINISTIC_OUTPUT.value,
        )

    def test_explicit_governed_identity_inputs_are_required_and_validated(self):
        package = self._context_package()
        allowed = disclosure.build_disclosure(classification="PUBLIC")
        for field, value in (
            ("run_identity", True),
            ("mr03_package_identity", "A" * 64),
            ("mr04_result_identity", "short"),
        ):
            kwargs = {
                "run_identity": "2" * 64,
                "mr03_package_identity": "3" * 64,
                "mr04_result_identity": "4" * 64,
                "byte_budget": self._budget(),
                "estimated_token_metadata": self._token_metadata(),
            }
            kwargs[field] = value
            with self.subTest(field=field), self.assertRaises(
                cloud_boundary.CloudContextAdmissionValidationError
            ):
                cloud_boundary.admit_cloud_context(package, allowed, **kwargs)

    def test_admission_does_not_repack_or_truncate_context(self):
        package = self._context_package()
        record = self._admit(package)
        self.assertEqual(
            [item["item_id"] for item in record.context_items],
            list(package.included_item_identities),
        )
        self.assertEqual(
            cloud_boundary.NO_REPACK_POLICY,
            "EXACT_BOUNDED_CONTEXT_PROJECTION_ONLY",
        )
        self.assertEqual(cloud_boundary.PARTIAL_CONTEXT_TRUNCATION, "NOT_ALLOWED")
        self.assertEqual(cloud_boundary.CONTEXT_REPACK_IMPLEMENTATION_COUNT, 0)
        self.assertEqual(
            cloud_boundary.PARTIAL_CONTEXT_TRUNCATION_IMPLEMENTATION_COUNT,
            0,
        )
        self.assertEqual(cloud_boundary.CLOUD_REQUEST_BUILD_COUNT, 1)

    def test_cloud_request_emits_exact_frozen_schema_and_identity(self):
        context = self._admit(self._context_package())
        request = cloud_boundary.build_cloud_request(
            context,
            model_identifier="openai/gpt-5.6-luna",
            human_authorization_reference="human://mr14c/r1",
        )
        self.assertEqual(
            set(request.to_dict()),
            {
                "schema_version", "run_identity", "context_identity",
                "request_identity", "model_identifier", "reasoning_metadata",
                "attempt_number", "max_attempts", "required_response_schema",
                "request_policy_version", "human_authorization_reference",
            },
        )
        self.assertEqual(request.schema_version, "1.0.0")
        self.assertEqual(request.run_identity, context.run_identity)
        self.assertEqual(request.context_identity, context.context_identity)
        self.assertEqual(request.attempt_number, 1)
        self.assertEqual(request.max_attempts, 1)
        self.assertEqual(request.required_response_schema, "mr05-cloud-proposal:1.0.0")
        self.assertEqual(request.request_policy_version, "1.0.0")
        self.assertEqual(
            dict(request.reasoning_metadata),
            {"OPENCLAW_REASONING": "ON", "PROJECT_REASONING_PROFILE": "MAX"},
        )
        self.assertEqual(
            tuple(request.identity_payload),
            cloud_boundary.CLOUD_REQUEST_IDENTITY_PREIMAGE,
        )
        self.assertEqual(
            request.request_identity, identity.sha256_canonical(request.identity_payload)
        )
        self.assertEqual(
            cloud_boundary.compute_cloud_request_identity(request),
            request.request_identity,
        )

    def test_human_authorization_and_observational_metadata_are_excluded_from_request_identity(self):
        context = self._admit(self._context_package())
        first = cloud_boundary.build_cloud_request(
            context,
            model_identifier="openai/gpt-5.6-luna",
            human_authorization_reference="human://one",
            observational_metadata={"transport_note": "one"},
        )
        second = cloud_boundary.build_cloud_request(
            context,
            model_identifier="openai/gpt-5.6-luna",
            human_authorization_reference="human://two",
            observational_metadata={"transport_note": "two"},
        )
        self.assertEqual(first.request_identity, second.request_identity)
        self.assertNotEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertNotIn("human_authorization_reference", first.identity_payload)
        self.assertNotIn("observational_metadata", first.identity_payload)

    def test_model_identifier_is_identity_bound(self):
        context = self._admit(self._context_package())
        first = cloud_boundary.build_cloud_request(
            context, model_identifier="model-a",
            human_authorization_reference="human://mr14c/r1",
        )
        second = cloud_boundary.build_cloud_request(
            context, model_identifier="model-b",
            human_authorization_reference="human://mr14c/r1",
        )
        self.assertNotEqual(first.request_identity, second.request_identity)
        self.assertEqual(first.run_identity, second.run_identity)
        self.assertEqual(first.context_identity, second.context_identity)

    def test_cloud_request_requires_explicit_human_authorization_reference(self):
        context = self._admit(self._context_package())
        for value in ("", None, True):
            with self.subTest(value=value), self.assertRaises(
                cloud_boundary.CloudRequestValidationError
            ) as caught:
                cloud_boundary.build_cloud_request(
                    context, model_identifier="model-a",
                    human_authorization_reference=value,
                )
            self.assertEqual(
                caught.exception.failure_code,
                failures.FailureCode.MR05_MODEL_UNAUTHORIZED.value,
            )

    def test_cloud_request_frozen_attempt_reasoning_and_response_policy_fail_closed(self):
        context = self._admit(self._context_package())
        base = cloud_boundary.build_cloud_request(
            context, model_identifier="model-a",
            human_authorization_reference="human://mr14c/r1",
        ).to_dict()
        mutations = []
        for field, value in (
            ("attempt_number", 2),
            ("max_attempts", 2),
            ("required_response_schema", "other:1.0.0"),
            ("request_policy_version", "9.9.9"),
        ):
            candidate = copy.deepcopy(base)
            candidate[field] = value
            candidate["request_identity"] = identity.sha256_canonical(
                {key: candidate[key] for key in cloud_boundary.CLOUD_REQUEST_IDENTITY_PREIMAGE}
            )
            mutations.append(candidate)
        bad_reasoning = copy.deepcopy(base)
        bad_reasoning["reasoning_metadata"]["PROJECT_REASONING_PROFILE"] = "MEDIUM"
        bad_reasoning["request_identity"] = identity.sha256_canonical(
            {key: bad_reasoning[key] for key in cloud_boundary.CLOUD_REQUEST_IDENTITY_PREIMAGE}
        )
        mutations.append(bad_reasoning)
        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(
                cloud_boundary.CloudRequestValidationError
            ):
                cloud_boundary.CloudRequest.from_mapping(candidate)

    def test_cloud_request_schema_unknown_fields_unknown_major_and_forgery_fail_closed(self):
        context = self._admit(self._context_package())
        base = cloud_boundary.build_cloud_request(
            context, model_identifier="model-a",
            human_authorization_reference="human://mr14c/r1",
        ).to_dict()
        unknown = copy.deepcopy(base)
        unknown["provider_request_id"] = "forbidden"
        with self.assertRaises(cloud_boundary.CloudRequestValidationError):
            cloud_boundary.CloudRequest.from_mapping(unknown)
        missing = copy.deepcopy(base)
        del missing["human_authorization_reference"]
        with self.assertRaises(cloud_boundary.CloudRequestValidationError):
            cloud_boundary.CloudRequest.from_mapping(missing)
        major = copy.deepcopy(base)
        major["schema_version"] = "2.0.0"
        with self.assertRaises(cloud_boundary.CloudRequestValidationError) as major_caught:
            cloud_boundary.CloudRequest.from_mapping(major)
        self.assertEqual(
            major_caught.exception.failure_code,
            failures.FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value,
        )
        forged = copy.deepcopy(base)
        forged["request_identity"] = "0" * 64
        with self.assertRaises(cloud_boundary.CloudRequestValidationError) as forged_caught:
            cloud_boundary.CloudRequest.from_mapping(forged)
        self.assertEqual(
            forged_caught.exception.failure_code,
            failures.FailureCode.HASH_MISMATCH.value,
        )

    def test_request_builder_has_no_live_execution_or_retry_authority(self):
        context = self._admit(self._context_package())
        request = cloud_boundary.build_cloud_request(
            context, model_identifier="model-a",
            human_authorization_reference="human://mr14c/r1",
        )
        self.assertIsInstance(request, cloud_boundary.CloudRequest)
        self.assertEqual(cloud_boundary.CLOUD_REQUEST_BUILD_COUNT, 1)
        for name in (
            "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT",
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(cloud_boundary, name), 0)

    def test_runtime_has_zero_external_and_progression_authority(self):
        self.assertEqual(cloud_boundary.CLOUD_CONTEXT_ADMISSION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(cloud_boundary.CLOUD_REQUEST_BUILD_COUNT, 1)
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
            "SOURCE_ACQUISITION_IMPLEMENTATION_COUNT",
            "DEPENDENCY_EXECUTION_IMPLEMENTATION_COUNT",
            "EVIDENCE_PERSISTENCE_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT",
            "CONTEXT_REPACK_IMPLEMENTATION_COUNT",
            "PARTIAL_CONTEXT_TRUNCATION_IMPLEMENTATION_COUNT",
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(cloud_boundary, name), 0)

    def test_runtime_source_has_no_external_execution_surface(self):
        source = inspect.getsource(cloud_boundary)
        for forbidden in (
            "import socket",
            "import subprocess",
            "import requests",
            "import httpx",
            "import urllib",
            "import openai",
            "import anthropic",
            "import boto3",
            "subprocess.",
            "socket.",
            "requests.",
            "httpx.",
            "urllib.",
            "os.environ",
            "os.getenv",
            "pathlib.Path",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_legacy_placeholder_entrypoint_remains_fail_closed(self):
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            cloud_boundary.not_implemented()


if __name__ == "__main__":
    unittest.main()

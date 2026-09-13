import io
import json
import unittest

from hai_mr05 import cli, discovery, materialization, metrics, mr03_adapter, mr04_adapter, normalization, provenance, workflow
import tests.test_final_result_runtime as _final_fixture_module


class PrepareInputMaterializationRuntimeTests(unittest.TestCase):
    @classmethod
    def _materialization_arguments(cls) -> tuple[dict[str, object], dict[str, object]]:
        fixture = _final_fixture_module.FinalResultRuntimeTests
        source = fixture._descriptor()
        discovered = discovery.discover(
            fixture._task(),
            [source],
            max_item_count=1,
            max_bytes=1000,
        )
        row = normalization.NormalizedItem.from_source(
            discovered.selected_sources[0],
            phase_id="MR14G",
            artifact_type="EVIDENCE",
            current_validity="VALID",
            supersession="NONE",
            classification="PUBLIC",
            mandatory=True,
        )
        normalized = normalization.normalize(discovered, [row])
        source_ref = {"schema_version": "1.0.0", **discovered.selected_sources[0].to_dict()}
        mr03 = mr03_adapter.bind_mr03_dependency(
            fixture._dependency_record(
                discovered,
                normalized,
                source_ref,
                "MR03_PACKAGER",
            ),
            discovered,
            normalized,
            source_ref,
        )
        mr04 = mr04_adapter.bind_mr04_dependency(
            fixture._dependency_record(
                discovered,
                normalized,
                source_ref,
                "MR04_GUARD",
                mr03.binding_identity,
            ),
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
        provenance_chain = provenance.ProvenanceChain(
            nodes=tuple(
                provenance.ProvenanceNode(name, value, f"fixture/{name.lower()}")
                for name, value in required
            ),
            edges=(),
        )
        full = fixture._full_chain()
        disclosure_record = full["disclosure"]
        arguments = {
            "discovery_result": discovered.to_dict(),
            "normalization_result": normalized.to_dict(),
            "dependency_bindings": [mr03.to_dict(), mr04.to_dict()],
            "provenance_chain": provenance_chain.to_dict(),
            "metrics_raw_source_bytes": metric.raw_source_bytes,
            "metrics_normalized_bytes": metric.normalized_bytes,
            "metrics_package_bytes": metric.package_bytes,
            "metrics_cloud_context_bytes": metric.cloud_context_bytes,
            "metrics_raw_estimated_tokens": metric.raw_estimated_tokens,
            "metrics_cloud_estimated_tokens": metric.cloud_estimated_tokens,
            "metrics_model_call_count": metric.model_call_count,
            "metrics_model_retry_count": metric.model_retry_count,
            "metrics_failure_count": metric.failure_count,
            "metrics_source_ref_count": metric.source_ref_count,
            "metrics_missing_source_ref_count": metric.missing_source_ref_count,
            "metrics_identity_mismatch_count": metric.identity_mismatch_count,
            "metrics_observational_metadata": dict(metric.observational_metadata),
            "max_context_bytes": 100000,
            "mr03_result_identity": "4" * 64,
            "mr04_result_identity": "5" * 64,
            "frozen_run_byte_budget": {
                "budget_identity": "c" * 64,
                "max_raw_bytes": 100000,
                "max_normalized_bytes": 100000,
                "max_package_bytes": 100000,
                "max_cloud_context_bytes": 100000,
                "byte_budget_policy_version": "1.0.0",
                "overflow_policy": "BLOCK_OR_DETERMINISTIC_REPACK",
                "silent_truncation": False,
            },
            "frozen_run_state": "VERIFIED_PASS_FOR_REVIEW",
            "frozen_run_observational_metadata": None,
            "disclosure_classification": disclosure_record.classification,
            "disclosure_findings": [item.to_dict() for item in disclosure_record.findings],
            "disclosure_observational_metadata": (
                None
                if disclosure_record.observational_metadata is None
                else dict(disclosure_record.observational_metadata)
            ),
            "model_identifier": "openai/gpt-5.6-luna",
            "human_authorization_reference": "human-auth:final-result-fixture",
            "estimated_token_metadata": fixture._token_metadata(),
            "authorized_provider_identifier": "provider-fixture",
            "authorized_account_boundary_reference": "account://workflow-fixture",
            "authorization_observational_metadata": None,
            "legacy_verifier_checks": [item.to_dict() for item in full["legacy"].checks],
            "verifier_failure_records": [item.to_dict() for item in full["verifier_failures"]],
        }
        return arguments, full

    def test_materialization_reconstructs_authoritative_context_and_frozen_run(self):
        arguments, full = self._materialization_arguments()
        result = materialization.materialize_prepare_inputs(**arguments)
        self.assertEqual(result.bounded_context_identity, full["bounded_context"].context_identity)
        self.assertEqual(result.frozen_run_identity, full["run"].run_identity)
        self.assertEqual(result.metrics_identity, full["metric"].metrics_identity)
        self.assertEqual(result.prepare_arguments["run_record"], full["run"].to_dict())
        self.assertEqual(
            result.prepare_arguments["bounded_context_record"],
            full["bounded_context"].to_dict(),
        )
        round_trip = materialization.PrepareInputMaterialization.from_mapping(result.to_dict())
        self.assertEqual(round_trip, result)

    def test_materialized_prepare_matches_direct_pre_send_chain(self):
        arguments, _ = self._materialization_arguments()
        result = materialization.materialize_prepare_inputs(**arguments)
        prepared = workflow.prepare_top_level_workflow(**dict(result.prepare_arguments))
        self.assertEqual(prepared.execution_authority, "NONE")
        self.assertEqual(prepared.run_record.run_identity, result.frozen_run_identity)
        self.assertEqual(
            prepared.bounded_context_record.context_identity,
            result.bounded_context_identity,
        )

    def test_materialize_cli_emits_identity_bound_pre_send_package(self):
        arguments, _ = self._materialization_arguments()
        request = {
            "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
            "operation": cli.MATERIALIZE_CLI_OPERATION,
            "materialization_arguments": arguments,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(
            cli.main(
                [cli.MATERIALIZE_CLI_COMMAND],
                stdin=io.StringIO(json.dumps(request)),
                stdout=stdout,
                stderr=stderr,
            ),
            0,
        )
        self.assertEqual(stderr.getvalue(), "")
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["status"], "PASS")
        self.assertEqual(output["operation"], cli.MATERIALIZE_CLI_OPERATION)
        self.assertEqual(output["execution_authority"], "NONE")
        self.assertFalse(output["network_authority"])
        self.assertFalse(output["model_provider_authority"])
        materialized = materialization.PrepareInputMaterialization.from_mapping(
            output["materialization"]
        )
        prepared = workflow.PreSendWorkflowPackage.from_mapping(output["prepared_workflow"])
        self.assertEqual(materialized.frozen_run_identity, prepared.run_record.run_identity)
        self.assertEqual(output["pre_send_identity"], prepared.pre_send_identity)

    def test_tampered_upstream_identity_fails_closed_before_prepare(self):
        arguments, _ = self._materialization_arguments()
        arguments["normalization_result"]["discovery_identity"] = "0" * 64
        request = {
            "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
            "operation": cli.MATERIALIZE_CLI_OPERATION,
            "materialization_arguments": arguments,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(
            cli.main(
                [cli.MATERIALIZE_CLI_COMMAND],
                stdin=io.StringIO(json.dumps(request)),
                stdout=stdout,
                stderr=stderr,
            ),
            2,
        )
        self.assertEqual(stdout.getvalue(), "")
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["status"], "FAIL_CLOSED")
        self.assertEqual(failure["operation"], cli.MATERIALIZE_CLI_OPERATION)

    def test_materialization_authority_surface_is_zero(self):
        self.assertEqual(materialization.MATERIALIZATION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(cli.MATERIALIZATION_CLI_IMPLEMENTATION_COUNT, 1)
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
            "FILESYSTEM_READ_COUNT",
            "FILESYSTEM_WRITE_COUNT",
            "DEPENDENCY_EXECUTION_COUNT",
            "GIT_OPERATION_COUNT",
        ):
            self.assertEqual(getattr(materialization, name), 0, name)


if __name__ == "__main__":
    unittest.main()

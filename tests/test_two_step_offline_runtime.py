import base64
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import cli, cloud_boundary, evidence, workflow
import tests.test_cli_runtime as _cli_fixture_module


class TwoStepOfflineRuntimeTests(unittest.TestCase):
    @staticmethod
    def _split_request(approved_root: str):
        request = _cli_fixture_module.OfflineCLIRuntimeTests._request(approved_root)
        full = dict(request["workflow_arguments"])
        prepare = {key: value for key, value in full.items() if key in cli._PREPARE_FIELDS}
        resume = {key: value for key, value in full.items() if key in cli._RESUME_FIELDS}
        return request, prepare, resume

    def test_prepare_is_zero_send_and_performs_no_final_evidence_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            request, prepare_args, _ = self._split_request(tmp)
            prepare_request = {
                "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
                "operation": cli.PREPARE_CLI_OPERATION,
                "prepare_arguments": prepare_args,
            }
            with mock.patch.object(
                cloud_boundary,
                "adapt_governed_external_transport_response",
                wraps=cloud_boundary.adapt_governed_external_transport_response,
            ) as transport, mock.patch.object(
                evidence,
                "persist_final_evidence_records",
                wraps=evidence.persist_final_evidence_records,
            ) as persistence:
                stdout = io.StringIO()
                stderr = io.StringIO()
                code = cli.main(
                    ["prepare"],
                    stdin=io.StringIO(json.dumps(prepare_request)),
                    stdout=stdout,
                    stderr=stderr,
                )
            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(transport.call_count, 0)
            self.assertEqual(persistence.call_count, 0)
            self.assertFalse(Path(tmp, "offline").exists())
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["operation"], cli.PREPARE_CLI_OPERATION)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["execution_authority"], "NONE")
            self.assertFalse(result["network_authority"])
            self.assertFalse(result["model_provider_authority"])
            prepared = workflow.PreSendWorkflowPackage.from_mapping(result["prepared_workflow"])
            self.assertEqual(prepared.pre_send_identity, result["pre_send_identity"])
            self.assertEqual(prepared.cloud_execution_handoff_record.handoff_identity, result["handoff_identity"])
            self.assertEqual(
                workflow.validate_pre_send_workflow_package(prepared).pre_send_identity,
                prepared.pre_send_identity,
            )

    def test_prepare_then_resume_matches_one_shot_authoritative_identities(self):
        with tempfile.TemporaryDirectory() as two_step_root, tempfile.TemporaryDirectory() as one_shot_root:
            original, prepare_args, resume_args = self._split_request(two_step_root)
            prepare_request = {
                "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
                "operation": cli.PREPARE_CLI_OPERATION,
                "prepare_arguments": prepare_args,
            }
            prepare_stdout = io.StringIO()
            self.assertEqual(
                cli.main(
                    ["prepare"],
                    stdin=io.StringIO(json.dumps(prepare_request)),
                    stdout=prepare_stdout,
                    stderr=io.StringIO(),
                ),
                0,
            )
            prepared_summary = json.loads(prepare_stdout.getvalue())
            Path(two_step_root, "offline").mkdir()
            resume_request = {
                "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
                "operation": cli.RESUME_CLI_OPERATION,
                "prepared_workflow": prepared_summary["prepared_workflow"],
                "resume_arguments": resume_args,
                "raw_provider_response_base64": original["raw_provider_response_base64"],
            }
            resume_stdout = io.StringIO()
            resume_stderr = io.StringIO()
            self.assertEqual(
                cli.main(
                    ["resume"],
                    stdin=io.StringIO(json.dumps(resume_request)),
                    stdout=resume_stdout,
                    stderr=resume_stderr,
                ),
                0,
            )
            self.assertEqual(resume_stderr.getvalue(), "")
            two_step = json.loads(resume_stdout.getvalue())
            self.assertEqual(two_step["operation"], cli.RESUME_CLI_OPERATION)
            self.assertTrue(Path(two_step_root, "offline", "manifest.json").is_file())
            self.assertTrue(Path(two_step_root, "offline", "final.json").is_file())

            one_shot_request = _cli_fixture_module.OfflineCLIRuntimeTests._request(one_shot_root)
            Path(one_shot_root, "offline").mkdir()
            one_shot_stdout = io.StringIO()
            self.assertEqual(
                cli.main(
                    ["offline"],
                    stdin=io.StringIO(json.dumps(one_shot_request)),
                    stdout=one_shot_stdout,
                    stderr=io.StringIO(),
                ),
                0,
            )
            one_shot = json.loads(one_shot_stdout.getvalue())
            for field in (
                "run_identity",
                "request_identity",
                "authorization_identity",
                "handoff_identity",
                "response_identity",
                "proposal_identity",
                "verification_identity",
                "manifest_identity",
                "final_result_identity",
            ):
                self.assertEqual(two_step[field], one_shot[field], field)

    def test_resume_rejects_tampered_pre_send_package_before_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, prepare_args, resume_args = self._split_request(tmp)
            prepared = workflow.prepare_top_level_workflow(**prepare_args).to_dict()
            prepared["cloud_execution_handoff_record"] = dict(
                prepared["cloud_execution_handoff_record"]
            )
            prepared["cloud_execution_handoff_record"]["handoff_identity"] = "0" * 64
            Path(tmp, "offline").mkdir()
            resume_request = {
                "schema_version": cli.OFFLINE_CLI_SCHEMA_VERSION,
                "operation": cli.RESUME_CLI_OPERATION,
                "prepared_workflow": prepared,
                "resume_arguments": resume_args,
                "raw_provider_response_base64": original["raw_provider_response_base64"],
            }
            stderr = io.StringIO()
            with mock.patch.object(
                evidence,
                "persist_final_evidence_records",
                wraps=evidence.persist_final_evidence_records,
            ) as persistence:
                code = cli.main(
                    ["resume"],
                    stdin=io.StringIO(json.dumps(resume_request)),
                    stdout=io.StringIO(),
                    stderr=stderr,
                )
            self.assertEqual(code, 2)
            self.assertEqual(persistence.call_count, 0)
            failure = json.loads(stderr.getvalue())
            self.assertEqual(failure["operation"], cli.RESUME_CLI_OPERATION)
            self.assertEqual(failure["status"], "FAIL_CLOSED")
            self.assertFalse(Path(tmp, "offline", "manifest.json").exists())
            self.assertFalse(Path(tmp, "offline", "final.json").exists())

    def test_two_step_signatures_and_authority_surface_are_frozen(self):
        self.assertEqual(cli.TWO_STEP_CLI_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(workflow.PRE_SEND_PREPARATION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(workflow.TWO_STEP_RESUME_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(workflow.PRE_SEND_EXECUTION_AUTHORITY, "NONE")
        self.assertEqual(cli._prepare_signature_contract(), (cli._PREPARE_FIELDS, cli._PREPARE_REQUIRED_FIELDS))
        self.assertEqual(cli._resume_signature_contract(), (cli._RESUME_FIELDS, cli._RESUME_REQUIRED_FIELDS))
        for module in (cli, workflow):
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
            ):
                self.assertEqual(getattr(module, name), 0, f"{module.__name__}.{name}")


if __name__ == "__main__":
    unittest.main()

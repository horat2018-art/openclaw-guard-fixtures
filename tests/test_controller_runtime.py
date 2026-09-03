from __future__ import annotations
import sys, tempfile, unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/"src"
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from hai_mr05 import controller, dependency_runtime, evidence
SHA_A="a"*64; SHA_B="b"*64; SHA_C="c"*64; SHA_D="d"*64; COMMIT="1"*40
class ControllerRuntimeTests(unittest.TestCase):
    def _run(self, root, transition=controller.TRANSITION_HOLD):
        return controller.orchestrate_deterministic_run(transition_kind=transition, approved_source_root=root, source_relative_path="input.txt", source_alias="fixture", provenance_owner="MR09B_TEST", repository_commit=COMMIT, task_identity=SHA_A, contract_identities=(SHA_B,), dependency_identities=(SHA_C,), provenance_identity=SHA_D, metrics_identity=SHA_A, operational_counters={"source_reads":1,"network":0,"evidence_persistence":0})
    def test_hold_orchestration_is_deterministic_and_non_authorizing(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"deterministic-input\n"); a=self._run(d); b=self._run(d)
        self.assertEqual(a.acquisition.capture_identity,b.acquisition.capture_identity); self.assertEqual(a.run_record.run_identity,b.run_record.run_identity); self.assertEqual(a.evidence_manifest.manifest_identity,b.evidence_manifest.manifest_identity)
        self.assertIsNone(a.persistence_result)
        self.assertFalse(a.controller_progress_authority); self.assertFalse(a.human_approval); self.assertFalse(a.evidence_write_authority); self.assertFalse(a.git_authority); self.assertFalse(a.model_provider_authority)
    def test_review_ready_is_qualified_without_progress_authority(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"review-ready"); r=self._run(d,controller.TRANSITION_READY_FOR_HUMAN_REVIEW_GATE)
        self.assertEqual(r.transition.semantic_status,"QUALIFIED / PASS"); self.assertFalse(r.transition.human_gate_required); self.assertEqual(r.transition.implementation_authority,"NONE"); self.assertFalse(r.controller_progress_authority)
    def test_progress_fails_closed_without_human_gate_execution(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"x")
            with self.assertRaisesRegex(controller.ControllerPolicyError,"Human Gate"): self._run(d,controller.TRANSITION_PROGRESS)
    def test_fail_closed_transition_executes_no_source_read(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(controller.ControllerPolicyError,"terminal"): self._run(d,controller.TRANSITION_FAIL_CLOSED)
    def test_forbidden_counter_fails_before_capture(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"x")
            with self.assertRaisesRegex(controller.ControllerPolicyError,"forbidden"):
                controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="owner",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters={"network":1})
    @staticmethod
    def _dependency_kwargs():
        return {
            "dependency_task":{"task_id":"fixture-task"},
            "normalization_identity":SHA_B,
            "source_set_identity":SHA_C,
            "byte_budget":{"budget_identity":SHA_D,"max_raw_bytes":100000,"max_normalized_bytes":100000,"max_package_bytes":100000,"max_cloud_context_bytes":100000},
            "token_estimate_metadata":{"estimator_name":"non_whitespace_groups_div4","estimator_version":"1.0.0","authority":"ADVISORY_ONLY","input_bytes":100,"estimated_tokens":25,"confidence":"ADVISORY"},
        }
    def test_frozen_dependency_runtime_is_invoked_once_and_bound_without_authority(self):
        mr03={"result_identity":"e"*64,"mr03_payload":{}}; mr04={"result_identity":"f"*64,"package_identity":"1"*64}
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"dependency-input")
            with mock.patch.object(dependency_runtime,"invoke_mr03",return_value=mr03) as call03, mock.patch.object(dependency_runtime,"invoke_mr04",return_value=mr04) as call04:
                r=controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="MR10B_TEST",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters={"source_reads":1,"network":0,"evidence_persistence":0},**self._dependency_kwargs())
        self.assertEqual(call03.call_count,1); self.assertEqual(call04.call_count,1)
        self.assertEqual(r.mr03_result,mr03); self.assertEqual(r.mr04_result,mr04)
        self.assertIn("e"*64,r.run_record.dependency_identities); self.assertIn("f"*64,r.run_record.dependency_identities)
        self.assertFalse(r.controller_progress_authority); self.assertFalse(r.human_approval); self.assertFalse(r.evidence_write_authority); self.assertFalse(r.git_authority); self.assertFalse(r.model_provider_authority)
        self.assertEqual(r.evidence_manifest.operational_counters["mr03_execution"],1); self.assertEqual(r.evidence_manifest.operational_counters["mr04_execution"],1)
    def test_partial_dependency_request_fails_closed_before_dependency_invocation(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"x")
            with mock.patch.object(dependency_runtime,"invoke_mr03") as call03, self.assertRaisesRegex(controller.ControllerPolicyError,"dependency_task"):
                controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="owner",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters={"source_reads":1},normalization_identity=SHA_B)
        call03.assert_not_called()
    def test_optional_evidence_persistence_invoked_once_and_bound_without_authority(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"persist-input")
            with mock.patch.object(evidence,"persist_evidence",wraps=evidence.persist_evidence) as persist:
                r=controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="MR11B_TEST",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters={"source_reads":1,"network":0,"evidence_persistence":0},approved_evidence_root=d,evidence_relative_path="manifest.json")
            self.assertEqual(persist.call_count,1)
            self.assertIsNotNone(r.persistence_result)
            self.assertEqual(Path(d,"manifest.json").read_bytes(),r.evidence_manifest.canonical_bytes())
        self.assertEqual(r.persistence_result.manifest_identity,r.evidence_manifest.manifest_identity)
        self.assertEqual(r.evidence_manifest.operational_counters["evidence_persistence"],1)
        self.assertEqual(r.evidence_manifest.operational_counters["filesystem_evidence_write"],1)
        self.assertFalse(r.controller_progress_authority); self.assertFalse(r.human_approval); self.assertFalse(r.evidence_write_authority); self.assertFalse(r.git_authority); self.assertFalse(r.model_provider_authority)
    def test_partial_evidence_persistence_request_fails_closed_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"input.txt").write_bytes(b"x")
            with mock.patch.object(evidence,"persist_evidence") as persist, self.assertRaisesRegex(controller.ControllerPolicyError,"supplied together"):
                controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="MR11B_TEST",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters={"source_reads":1},approved_evidence_root=d)
        persist.assert_not_called()
    def test_controller_derived_counters_fail_closed_before_delegated_operations(self):
        reserved = ("mr03_execution", "mr04_execution", "subprocess", "filesystem_dependency", "evidence_persistence", "filesystem_evidence_write")
        for counter_name in reserved:
            with self.subTest(counter_name=counter_name), tempfile.TemporaryDirectory() as d:
                Path(d,"input.txt").write_bytes(b"x")
                counters={"source_reads":1,counter_name:7}
                with mock.patch.object(dependency_runtime,"invoke_mr03") as call03, mock.patch.object(dependency_runtime,"invoke_mr04") as call04, mock.patch.object(evidence,"persist_evidence") as persist, self.assertRaisesRegex(controller.ControllerPolicyError,"forbidden"):
                    controller.orchestrate_deterministic_run(transition_kind=controller.TRANSITION_HOLD,approved_source_root=d,source_relative_path="input.txt",source_alias="fixture",provenance_owner="MR11D_TEST",repository_commit=COMMIT,task_identity=SHA_A,contract_identities=(SHA_B,),dependency_identities=(SHA_C,),provenance_identity=SHA_D,metrics_identity=SHA_A,operational_counters=counters,approved_evidence_root=d,evidence_relative_path="manifest.json",**self._dependency_kwargs())
                call03.assert_not_called(); call04.assert_not_called(); persist.assert_not_called()
    def test_external_boundary_counters_are_bounded(self):
        self.assertEqual(controller.CONTROLLER_IMPLEMENTATION_COUNT,1); self.assertEqual(controller.OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT,1)
        self.assertEqual(controller.MR03_EXECUTION_IMPLEMENTATION_COUNT,1); self.assertEqual(controller.MR04_EXECUTION_IMPLEMENTATION_COUNT,1)
        self.assertEqual(controller.EVIDENCE_PERSISTENCE_COUNT,1)
        for n in ("STATE_TRANSITION_EXECUTION_COUNT","HUMAN_APPROVAL_EXECUTION_COUNT","HUMAN_GATE_EXECUTION_COUNT","FILESYSTEM_WRITE_IMPLEMENTATION_COUNT","SUBPROCESS_EXECUTION_COUNT","NETWORK_IMPLEMENTATION_COUNT","PROVIDER_CLIENT_IMPLEMENTATION_COUNT","MODEL_CALL_IMPLEMENTATION_COUNT","MODEL_ROUTING_IMPLEMENTATION_COUNT","AUTH_IMPLEMENTATION_COUNT","AUTO_RETRY_IMPLEMENTATION_COUNT","AUTO_FALLBACK_IMPLEMENTATION_COUNT"): self.assertEqual(getattr(controller,n),0,n)
if __name__=="__main__": unittest.main()

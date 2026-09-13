import unittest
from hai_mr05 import coordination, memory_layer, multi_agent, run_ledger

class MultiAgentArchitectureRuntimeTests(unittest.TestCase):
    def test_sibling_lanes_are_frozen_under_inwjud(self):
        self.assertEqual(set(multi_agent.LANE_POLICIES), {"OPENCLAW","HERMES","CODEX"})
        self.assertEqual(multi_agent.OPENCLAW_POLICY.role,"PRIMARY_OPERATOR_ORCHESTRATOR")
        self.assertEqual(multi_agent.HERMES_POLICY.role,"LEARNING_AI_WORKER")
        self.assertEqual(multi_agent.CODEX_POLICY.role,"INDEPENDENT_REVIEWER_AUDITOR")
        for policy in multi_agent.LANE_POLICIES.values():
            self.assertEqual(policy.control_plane,"INWJUD")
            self.assertEqual(policy.direct_peer_agent_call,"DENY")
            self.assertEqual(policy.execution_authority,"NONE")
            self.assertEqual(policy.trust_level,"LEVEL 0")
            self.assertEqual(policy.mr05_gate,"REQUIRED")

    def test_task_envelope_is_deterministic_and_zero_authority(self):
        kwargs=dict(task_id="task-1",objective="Bounded analysis",selected_lane="HERMES",approved_context_refs=("ctx:1",),allowed_actions=("BOUNDED_ANALYSIS",),expected_output_schema="WORKER_V1",authorization_reference="human:rollout")
        a=multi_agent.build_task_envelope(**kwargs); b=multi_agent.build_task_envelope(**kwargs)
        self.assertEqual(a.task_identity,b.task_identity)
        self.assertEqual(a.execution_authority,"NONE"); self.assertEqual(a.live_send_authority,"NONE"); self.assertEqual(a.peer_agent_authority,"NONE")

    def test_peer_or_live_authority_fails_closed(self):
        common=dict(task_id="task-bad",objective="Bounded review",selected_lane="CODEX",approved_context_refs=("ctx:1",),allowed_actions=("DIFF_REVIEW",),forbidden_actions=multi_agent.COMMON_FORBIDDEN,expected_output_schema="REVIEW_V1",decision_by="INWJUD",authorization_reference="human:x")
        with self.assertRaises(multi_agent.MultiAgentContractError): multi_agent.MultiAgentTaskEnvelope(**common,peer_agent_authority="ALLOW")
        with self.assertRaises(multi_agent.MultiAgentContractError): multi_agent.MultiAgentTaskEnvelope(**common,live_send_authority="ALLOW")

    def test_memory_truth_priority_and_no_direct_obsidian_write(self):
        self.assertEqual(memory_layer.SOURCE_PRIORITY,("GIT_EVIDENCE","PCL_CURRENT_STATE","OBSIDIAN_DURABLE_KNOWLEDGE","AGENT_WORKING_MEMORY"))
        c=memory_layer.MemoryCandidate("m1","HERMES","RUNTIME_LESSON","Verified lesson",("ev:1",),"HIGH","c49715f90b8610a73ccc0add1178d88055d2b217")
        self.assertEqual(c.direct_obsidian_write_authority,"NONE")
        with self.assertRaises(memory_layer.MemoryContractError):
            memory_layer.MemoryPromotionDecision(c.candidate_identity,"APPROVE",("verify:1",),False,True)
        d=memory_layer.MemoryPromotionDecision(c.candidate_identity,"APPROVE",("verify:1",),True,True)
        self.assertEqual(d.filesystem_write_authority,"NONE")

    def test_memory_recall_is_bounded_read_only_via_inwjud(self):
        r=memory_layer.RecallPacket("HAI","c49715f90b8610a73ccc0add1178d88055d2b217",("git:head","pcl:state","obsidian:arch"),("GIT_EVIDENCE","PCL_CURRENT_STATE","OBSIDIAN_DURABLE_KNOWLEDGE"),("ctx:phase",),"CODEX")
        self.assertEqual(r.control_plane,"INWJUD"); self.assertEqual(r.read_authority,"BOUNDED_READ_ONLY"); self.assertEqual(r.mutation_authority,"NONE")

    def test_codex_review_cannot_be_bypassed(self):
        p=coordination.build_coordination_decision(task_identity="1"*64,operator_result_identity="2"*64,worker_result_identity="3"*64,reviewer_result_identity="4"*64,reviewer_verdict="PASS",findings_refs=())
        self.assertEqual(p.next_action,"PROCEED_TO_MR05"); self.assertFalse(p.adjudication_required); self.assertEqual(p.reviewer_bypass_authority,"NONE")
        for verdict in ("PASS_WITH_FINDINGS","REWORK_REQUIRED","INCONCLUSIVE"):
            d=coordination.build_coordination_decision(task_identity="1"*64,operator_result_identity="2"*64,worker_result_identity="3"*64,reviewer_result_identity="4"*64,reviewer_verdict=verdict,findings_refs=("finding:1",))
            self.assertEqual(d.next_action,"SOL_ADJUDICATION_REQUIRED"); self.assertTrue(d.adjudication_required)

    def test_canonical_sequence_places_independent_review_before_mr05(self):
        seq=coordination.CANONICAL_SEQUENCE
        self.assertLess(seq.index("HERMES_WORKER_PROPOSAL"),seq.index("CODEX_INDEPENDENT_REVIEW"))
        self.assertLess(seq.index("CODEX_INDEPENDENT_REVIEW"),seq.index("MR05_DETERMINISTIC_GATE"))

    def test_run_ledger_chain_is_deterministic(self):
        e0=run_ledger.build_event(run_id="run-1",sequence=0,actor="SOL",event_type="ARCHITECTURE",event_time="2026-09-13T18:00:00+07:00",input_refs=("objective:1",),output_refs=("arch:1",),previous_event_identity=None,status="PASS")
        e1=run_ledger.build_event(run_id="run-1",sequence=1,actor="INWJUD",event_type="ROUTE",event_time="2026-09-13T18:00:01+07:00",input_refs=(e0.event_identity,),output_refs=("route:hermes",),previous_event_identity=e0.event_identity,status="PASS")
        a=run_ledger.build_ledger(run_id="run-1",events=(e0,e1)); b=run_ledger.build_ledger(run_id="run-1",events=(e0,e1))
        self.assertEqual(a.ledger_identity,b.ledger_identity); self.assertEqual(a.persistence_authority,"NONE")
        bad=run_ledger.build_event(run_id="run-1",sequence=1,actor="HERMES",event_type="WORKER_RESULT",event_time="2026-09-13T18:00:02+07:00",input_refs=(),output_refs=("worker:1",),previous_event_identity="wrong",status="PASS")
        with self.assertRaises(run_ledger.RunLedgerContractError): run_ledger.build_ledger(run_id="run-1",events=(e0,bad))

    def test_all_new_modules_keep_external_authorities_zero(self):
        names=("FILESYSTEM_SOURCE_READ_COUNT","FILESYSTEM_WRITE_IMPLEMENTATION_COUNT","SUBPROCESS_EXECUTION_COUNT","NETWORK_IMPLEMENTATION_COUNT","PROVIDER_CLIENT_IMPLEMENTATION_COUNT","MODEL_CALL_IMPLEMENTATION_COUNT","MODEL_ROUTING_IMPLEMENTATION_COUNT","AUTH_IMPLEMENTATION_COUNT","AUTO_RETRY_IMPLEMENTATION_COUNT","AUTO_FALLBACK_IMPLEMENTATION_COUNT","HUMAN_APPROVAL_EXECUTION_COUNT","HUMAN_DECISION_SIDE_EFFECT_COUNT","STATE_TRANSITION_EXECUTION_COUNT","GIT_OPERATION_COUNT","LIVE_CLOUD_EXECUTION_COUNT")
        for module in (multi_agent,memory_layer,coordination,run_ledger):
            for name in names: self.assertEqual(getattr(module,name),0,f"{module.__name__}.{name}")

if __name__ == "__main__": unittest.main()

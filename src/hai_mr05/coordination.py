"""Pure-data independent-review coordination contracts."""
from __future__ import annotations
from dataclasses import dataclass
from .identity import identity_from_fields
from .multi_agent import CONTROL_PLANE, LANE_CODEX, LANE_HERMES, LANE_OPENCLAW, TRUST_LEVEL

COORDINATION_CONTRACT_IMPLEMENTATION_COUNT=1
COORDINATION_DECISION_BUILD_COUNT=1
FILESYSTEM_SOURCE_READ_COUNT=0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT=0
SUBPROCESS_EXECUTION_COUNT=0
NETWORK_IMPLEMENTATION_COUNT=0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT=0
MODEL_CALL_IMPLEMENTATION_COUNT=0
MODEL_ROUTING_IMPLEMENTATION_COUNT=0
AUTH_IMPLEMENTATION_COUNT=0
AUTO_RETRY_IMPLEMENTATION_COUNT=0
AUTO_FALLBACK_IMPLEMENTATION_COUNT=0
HUMAN_APPROVAL_EXECUTION_COUNT=0
HUMAN_DECISION_SIDE_EFFECT_COUNT=0
STATE_TRANSITION_EXECUTION_COUNT=0
GIT_OPERATION_COUNT=0
LIVE_CLOUD_EXECUTION_COUNT=0
VERDICT_PASS="PASS"; VERDICT_PASS_WITH_FINDINGS="PASS_WITH_FINDINGS"; VERDICT_REWORK_REQUIRED="REWORK_REQUIRED"; VERDICT_INCONCLUSIVE="INCONCLUSIVE"
REVIEW_VERDICTS=(VERDICT_PASS,VERDICT_PASS_WITH_FINDINGS,VERDICT_REWORK_REQUIRED,VERDICT_INCONCLUSIVE)
ACTION_PROCEED_TO_MR05="PROCEED_TO_MR05"; ACTION_SOL_ADJUDICATION="SOL_ADJUDICATION_REQUIRED"
CANONICAL_SEQUENCE=("SOL_ARCHITECTURE","INWJUD_ROUTE","OPENCLAW_OPERATOR_CONTEXT","HERMES_WORKER_PROPOSAL","CODEX_INDEPENDENT_REVIEW","SOL_ADJUDICATION_IF_REQUIRED","MR05_DETERMINISTIC_GATE","HUMAN_FINAL_AUTHORITY")
class CoordinationContractError(ValueError): pass

def _text(v:object,f:str)->str:
    if not isinstance(v,str) or not v.strip() or "\x00" in v: raise CoordinationContractError(f"{f} invalid")
    return v
@dataclass(frozen=True)
class AgentResultRef:
    lane_id:str; result_identity:str; result_type:str
    def __post_init__(self)->None:
        if self.lane_id not in (LANE_OPENCLAW,LANE_HERMES,LANE_CODEX): raise CoordinationContractError("unsupported result lane")
        _text(self.result_identity,"result_identity"); _text(self.result_type,"result_type")
    def to_dict(self)->dict[str,object]: return {"lane_id":self.lane_id,"result_identity":self.result_identity,"result_type":self.result_type}
def decide_next_action(verdict:str)->tuple[str,bool]:
    if verdict==VERDICT_PASS: return ACTION_PROCEED_TO_MR05,False
    if verdict in (VERDICT_PASS_WITH_FINDINGS,VERDICT_REWORK_REQUIRED,VERDICT_INCONCLUSIVE): return ACTION_SOL_ADJUDICATION,True
    raise CoordinationContractError("unsupported reviewer verdict")
@dataclass(frozen=True)
class CoordinationDecision:
    task_identity:str; operator_result:AgentResultRef; worker_result:AgentResultRef; reviewer_result:AgentResultRef; reviewer_verdict:str; findings_refs:tuple[str,...]; next_action:str; adjudication_required:bool
    control_plane:str=CONTROL_PLANE; trust_level:str=TRUST_LEVEL; execution_authority:str="NONE"; reviewer_bypass_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.task_identity,"task_identity")
        if self.operator_result.lane_id!=LANE_OPENCLAW or self.worker_result.lane_id!=LANE_HERMES or self.reviewer_result.lane_id!=LANE_CODEX: raise CoordinationContractError("agent result roles are not independent-lane bound")
        if self.reviewer_verdict not in REVIEW_VERDICTS: raise CoordinationContractError("unsupported reviewer verdict")
        if not isinstance(self.findings_refs,tuple): raise CoordinationContractError("findings_refs must be tuple")
        if self.reviewer_verdict!=VERDICT_PASS and not self.findings_refs: raise CoordinationContractError("non-pass review requires findings")
        expected=decide_next_action(self.reviewer_verdict)
        if (self.next_action,self.adjudication_required)!=expected: raise CoordinationContractError("decision conflicts with reviewer verdict")
        if self.control_plane!=CONTROL_PLANE or self.trust_level!=TRUST_LEVEL or self.execution_authority!="NONE" or self.reviewer_bypass_authority!="NONE": raise CoordinationContractError("coordination authority contract violated")
    def to_dict(self)->dict[str,object]: return {"task_identity":self.task_identity,"operator_result":self.operator_result.to_dict(),"worker_result":self.worker_result.to_dict(),"reviewer_result":self.reviewer_result.to_dict(),"reviewer_verdict":self.reviewer_verdict,"findings_refs":list(self.findings_refs),"next_action":self.next_action,"adjudication_required":self.adjudication_required,"control_plane":self.control_plane,"trust_level":self.trust_level,"execution_authority":self.execution_authority,"reviewer_bypass_authority":self.reviewer_bypass_authority}
    @property
    def decision_identity(self)->str: return identity_from_fields(self.to_dict())
def build_coordination_decision(*,task_identity:str,operator_result_identity:str,worker_result_identity:str,reviewer_result_identity:str,reviewer_verdict:str,findings_refs:tuple[str,...]|list[str])->CoordinationDecision:
    action,adj=decide_next_action(reviewer_verdict)
    return CoordinationDecision(task_identity,AgentResultRef(LANE_OPENCLAW,operator_result_identity,"OPERATOR_CONTEXT"),AgentResultRef(LANE_HERMES,worker_result_identity,"WORKER_PROPOSAL"),AgentResultRef(LANE_CODEX,reviewer_result_identity,"INDEPENDENT_REVIEW"),reviewer_verdict,tuple(findings_refs),action,adj)

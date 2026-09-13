"""Deterministic Trust-Level-0 multi-agent lane contracts.

OpenClaw, Hermes, and Codex are independent sibling lanes beneath Inwjud.
This module is pure data: it grants no execution or peer-agent authority.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from .identity import identity_from_fields

MULTI_AGENT_CONTRACT_IMPLEMENTATION_COUNT = 1
MULTI_AGENT_TASK_ENVELOPE_BUILD_COUNT = 1
FILESYSTEM_SOURCE_READ_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
HUMAN_DECISION_SIDE_EFFECT_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0
LIVE_CLOUD_EXECUTION_COUNT = 0

TRUST_LEVEL = "LEVEL 0"
CONTROL_PLANE = "INWJUD"
MR05_GATE = "REQUIRED"
DIRECT_PEER_AGENT_CALL = "DENY"
EXECUTION_AUTHORITY = "NONE"
LANE_OPENCLAW = "OPENCLAW"
LANE_HERMES = "HERMES"
LANE_CODEX = "CODEX"
LANE_IDS = (LANE_OPENCLAW, LANE_HERMES, LANE_CODEX)
ROLE_OPENCLAW = "PRIMARY_OPERATOR_ORCHESTRATOR"
ROLE_HERMES = "LEARNING_AI_WORKER"
ROLE_CODEX = "INDEPENDENT_REVIEWER_AUDITOR"
COMMON_FORBIDDEN = (
    "DIRECT_PEER_AGENT_CALL",
    "UNBOUNDED_FILESYSTEM_MUTATION",
    "AUTONOMOUS_STAGE_COMMIT_PUSH",
    "AUTONOMOUS_POLICY_CHANGE",
    "AUTONOMOUS_HUMAN_APPROVAL",
    "AUTONOMOUS_STATE_TRANSITION",
    "UNREVIEWED_MEMORY_PROMOTION",
    "LIVE_SEND_WITHOUT_SEPARATE_AUTHORIZATION",
)

class MultiAgentContractError(ValueError):
    pass

def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise MultiAgentContractError(f"{field} must be non-empty safe text")
    return value

def _items(value: object, field: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise MultiAgentContractError(f"{field} must be a sequence")
    result = tuple(_text(x, f"{field} item") for x in value)
    if not allow_empty and not result:
        raise MultiAgentContractError(f"{field} must not be empty")
    if len(set(result)) != len(result):
        raise MultiAgentContractError(f"{field} must not contain duplicates")
    return result

@dataclass(frozen=True)
class AgentLanePolicy:
    lane_id: str
    role: str
    purpose: str
    allowed_capabilities: tuple[str, ...]
    forbidden_capabilities: tuple[str, ...]
    control_plane: str = CONTROL_PLANE
    trust_level: str = TRUST_LEVEL
    mr05_gate: str = MR05_GATE
    direct_peer_agent_call: str = DIRECT_PEER_AGENT_CALL
    execution_authority: str = EXECUTION_AUTHORITY
    def __post_init__(self) -> None:
        if self.lane_id not in LANE_IDS: raise MultiAgentContractError("unsupported lane")
        _text(self.role, "role"); _text(self.purpose, "purpose")
        object.__setattr__(self, "allowed_capabilities", _items(self.allowed_capabilities, "allowed_capabilities"))
        object.__setattr__(self, "forbidden_capabilities", _items(self.forbidden_capabilities, "forbidden_capabilities"))
        if self.control_plane != CONTROL_PLANE: raise MultiAgentContractError("lane must remain under Inwjud")
        if self.trust_level != TRUST_LEVEL: raise MultiAgentContractError("lane must remain Trust Level 0")
        if self.mr05_gate != MR05_GATE: raise MultiAgentContractError("MR05 gate required")
        if self.direct_peer_agent_call != DIRECT_PEER_AGENT_CALL: raise MultiAgentContractError("peer calls forbidden")
        if self.execution_authority != EXECUTION_AUTHORITY: raise MultiAgentContractError("execution authority forbidden")
    def to_dict(self) -> dict[str, object]:
        return {"lane_id":self.lane_id,"role":self.role,"purpose":self.purpose,"allowed_capabilities":list(self.allowed_capabilities),"forbidden_capabilities":list(self.forbidden_capabilities),"control_plane":self.control_plane,"trust_level":self.trust_level,"mr05_gate":self.mr05_gate,"direct_peer_agent_call":self.direct_peer_agent_call,"execution_authority":self.execution_authority}
    @property
    def lane_identity(self) -> str: return identity_from_fields(self.to_dict())

OPENCLAW_POLICY = AgentLanePolicy(LANE_OPENCLAW, ROLE_OPENCLAW, "Primary governed operator and work orchestrator; peer requests route through Inwjud.", ("BOUNDED_OPERATION_PLANNING","BOUNDED_OPERATOR_PROPOSAL","INWJUD_ROUTING_REQUEST","MR05_SUBMISSION"), COMMON_FORBIDDEN)
HERMES_POLICY = AgentLanePolicy(LANE_HERMES, ROLE_HERMES, "Learning worker for bounded analysis, proposal, skills, and qualified local inference.", ("BOUNDED_ANALYSIS","BOUNDED_PROPOSAL","CONTROLLED_SKILL_USE","QUALIFIED_LOCAL_INFERENCE_PROFILE","MEMORY_CANDIDATE_PROPOSAL","MR05_SUBMISSION"), COMMON_FORBIDDEN)
CODEX_POLICY = AgentLanePolicy(LANE_CODEX, ROLE_CODEX, "Independent adversarial reviewer of bounded context, diffs, tests, and evidence.", ("BOUNDED_CONTEXT_REVIEW","DIFF_REVIEW","TEST_ORACLE_REVIEW","SECURITY_BOUNDARY_REVIEW","STRUCTURED_FINDINGS","MR05_SUBMISSION"), COMMON_FORBIDDEN)
LANE_POLICIES: Mapping[str, AgentLanePolicy] = {LANE_OPENCLAW:OPENCLAW_POLICY, LANE_HERMES:HERMES_POLICY, LANE_CODEX:CODEX_POLICY}

@dataclass(frozen=True)
class MultiAgentTaskEnvelope:
    task_id: str
    objective: str
    selected_lane: str
    approved_context_refs: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    expected_output_schema: str
    decision_by: str
    authorization_reference: str
    trust_level: str = TRUST_LEVEL
    control_plane: str = CONTROL_PLANE
    execution_authority: str = EXECUTION_AUTHORITY
    live_send_authority: str = "NONE"
    peer_agent_authority: str = "NONE"
    def __post_init__(self) -> None:
        _text(self.task_id,"task_id"); _text(self.objective,"objective")
        if self.selected_lane not in LANE_POLICIES: raise MultiAgentContractError("unsupported selected_lane")
        object.__setattr__(self,"approved_context_refs",_items(self.approved_context_refs,"approved_context_refs"))
        object.__setattr__(self,"allowed_actions",_items(self.allowed_actions,"allowed_actions"))
        object.__setattr__(self,"forbidden_actions",_items(self.forbidden_actions,"forbidden_actions"))
        _text(self.expected_output_schema,"expected_output_schema"); _text(self.authorization_reference,"authorization_reference")
        if self.decision_by != CONTROL_PLANE or self.control_plane != CONTROL_PLANE: raise MultiAgentContractError("Inwjud must route tasks")
        if self.trust_level != TRUST_LEVEL: raise MultiAgentContractError("task must remain Trust Level 0")
        if self.execution_authority != "NONE" or self.live_send_authority != "NONE" or self.peer_agent_authority != "NONE": raise MultiAgentContractError("task cannot grant execution, live-send, or peer authority")
        if any(x in COMMON_FORBIDDEN for x in self.allowed_actions): raise MultiAgentContractError("globally forbidden action was allowed")
        if not set(COMMON_FORBIDDEN).issubset(set(self.forbidden_actions)): raise MultiAgentContractError("common deny set is incomplete")
    def to_dict(self) -> dict[str, object]:
        return {"task_id":self.task_id,"objective":self.objective,"selected_lane":self.selected_lane,"selected_lane_identity":LANE_POLICIES[self.selected_lane].lane_identity,"approved_context_refs":list(self.approved_context_refs),"allowed_actions":list(self.allowed_actions),"forbidden_actions":list(self.forbidden_actions),"expected_output_schema":self.expected_output_schema,"decision_by":self.decision_by,"authorization_reference":self.authorization_reference,"trust_level":self.trust_level,"control_plane":self.control_plane,"execution_authority":self.execution_authority,"live_send_authority":self.live_send_authority,"peer_agent_authority":self.peer_agent_authority}
    @property
    def task_identity(self) -> str: return identity_from_fields(self.to_dict())

def build_task_envelope(*, task_id: str, objective: str, selected_lane: str, approved_context_refs: tuple[str,...] | list[str], allowed_actions: tuple[str,...] | list[str], expected_output_schema: str, authorization_reference: str) -> MultiAgentTaskEnvelope:
    return MultiAgentTaskEnvelope(task_id, objective, selected_lane, tuple(approved_context_refs), tuple(allowed_actions), COMMON_FORBIDDEN, expected_output_schema, CONTROL_PLANE, authorization_reference)

"""Pure-data memory, continuity, recall, and promotion contracts."""
from __future__ import annotations
from dataclasses import dataclass
from .identity import identity_from_fields
from .multi_agent import CONTROL_PLANE, LANE_IDS, TRUST_LEVEL

MEMORY_CONTRACT_IMPLEMENTATION_COUNT=1
MEMORY_CANDIDATE_BUILD_COUNT=1
MEMORY_PROMOTION_DECISION_BUILD_COUNT=1
RECALL_PACKET_BUILD_COUNT=1
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
SOURCE_GIT_EVIDENCE="GIT_EVIDENCE"
SOURCE_PCL="PCL_CURRENT_STATE"
SOURCE_OBSIDIAN="OBSIDIAN_DURABLE_KNOWLEDGE"
SOURCE_AGENT_MEMORY="AGENT_WORKING_MEMORY"
SOURCE_PRIORITY=(SOURCE_GIT_EVIDENCE,SOURCE_PCL,SOURCE_OBSIDIAN,SOURCE_AGENT_MEMORY)
MEMORY_RUNTIME_LESSON="RUNTIME_LESSON"
MEMORY_ARCHITECTURE_DECISION="ARCHITECTURE_DECISION"
MEMORY_DEFECT_LESSON="DEFECT_LESSON"
MEMORY_WORKING_NOTE="WORKING_NOTE"
MEMORY_TYPES=(MEMORY_RUNTIME_LESSON,MEMORY_ARCHITECTURE_DECISION,MEMORY_DEFECT_LESSON,MEMORY_WORKING_NOTE)
CONFIDENCE_VALUES=("HIGH","MEDIUM","LOW")
PROMOTION_DECISIONS=("APPROVE","REJECT","HOLD")
MEMORY_PROMOTION_GATE="REQUIRED"

class MemoryContractError(ValueError): pass

def _text(v: object, field: str) -> str:
    if not isinstance(v,str) or not v.strip() or "\x00" in v: raise MemoryContractError(f"{field} must be non-empty safe text")
    return v

def _items(v: object, field: str, allow_empty: bool=False) -> tuple[str,...]:
    if not isinstance(v,(tuple,list)): raise MemoryContractError(f"{field} must be a sequence")
    r=tuple(_text(x,f"{field} item") for x in v)
    if not allow_empty and not r: raise MemoryContractError(f"{field} must not be empty")
    if len(set(r))!=len(r): raise MemoryContractError(f"{field} contains duplicates")
    return r

@dataclass(frozen=True)
class MemoryCandidate:
    candidate_id:str; source_lane:str; memory_type:str; claim:str; evidence_refs:tuple[str,...]; confidence:str; project_baseline:str
    proposed_destination:str=SOURCE_OBSIDIAN; trust_level:str=TRUST_LEVEL; direct_obsidian_write_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.candidate_id,"candidate_id"); _text(self.claim,"claim"); _text(self.project_baseline,"project_baseline")
        if self.source_lane not in LANE_IDS: raise MemoryContractError("unsupported source lane")
        if self.memory_type not in MEMORY_TYPES: raise MemoryContractError("unsupported memory type")
        object.__setattr__(self,"evidence_refs",_items(self.evidence_refs,"evidence_refs"))
        if self.confidence not in CONFIDENCE_VALUES: raise MemoryContractError("unsupported confidence")
        if self.proposed_destination!=SOURCE_OBSIDIAN: raise MemoryContractError("durable destination must be Obsidian")
        if self.trust_level!=TRUST_LEVEL or self.direct_obsidian_write_authority!="NONE": raise MemoryContractError("agent memory cannot gain durable write authority")
    def to_dict(self)->dict[str,object]: return {"candidate_id":self.candidate_id,"source_lane":self.source_lane,"memory_type":self.memory_type,"claim":self.claim,"evidence_refs":list(self.evidence_refs),"confidence":self.confidence,"project_baseline":self.project_baseline,"proposed_destination":self.proposed_destination,"trust_level":self.trust_level,"direct_obsidian_write_authority":self.direct_obsidian_write_authority}
    @property
    def candidate_identity(self)->str: return identity_from_fields(self.to_dict())

@dataclass(frozen=True)
class MemoryPromotionDecision:
    candidate_identity:str; decision:str; verifier_refs:tuple[str,...]; baseline_verified:bool; evidence_verified:bool
    authority:str=CONTROL_PLANE; promotion_gate:str=MEMORY_PROMOTION_GATE; filesystem_write_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.candidate_identity,"candidate_identity"); object.__setattr__(self,"verifier_refs",_items(self.verifier_refs,"verifier_refs"))
        if self.decision not in PROMOTION_DECISIONS: raise MemoryContractError("unsupported promotion decision")
        if self.authority!=CONTROL_PLANE or self.promotion_gate!=MEMORY_PROMOTION_GATE or self.filesystem_write_authority!="NONE": raise MemoryContractError("promotion authority contract violated")
        if self.decision=="APPROVE" and not (self.baseline_verified and self.evidence_verified): raise MemoryContractError("approval requires verified baseline and evidence")
    def to_dict(self)->dict[str,object]: return {"candidate_identity":self.candidate_identity,"decision":self.decision,"verifier_refs":list(self.verifier_refs),"baseline_verified":self.baseline_verified,"evidence_verified":self.evidence_verified,"authority":self.authority,"promotion_gate":self.promotion_gate,"filesystem_write_authority":self.filesystem_write_authority}
    @property
    def decision_identity(self)->str: return identity_from_fields(self.to_dict())

@dataclass(frozen=True)
class RecallPacket:
    project_id:str; project_baseline:str; source_refs:tuple[str,...]; source_kinds:tuple[str,...]; bounded_context_refs:tuple[str,...]; requested_by_lane:str
    control_plane:str=CONTROL_PLANE; read_authority:str="BOUNDED_READ_ONLY"; mutation_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.project_id,"project_id"); _text(self.project_baseline,"project_baseline")
        object.__setattr__(self,"source_refs",_items(self.source_refs,"source_refs")); object.__setattr__(self,"source_kinds",_items(self.source_kinds,"source_kinds")); object.__setattr__(self,"bounded_context_refs",_items(self.bounded_context_refs,"bounded_context_refs"))
        if len(self.source_refs)!=len(self.source_kinds) or any(x not in SOURCE_PRIORITY for x in self.source_kinds): raise MemoryContractError("recall sources invalid")
        if self.requested_by_lane not in LANE_IDS: raise MemoryContractError("unsupported requesting lane")
        if self.control_plane!=CONTROL_PLANE or self.read_authority!="BOUNDED_READ_ONLY" or self.mutation_authority!="NONE": raise MemoryContractError("recall must be bounded read-only through Inwjud")
    def to_dict(self)->dict[str,object]: return {"project_id":self.project_id,"project_baseline":self.project_baseline,"source_refs":list(self.source_refs),"source_kinds":list(self.source_kinds),"bounded_context_refs":list(self.bounded_context_refs),"requested_by_lane":self.requested_by_lane,"control_plane":self.control_plane,"read_authority":self.read_authority,"mutation_authority":self.mutation_authority}
    @property
    def recall_identity(self)->str: return identity_from_fields(self.to_dict())

def build_memory_candidate(**kwargs: object)->MemoryCandidate: return MemoryCandidate(**kwargs)
def build_promotion_decision(**kwargs: object)->MemoryPromotionDecision: return MemoryPromotionDecision(**kwargs)
def build_recall_packet(**kwargs: object)->RecallPacket: return RecallPacket(**kwargs)

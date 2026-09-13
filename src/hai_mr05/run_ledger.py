"""Pure-data chained run-ledger contracts for agent observability."""
from __future__ import annotations
from dataclasses import dataclass
from .identity import identity_from_fields
from .multi_agent import CONTROL_PLANE, TRUST_LEVEL
RUN_LEDGER_CONTRACT_IMPLEMENTATION_COUNT=1
LEDGER_EVENT_BUILD_COUNT=1
RUN_LEDGER_BUILD_COUNT=1
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
LEDGER_ACTORS=("SOL","INWJUD","OPENCLAW","HERMES","CODEX","MR05","HUMAN")
LEDGER_EVENT_TYPES=("ARCHITECTURE","ROUTE","OPERATOR_CONTEXT","WORKER_RESULT","REVIEW","ADJUDICATION","GATE","HUMAN_DECISION","MEMORY_CANDIDATE","MEMORY_PROMOTION")
class RunLedgerContractError(ValueError): pass

def _text(v:object,f:str)->str:
    if not isinstance(v,str) or not v.strip() or "\x00" in v: raise RunLedgerContractError(f"{f} invalid")
    return v
@dataclass(frozen=True)
class LedgerEvent:
    run_id:str; sequence:int; actor:str; event_type:str; event_time:str; input_refs:tuple[str,...]; output_refs:tuple[str,...]; previous_event_identity:str|None; status:str
    trust_level:str=TRUST_LEVEL; mutation_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.run_id,"run_id"); _text(self.event_time,"event_time"); _text(self.status,"status")
        if not isinstance(self.sequence,int) or isinstance(self.sequence,bool) or self.sequence<0: raise RunLedgerContractError("invalid sequence")
        if self.actor not in LEDGER_ACTORS or self.event_type not in LEDGER_EVENT_TYPES: raise RunLedgerContractError("unsupported actor or event")
        if not isinstance(self.input_refs,tuple) or not isinstance(self.output_refs,tuple): raise RunLedgerContractError("refs must be tuples")
        if self.previous_event_identity is not None: _text(self.previous_event_identity,"previous_event_identity")
        if self.trust_level!=TRUST_LEVEL or self.mutation_authority!="NONE": raise RunLedgerContractError("ledger event authority contract violated")
    def to_dict(self)->dict[str,object]: return {"run_id":self.run_id,"sequence":self.sequence,"actor":self.actor,"event_type":self.event_type,"event_time":self.event_time,"input_refs":list(self.input_refs),"output_refs":list(self.output_refs),"previous_event_identity":self.previous_event_identity,"status":self.status,"trust_level":self.trust_level,"mutation_authority":self.mutation_authority}
    @property
    def event_identity(self)->str: return identity_from_fields(self.to_dict())
@dataclass(frozen=True)
class RunLedger:
    run_id:str; events:tuple[LedgerEvent,...]; control_plane:str=CONTROL_PLANE; persistence_authority:str="NONE"
    def __post_init__(self)->None:
        _text(self.run_id,"run_id")
        if not self.events or self.control_plane!=CONTROL_PLANE or self.persistence_authority!="NONE": raise RunLedgerContractError("ledger contract invalid")
        previous=None; seen=set()
        for i,event in enumerate(self.events):
            if event.run_id!=self.run_id or event.sequence!=i or event.previous_event_identity!=previous: raise RunLedgerContractError("event chain invalid")
            ident=event.event_identity
            if ident in seen: raise RunLedgerContractError("duplicate event")
            seen.add(ident); previous=ident
    def to_dict(self)->dict[str,object]: return {"run_id":self.run_id,"events":[e.to_dict() for e in self.events],"control_plane":self.control_plane,"persistence_authority":self.persistence_authority}
    @property
    def ledger_identity(self)->str: return identity_from_fields(self.to_dict())
def build_event(**kwargs:object)->LedgerEvent:
    kwargs["input_refs"]=tuple(kwargs.get("input_refs",())) ; kwargs["output_refs"]=tuple(kwargs.get("output_refs",()))
    return LedgerEvent(**kwargs)
def build_ledger(*,run_id:str,events:tuple[LedgerEvent,...]|list[LedgerEvent])->RunLedger: return RunLedger(run_id,tuple(events))

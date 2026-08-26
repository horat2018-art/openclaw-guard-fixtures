from .discovery import discover
from .normalization import normalize
from .mr03_adapter import invoke_read_only
from .bounded_context import build
from .proposer_stub import propose
from .verifier import verify
from .human_gate import decision

def run(source, task=None, mode="normal"):
    task = task or {}
    discovery = discover(source)
    rows = normalize(discovery)
    adapter_output = invoke_read_only(source, task)
    package = build(rows, task, adapter_output)
    proposal = propose(package, mode)
    result = verify(package, proposal)
    return {"discovery": discovery, "normalized": rows, "mr03_adapter_output": adapter_output, "mr03_adapter_invoked": True, "package": package, "proposal": proposal, "verification": result, "human_gate": decision(result)}

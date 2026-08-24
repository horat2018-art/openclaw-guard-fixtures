import re
from .errors import EvidenceError

def status_pack(data, path=""):
    if not isinstance(data, dict): raise EvidenceError("INVALID_SCHEMA", "status source must be object")
    hashes={k:v for k,v in sorted(data.items()) if "sha" in k.lower() and isinstance(v,str)}
    result=data.get("result", data.get("status", data.get("GW_RESULT", data.get("RESULT", "UNKNOWN"))))
    validity=data.get("current_validity", data.get("classification", "UNKNOWN"))
    return {"phase_id":data.get("phase", "UNKNOWN"),"result":result,"current_validity":validity,"key_findings":data.get("reason", data.get("next", "")),"authority_delta":{k:v for k,v in data.items() if "AUTHORITY" in k},"mutation_summary":{k:v for k,v in data.items() if "WRITES" in k or "CHANGES" in k},"network_summary":{k:v for k,v in data.items() if "NETWORK" in k or "MODEL_CALLS" in k or "PROVIDER" in k},"important_hashes":hashes,"superseded_by":data.get("superseded_by", "NONE"),"invalidated_scope":data.get("invalidated_scope", data.get("scope", "NONE")),"next_decision":data.get("next_phase", data.get("next", "NONE")),"provenance":{"path":path}}

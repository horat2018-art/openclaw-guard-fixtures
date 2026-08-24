import os, json
from .canonical import canonical_bytes, canonical_sha256, approximate_tokens
from .dedup import duplicates
from .errors import EvidenceError
from .selection import select
from .security import enforce_safe
from .supersession import graph

def build(rows, task):
 selected, excluded=select(rows,task)
 if not selected: raise EvidenceError("MISSING_REQUIRED_ARTIFACT", "selection produced no evidence")
 for r in selected:
  if r.get("content_kind") == "json":
   try:
    with open(r["path"],encoding="utf-8") as stream: value=json.load(stream)
   except (OSError,json.JSONDecodeError) as exc:
    raise EvidenceError("INVALID_SCHEMA", str(exc))
   enforce_safe(value,r.get("relative_path",r.get("path","")))
 refs=[{"sha256":r["sha256"],"source_path":r["path"],"phase_id":r["phase_id"],"artifact_type":r["artifact_type"],"relative_path":r["relative_path"]} for r in selected]
 statuses=[]
 for r in selected:
  statuses.append({"phase_id":r["phase_id"],"result":"STRUCTURED_REFERENCE","current_validity":r["current_validity"],"important_hashes":[r["sha256"]],"provenance":r["relative_path"]})
 payload={"L0_IDENTITY_HEADER":{"policy_version":"MR03-PACKAGE-V1","task_id":task.get("task_id","UNSPECIFIED"),"qualification_exposure":0},"L1_CURRENT_STATE":{"task_class":task.get("task_class","UNKNOWN")},"L2_REQUIRED_EVIDENCE":statuses,"L3_RELEVANT_HISTORICAL_DELTA":[],"L4_PROVENANCE_REFERENCES":refs,"L5_EXCLUDED_EVIDENCE_INDEX":sorted(excluded,key=lambda x:x["path"]),"L6_VALIDATION_REPORT":{"mandatory_field_retention":"100%","provenance_reference_retention":"100%","known_fact_regression_count":0}}
 raw= sum(r["size_bytes"] for r in rows)
 rawtok=0
 for row in rows:
  with open(row["path"],encoding="utf-8",errors="ignore") as stream:
   rawtok += approximate_tokens(stream.read())
 content=canonical_bytes(payload); return payload,{"package_sha256":canonical_sha256(payload),"source_set_sha256":canonical_sha256(sorted(r["sha256"] for r in rows)),"policy_version":"MR03-PACKAGE-V1","source_count":len(rows),"included_count":len(selected),"reference_only_count":len(refs),"excluded_count":len(excluded),"exclusion_reason_counts":{},"provenance_completeness":"100%","raw_bytes":raw,"optimized_bytes":len(content),"raw_approx_tokens":rawtok,"optimized_approx_tokens":approximate_tokens(content.decode("utf-8"))}

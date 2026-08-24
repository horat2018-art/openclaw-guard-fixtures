from .errors import EvidenceError

def _relevant(rows, task):
 required=set(task.get("required_phase_ids",[])); types=set(task.get("required_artifact_types",[]))
 if not required and not types: return list(rows)
 return [r for r in rows if (not required or r.get("phase_id") in required) or (not types or r.get("artifact_type") in types)]

def resolve_current_state(rows, task):
 relevant=_relevant(rows,task)
 active=[]
 for r in relevant:
  if r.get("superseded_by") not in (None,"NONE"): continue
  validity=r.get("current_validity","UNKNOWN")
  if task.get("current_state_required") and validity == "UNKNOWN":
   raise EvidenceError("UNKNOWN_VALIDITY", "required current validity is unknown", {"path":r.get("relative_path")})
  if r.get("authority_level") is not None and r.get("claim_scope") is not None:
   active.append(r)
 claims={}
 for r in active:
  key=(r.get("claim_scope"),r.get("authority_level"))
  claims.setdefault(key,[]).append(r)
 for key, group in claims.items():
  values={r.get("claim_value") for r in group}
  if len(values)>1:
   raise EvidenceError("AMBIGUOUS_PRECEDENCE", "conflicting same-precedence claims", {"scope":key[0],"authority_level":key[1]})
 return relevant

def select(rows, task):
 resolve_current_state(rows,task)
 required=set(task.get("required_phase_ids",[])); types=set(task.get("required_artifact_types",[]))
 selected=[]; excluded=[]
 for r in rows:
  if r.get("superseded_by") not in (None,"NONE"):
   excluded.append({"path":r["relative_path"],"reason":"SUPERSEDED"}); continue
  if r.get("sensitive_class") != "NON_SENSITIVE_METADATA": excluded.append({"path":r["relative_path"],"reason":"SECRET"}); continue
  if required and r.get("phase_id") not in required and (not types or r.get("artifact_type") not in types):
   excluded.append({"path":r["relative_path"],"reason":"HISTORICAL_NOT_REQUIRED"}); continue
  if not required and types and r.get("artifact_type") not in types:
   excluded.append({"path":r["relative_path"],"reason":"HISTORICAL_NOT_REQUIRED"}); continue
  selected.append(r)
 return sorted(selected,key=lambda x:(x.get("phase_id",""),x.get("artifact_type",""),x.get("relative_path",""))), excluded

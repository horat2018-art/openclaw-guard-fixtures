from .errors import HarnessError
def validate(rows):
 for r in rows:
  p=r.get("provenance",{})
  if not all(p.get(k) for k in ("source_sha256","source_reference","phase_id","artifact_type")): raise HarnessError("PROVENANCE_GAP","required provenance missing","BOUNDED_CONTEXT")
 return "100%"

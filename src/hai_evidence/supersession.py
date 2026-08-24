VALIDITY={"VALID","VALID_WITH_SCOPE_LIMITATION","SUPERSEDED","INVALIDATED_SPECIFICALLY","HISTORICAL_BLOCK_ONLY","AUTHORITATIVE_TERMINAL_POLICY","UNKNOWN"}
def graph(rows):
 nodes=[];edges=[]
 for row in rows:
  status=row.get("current_validity","UNKNOWN")
  nodes.append({"id":row.get("relative_path"),"status":status,"sha256":row.get("sha256"),"provenance":row.get("relative_path")})
  for field,rel in (("superseded_by","SUPERSEDED"),("invalidated_by","INVALIDATED_SPECIFICALLY")):
   target=row.get(field)
   if target and target != "NONE": edges.append({"from":row.get("relative_path"),"to":target,"relation":rel,"provenance":row.get("relative_path")})
 return {"nodes":sorted(nodes,key=lambda x:x["id"]),"edges":sorted(edges,key=lambda x:(x["from"],x["to"]))}

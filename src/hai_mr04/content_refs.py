from .canonical import canonical_sha256
def ref(row): return {"sha256":row["sha256"],"reference":row["reference"],"phase_id":row["phase_id"],"artifact_type":row["artifact_type"]}
def ref_set(rows): return [ref(x) for x in sorted(rows,key=lambda x:(x["sha256"],x["reference"]))]
def identity(rows): return canonical_sha256(ref_set(rows))

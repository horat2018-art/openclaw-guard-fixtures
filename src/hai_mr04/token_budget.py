from .canonical import approx_tokens,canonical_bytes
def measure(raw,package):
 rb=len(raw.encode()); pb=len(canonical_bytes(package)); rt=approx_tokens(raw); pt=approx_tokens(canonical_bytes(package).decode())
 return {"RAW_INPUT_BYTES":rb,"BOUNDED_CONTEXT_BYTES":pb,"BYTE_REDUCTION_PERCENT":round((rb-pb)/rb*100,2) if rb else 0,"APPROX_RAW_TOKENS":rt,"APPROX_BOUNDED_TOKENS":pt,"APPROX_TOKEN_REDUCTION_PERCENT":round((rt-pt)/rt*100,2) if rt else 0,"TOKEN_ESTIMATE_CLASS":"APPROXIMATE_ESTIMATE"}
def classify(raw_tokens,protected=False,full_raw=False):
 if protected:return "PROTECTED_BLOCKED"
 if full_raw:return "FULL_RAW_REQUIRED"
 return "HIGH_CONTEXT" if raw_tokens>4000 else "NORMAL"

def finalize(raw, package_without_budget):
    """Finalize immutable budget metrics before package identity is computed."""
    return measure(raw, package_without_budget)

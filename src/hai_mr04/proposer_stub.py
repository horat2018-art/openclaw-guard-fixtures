from .errors import HarnessError

def propose(context, mode="normal"):
    if mode == "malformed":
        return {"bad": True}
    refs = context.get("source_reference_set", [])
    envelope = {
        "schema_version": "proposal-v2",
        "package_identity": context.get("package_identity", ""),
        "package_sha256": context.get("package_sha256", ""),
        "package_schema_version": context.get("schema_version", ""),
        "proposal": "synthetic proposal",
        "source_refs": refs,
        "confidence_state": "DERIVED",
        "unresolved_issues": [],
        "escalation_signals": [],
        "no_action": False,
    }
    if mode == "unsupported_ref":
        envelope["source_refs"] = refs + [{"sha256": "0" * 64, "reference": "missing", "phase_id": "X", "artifact_type": "X"}]
    if mode == "escalate":
        envelope.update({"proposal": "synthetic uncertainty", "source_refs": refs[:1], "confidence_state": "UNCERTAIN", "unresolved_issues": ["semantic ambiguity"], "escalation_signals": ["AMBIGUOUS_PRECEDENCE"]})
    return envelope

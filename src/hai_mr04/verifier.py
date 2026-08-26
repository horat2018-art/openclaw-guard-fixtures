from .bounded_context import package_identity_from_semantics, package_sha256_from_content

def verify(context, proposal):
    required = ("schema_version", "package_identity", "package_sha256", "package_schema_version", "proposal", "source_refs", "confidence_state", "unresolved_issues", "escalation_signals", "no_action")
    if not isinstance(proposal, dict) or not all(key in proposal for key in required):
        return {"decision": "DENY", "code": "PROPOSER_SCHEMA_INVALID"}
    if not isinstance(context, dict):
        return {"decision": "DENY", "code": "PROPOSER_SCHEMA_INVALID"}
    if proposal.get("schema_version") != "proposal-v2" or proposal.get("package_schema_version") != context.get("schema_version"):
        return {"decision": "DENY", "code": "PROPOSER_SCHEMA_INVALID"}
    if proposal.get("deterministic_output") is False:
        return {"decision": "DENY", "code": "NONDETERMINISTIC_OUTPUT"}
    try:
        recomputed_identity = package_identity_from_semantics(context)
        recomputed_package_sha256 = package_sha256_from_content(context)
    except (TypeError, ValueError):
        return {"decision": "DENY", "code": "PROPOSER_SCHEMA_INVALID"}
    if context.get("package_identity") != recomputed_identity or context.get("package_sha256") != recomputed_package_sha256:
        return {"decision": "DENY", "code": "PROPOSAL_PACKAGE_BINDING_MISMATCH"}
    if proposal.get("package_identity") != recomputed_identity or proposal.get("package_sha256") != recomputed_package_sha256:
        return {"decision": "DENY", "code": "PROPOSAL_PACKAGE_BINDING_MISMATCH"}
    if not isinstance(proposal["source_refs"], list) or not isinstance(proposal["unresolved_issues"], list) or not isinstance(proposal["escalation_signals"], list):
        return {"decision": "DENY", "code": "PROPOSER_SCHEMA_INVALID"}
    allowed = {item["sha256"] for item in context.get("source_reference_set", [])}
    if any(not isinstance(item, dict) or item.get("sha256") not in allowed for item in proposal["source_refs"]):
        return {"decision": "DENY", "code": "PROPOSAL_SOURCE_REF_INVALID"}
    if context.get("protected_content_status") != "RAW_EXCLUDED":
        return {"decision": "DENY", "code": "PROTECTED_CONTENT_SELECTED"}
    if proposal["escalation_signals"] or proposal["unresolved_issues"]:
        return {"decision": "ESCALATE", "code": proposal["escalation_signals"][0] if proposal["escalation_signals"] else "UNRESOLVED"}
    return {"decision": "PASS_FOR_REVIEW", "approval": False, "code": "NONE"}

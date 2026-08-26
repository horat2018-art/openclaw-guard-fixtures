import json
from .errors import HarnessError
from .canonical import canonical_sha256
from .token_budget import finalize
from .content_refs import ref_set

VALID = {"VALID", "VALID_WITH_SCOPE_LIMITATION", "SUPERSEDED", "INVALIDATED_SPECIFICALLY", "HISTORICAL_BLOCK_ONLY", "UNKNOWN"}
ADAPTER_TOP_LEVEL = {"L0_IDENTITY_HEADER", "L1_CURRENT_STATE", "L2_REQUIRED_EVIDENCE", "L3_RELEVANT_HISTORICAL_DELTA", "L4_PROVENANCE_REFERENCES", "L5_EXCLUDED_EVIDENCE_INDEX", "L6_VALIDATION_REPORT"}

IDENTITY_FIELDS = frozenset(("package_identity", "package_sha256"))


def semantic_package_projection(package):
    """Return the current semantic package content without derived identities."""
    if not isinstance(package, dict):
        raise TypeError("package must be a mapping")
    return {key: value for key, value in package.items() if key not in IDENTITY_FIELDS}


def package_identity_from_semantics(package):
    """Compute the package identity from the package as it exists now."""
    return canonical_sha256(semantic_package_projection(package))


def package_sha256_from_content(package):
    """Compute the envelope SHA without trusting its stored derived SHA."""
    if not isinstance(package, dict):
        raise TypeError("package must be a mapping")
    return canonical_sha256({key: value for key, value in package.items() if key != "package_sha256"})


def _validate_adapter_output(value):
    if not isinstance(value, dict) or set(value) != ADAPTER_TOP_LEVEL:
        raise HarnessError("INVALID_SCHEMA", "MR-03 adapter output schema mismatch", "BOUNDED_CONTEXT")
    dict_layers = ("L0_IDENTITY_HEADER", "L1_CURRENT_STATE", "L6_VALIDATION_REPORT")
    if not all(isinstance(value[key], dict) for key in dict_layers):
        raise HarnessError("INVALID_SCHEMA", "MR-03 adapter layer type mismatch", "BOUNDED_CONTEXT")
    if not isinstance(value["L2_REQUIRED_EVIDENCE"], list) or not isinstance(value["L3_RELEVANT_HISTORICAL_DELTA"], list) or not isinstance(value["L4_PROVENANCE_REFERENCES"], list) or not isinstance(value["L5_EXCLUDED_EVIDENCE_INDEX"], list):
        raise HarnessError("INVALID_SCHEMA", "MR-03 adapter reference type mismatch", "BOUNDED_CONTEXT")
    return value

def build(rows, task=None, mr03_output=None):
    task = task or {}
    selected, excluded = [], []
    if mr03_output is not None:
        _validate_adapter_output(mr03_output)
    required = set(task.get("required_references", []))
    available = {row["reference"] for row in rows}
    if required - available:
        raise HarnessError("MISSING_REQUIRED_ARTIFACT", "required artifact is absent", "BOUNDED_CONTEXT", {"missing": sorted(required - available)})
    for row in rows:
        if row["security"] == "SECRET_RISK":
            raise HarnessError("SECRET_RISK", "synthetic secret rejected", "BOUNDED_CONTEXT")
        if row["protected"]:
            raise HarnessError("PROTECTED_CONTENT_SELECTED", "protected raw rejected", "BOUNDED_CONTEXT")
        if row["current_validity"] not in VALID:
            raise HarnessError("INVALID_SCHEMA", "unknown validity enum", "BOUNDED_CONTEXT")
        if task.get("current_state_required") and row["current_validity"] == "UNKNOWN":
            raise HarnessError("UNKNOWN_VALIDITY", "current state required", "BOUNDED_CONTEXT")
        selected.append(row)
    selected = sorted(selected, key=lambda x: (x["phase_id"], x["artifact_type"], x["reference"]))
    claims = {}
    for row in selected:
        if row["superseded_by"] != "NONE":
            continue
        key = (row["claim_scope"], row["authority_level"])
        claims.setdefault(key, set()).add(row["claim_value"])
    if any(len(values) > 1 for values in claims.values()):
        raise HarnessError("AMBIGUOUS_PRECEDENCE", "conflicting claims", "BOUNDED_CONTEXT")
    raw = json.dumps(selected, sort_keys=True, separators=(",", ":"))
    refs = ref_set(selected)
    package = {
        "schema_version": "bounded-context-package-v2",
        "package_schema_version": "bounded-context-package-v2",
        "package_identity": "",
        "L0_IDENTITY_HEADER": {"policy": "MR04B-SYNTHETIC", "task_id": task.get("task_id", "UNSPECIFIED")},
        "L1_CURRENT_STATE": {"facts": [row for row in selected if row["current_validity"] in ("VALID", "VALID_WITH_SCOPE_LIMITATION")]},
        "L2_REQUIRED_EVIDENCE": {"mandatory": [row for row in selected if row["mandatory"]]},
        "L3_RELEVANT_HISTORICAL_DELTA": {"references": [ref for ref in refs if ref["phase_id"] != "MR04B-SYNTHETIC"]},
        "L4_PROVENANCE_REFERENCES": refs,
        "L5_EXCLUDED_EVIDENCE_INDEX": excluded,
        "L6_VALIDATION_REPORT": {"result": "PASS", "mandatory_retention": "100%", "provenance_retention": "100%"},
        "source_reference_set": refs,
        "security_status": "SAFE_METADATA_ONLY",
        "protected_content_status": "RAW_EXCLUDED",
        "token_budget": {},
        "mr03_adapter_output": mr03_output if mr03_output is not None else {},
        "escalation_signals": [],
    }
    package["token_budget"] = finalize(raw, {key: value for key, value in package.items() if key not in ("package_identity", "token_budget")})
    package["package_identity"] = package_identity_from_semantics(package)
    package["package_sha256"] = package_sha256_from_content(package)
    return package

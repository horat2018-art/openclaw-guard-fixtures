from .errors import HarnessError

SECRET_FIELDS = {
    "secret", "api_key", "apikey", "access_token", "auth_token", "private_key",
    "password", "credential", "credentials", "token", "client_secret", "refresh_token",
}

def _secret_key(key):
    return str(key).casefold().replace("-", "_").replace(" ", "_") in SECRET_FIELDS

def _contains_secret(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if _secret_key(key) and item not in (None, "", [], {}):
                return True
            if _contains_secret(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False

def normalize(discovery):
    rows = []
    seen = {}
    for x in discovery["artifacts"]:
        d = x.get("data") or {}
        if not isinstance(d, dict):
            raise HarnessError("INVALID_SCHEMA", "fixture must be object", "NORMALIZATION")
        duplicate_key = d.get("duplicate_key")
        if duplicate_key:
            if duplicate_key in seen and seen[duplicate_key] != x["sha256"]:
                raise HarnessError("DUPLICATE_CONFLICT", "duplicate evidence identity conflicts", "NORMALIZATION")
            seen[duplicate_key] = x["sha256"]
        security = d.get("security", "NON_SENSITIVE_METADATA")
        if _contains_secret(d):
            security = "SECRET_RISK"
        phase_id = d.get("phase_id", "MR04B-SYNTHETIC")
        artifact_type = d.get("artifact_type", "SYNTHETIC_EVIDENCE")
        rows.append({
            "reference": x["reference"], "sha256": x["sha256"], "size_bytes": x["size_bytes"],
            "artifact_type": artifact_type, "phase_id": phase_id,
            "current_validity": d.get("current_validity", "UNKNOWN"),
            "superseded_by": d.get("superseded_by", "NONE"),
            "claim_scope": d.get("claim_scope", "default"),
            "authority_level": d.get("authority_level", 0),
            "claim_value": d.get("claim_value", "UNSPECIFIED"),
            "security": security, "protected": bool(d.get("protected", False)),
            "mandatory": bool(d.get("mandatory", False)),
            "provenance": {"source_sha256": x["sha256"], "source_reference": x["reference"], "phase_id": phase_id, "artifact_type": artifact_type},
        })
    return sorted(rows, key=lambda x: (x["phase_id"], x["artifact_type"], x["reference"]))

import os

def artifact_type(path):
    name = os.path.basename(path).lower()
    parent = path.replace("\\", "/").split("/")
    if name == "final_report.json": return "FINAL_REPORT"
    if "contract" in parent: return "CONTRACT"
    if "manifest" in name: return "MANIFEST"
    if "decision" in parent: return "DECISION"
    if "snapshot" in parent: return "SNAPSHOT"
    if "diff" in name: return "DIFF"
    if "test" in parent: return "TEST_RESULT"
    if "security" in parent: return "SECURITY_REVIEW"
    if "handoff" in parent: return "HANDOFF"
    if name.endswith(".md"): return "DOCUMENTATION"
    if "historical" in name or "block" in name: return "HISTORICAL_BLOCK"
    if "identity" in name: return "SOURCE_IDENTITY"
    return "OTHER"

def phase_id(path, data=None):
    if isinstance(data, dict) and data.get("phase"): return data["phase"]
    text = path.replace("\\", "/")
    for part in text.split("/"):
        if part.startswith("HAI-") or part.startswith("MR-"):
            return part
    return "UNKNOWN"

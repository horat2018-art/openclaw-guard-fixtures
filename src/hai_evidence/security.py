import re
from .errors import EvidenceError
SECRET_RULES = {
    "access_token": re.compile(r"access[_-]?token", re.I),
    "refresh_token": re.compile(r"refresh[_-]?token", re.I),
    "authorization": re.compile(r"authorization|bearer", re.I),
    "cookie": re.compile(r"cookie", re.I),
    "oauth_code": re.compile(r"oauth[_-]?code", re.I),
    "code_verifier": re.compile(r"code[_-]?verifier|pkce", re.I),
    "credential": re.compile(r"credential|client[_-]?secret", re.I),
}

def _walk(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield path + "." + str(key), str(key), child
            yield from _walk(child, path + "." + str(key))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _walk(child, f"{path}[{i}]")

def scan_object(value, source=""):
    findings = []
    for path, key, child in _walk(value):
        text = key
        for rule, pattern in SECRET_RULES.items():
            if pattern.search(text):
                findings.append({"rule_id": rule, "file": source, "field_path": path, "classification": "SECRET", "action": "BLOCK_WITHOUT_VALUE"})
        if isinstance(child, str) and len(child) > 20:
            for rule, pattern in SECRET_RULES.items():
                if pattern.search(text) or (rule == "authorization" and child.lower().startswith("bearer ")):
                    findings.append({"rule_id": rule, "file": source, "field_path": path, "classification": "SECRET", "action": "BLOCK_WITHOUT_VALUE"})
    return findings

def is_protected(value):
    text = " ".join(str(x) for x in value.keys()) if isinstance(value, dict) else str(value)
    return bool(re.search(r"protected[_-]?qualification|qualification[_-]?oracle|v2[_-]?oracle", text, re.I))

def enforce_safe(value, source=""):
    findings = scan_object(value, source)
    if findings:
        raise EvidenceError("SECRET_RISK", "secret-like field detected", {"findings": findings})
    if is_protected(value):
        raise EvidenceError("PROTECTED_CONTENT_SELECTED", "protected content selected", {"source": source})

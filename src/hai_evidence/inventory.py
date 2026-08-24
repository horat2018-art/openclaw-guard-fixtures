import json, os
from .canonical import file_sha256
from .classify import artifact_type, phase_id
from .errors import EvidenceError
from .security import scan_object

def _safe(root, path):
    root = os.path.realpath(root); real = os.path.realpath(path)
    if os.path.commonpath([root, real]) != root: raise EvidenceError("PROVENANCE_FAILURE", "path escapes source root")
    if os.path.islink(path): raise EvidenceError("SECURITY_BLOCK", "symlink input is denied")

def inventory(root):
    root = os.path.realpath(root)
    if not os.path.isdir(root): raise EvidenceError("UNSUPPORTED_INPUT", "source root is not a directory")
    rows=[]
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base,d)))
        for name in sorted(files):
            path=os.path.join(base,name); _safe(root,path)
            rel=os.path.relpath(path,root).replace(os.sep,"/")
            with open(path,"rb") as stream:
                raw=stream.read()
            kind="binary"
            data=None
            try:
                text=raw.decode("utf-8"); kind="json" if name.lower().endswith(".json") else "text"
                if kind == "json":
                    data=json.loads(text)
            except (UnicodeDecodeError,json.JSONDecodeError):
                text=""
            findings=scan_object(data,rel) if data is not None else []
            rows.append({"path":path,"relative_path":rel,"phase_id":phase_id(rel,data),"artifact_type":artifact_type(rel),"sha256":file_sha256(path),"size_bytes":len(raw),"line_count":text.count("\n"),"content_kind":kind,"current_validity":data.get("current_validity","UNKNOWN") if isinstance(data,dict) else "UNKNOWN","dependencies":data.get("dependencies",[]) if isinstance(data,dict) else [],"superseded_by":data.get("superseded_by","NONE") if isinstance(data,dict) else "NONE","invalidated_by":data.get("invalidated_by","NONE") if isinstance(data,dict) else "NONE","sensitive_class":"SECRET_RISK" if findings else "NON_SENSITIVE_METADATA","cloud_eligibility":"NEVER_CLOUD" if findings else "CLOUD_SAFE_SUMMARY"})
    return rows

def load_json(path):
    try:
        with open(path,encoding="utf-8") as stream: return json.load(stream)
    except (OSError,json.JSONDecodeError) as exc: raise EvidenceError("INVALID_SCHEMA", str(exc))

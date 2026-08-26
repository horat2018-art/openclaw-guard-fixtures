import json, os
from .errors import HarnessError
from .canonical import sha256_bytes

def safe_root(root):
    r = os.path.realpath(root)
    if not os.path.isdir(r):
        raise HarnessError("UNSUPPORTED_INPUT", "source root is not a directory", "DISCOVERY")
    return r

def discover(root):
    r = safe_root(root)
    out = []
    for base, dirs, files in os.walk(r, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base, d)))
        for name in sorted(files):
            p = os.path.join(base, name)
            real = os.path.realpath(p)
            if os.path.commonpath([r, real]) != r or os.path.islink(p):
                raise HarnessError("SOURCE_PATH_ESCAPE", "unsafe source path", "DISCOVERY")
            with open(p, "rb") as stream:
                raw = stream.read()
            digest = sha256_bytes(raw)
            rel = os.path.relpath(p, r).replace(os.sep, "/")
            data = None
            try:
                data = json.loads(raw.decode())
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            if isinstance(data, dict) and data.get("expected_sha256") and data["expected_sha256"] != digest:
                raise HarnessError("HASH_MISMATCH", "artifact content hash mismatch", "DISCOVERY")
            out.append({"reference": rel, "sha256": digest, "size_bytes": len(raw), "data": data})
    return {"root": r, "artifacts": out, "identity": sha256_bytes(json.dumps(out, sort_keys=True, separators=(",", ":")).encode())}

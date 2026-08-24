import hashlib, json, re

def canonical_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

def canonical_sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def approximate_tokens(text):
    return (len(re.findall(r"\S+", text)) + 3) // 4

def write_json(path, value):
    with open(path, "wb") as stream:
        stream.write(canonical_bytes(value))

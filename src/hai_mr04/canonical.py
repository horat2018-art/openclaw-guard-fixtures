import hashlib,json,re
def canonical_bytes(v): return (json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha256_bytes(b): return hashlib.sha256(b).hexdigest()
def canonical_sha256(v): return sha256_bytes(canonical_bytes(v))
def approx_tokens(text): return (len(re.findall(r"\S+",text))+3)//4

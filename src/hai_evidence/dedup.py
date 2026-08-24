from collections import defaultdict
def duplicates(rows):
 by=defaultdict(list)
 for r in rows: by[r["sha256"]].append(r["relative_path"])
 return [{"class":"EXACT_HASH_DUPLICATE","sha256":k,"paths":sorted(v)} for k,v in sorted(by.items()) if len(v)>1]

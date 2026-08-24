import argparse, json, os, sys
from .errors import EvidenceError, EXIT_CODES
from .canonical import write_json, canonical_sha256, file_sha256
from .inventory import inventory, load_json
from .package import build
from .validation import validate_package
from .benchmark import compare

def _check_output_boundary(source, output):
 source_real=os.path.realpath(source); output_real=os.path.realpath(output)
 if source_real == output_real:
  raise EvidenceError("SECURITY_BLOCK", "output root equals source root")
 try:
  common=os.path.commonpath([source_real,output_real])
 except ValueError:
  common=None
 if common in (source_real,output_real):
  raise EvidenceError("SECURITY_BLOCK", "source and output roots overlap")

def main(argv=None):
 p=argparse.ArgumentParser(prog="hai-evidence"); sub=p.add_subparsers(dest="command",required=True)
 i=sub.add_parser("inventory");i.add_argument("source");i.add_argument("--output",required=True)
 v=sub.add_parser("verify");v.add_argument("inventory")
 s=sub.add_parser("status");s.add_argument("source");s.add_argument("--output",required=True)
 q=sub.add_parser("package");q.add_argument("--task",required=True);q.add_argument("--source",required=True);q.add_argument("--output",required=True)
 x=sub.add_parser("validate");x.add_argument("package")
 b=sub.add_parser("benchmark");b.add_argument("raw");b.add_argument("package")
 a=p.parse_args(argv)
 try:
  if a.command=="inventory": write_json(a.output, {"entries":inventory(a.source)})
  elif a.command=="verify":
   data=load_json(a.inventory); rows=data.get("entries",[]); bad=[]
   for r in rows:
    path=r.get("path"); expected=r.get("sha256")
    if not path or not os.path.isfile(path): bad.append({"path":path,"code":"MISSING_REQUIRED_ARTIFACT"}); continue
    if expected and file_sha256(path) != expected: bad.append({"path":path,"code":"HASH_MISMATCH"})
   if bad: raise EvidenceError(bad[0]["code"],"artifact verification failed",{"artifacts":bad})
   print(json.dumps({"result":"PASS","entries":len(rows)}))
  elif a.command=="status":
   rows=inventory(a.source); write_json(a.output,{"entries":rows})
  elif a.command=="package":
   _check_output_boundary(a.source,a.output)
   rows=inventory(a.source); task=load_json(a.task);payload,manifest=build(rows,task);os.makedirs(a.output,exist_ok=False);write_json(os.path.join(a.output,"optimized_package.json"),payload);write_json(os.path.join(a.output,"optimized_package_manifest.json"),manifest)
  elif a.command=="validate": print(json.dumps(validate_package(load_json(os.path.join(a.package,"optimized_package.json")))))
  elif a.command=="benchmark": print(json.dumps(compare(open(a.raw,encoding="utf-8").read(),open(os.path.join(a.package,"optimized_package.json"),encoding="utf-8").read())))
  return 0
 except EvidenceError as exc:
  print(json.dumps({"result":"BLOCK","code":exc.code,"message":str(exc),"details":exc.details},sort_keys=True),file=sys.stderr);return EXIT_CODES.get("SECURITY_BLOCK" if exc.code in ("SECRET_RISK","PROTECTED_CONTENT_SELECTED") else "PROVENANCE_FAILURE" if exc.code=="PROVENANCE_GAP" else "INPUT_SCHEMA_FAILURE" if exc.code in ("INVALID_SCHEMA","UNSUPPORTED_INPUT") else "VALIDATION_FAILURE",1)
if __name__=="__main__": raise SystemExit(main())

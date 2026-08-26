import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
from hai_mr04.bounded_context import build
class FailureTests(unittest.TestCase):
 def test_invalid_root(self):
  with self.assertRaises(Exception) as c: discover('/not/a/real/root')
  self.assertEqual(c.exception.code,'UNSUPPORTED_INPUT')
 def test_invalid_validity(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'x.json').write_text(json.dumps({'current_validity':'BAD'}));
   with self.assertRaises(Exception) as c: build(normalize(discover(p)))
   self.assertEqual(c.exception.code,'INVALID_SCHEMA')
 def test_ambiguous(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'a.json').write_text(json.dumps({'current_validity':'VALID','claim_scope':'s','authority_level':1,'claim_value':'A'}));(p/'b.json').write_text(json.dumps({'current_validity':'VALID','claim_scope':'s','authority_level':1,'claim_value':'B'}));
   with self.assertRaises(Exception) as c: build(normalize(discover(p)))
   self.assertEqual(c.exception.code,'AMBIGUOUS_PRECEDENCE')
 def test_fail_closed_is_explicit(self): self.assertTrue('MR03_IDENTITY_MISMATCH' in __import__('hai_mr04.errors',fromlist=['CODES']).CODES)

 def test_failure_code_ownership_is_complete(self):
  from hai_mr04.errors import CODES, ERROR_OWNERS
  required={'HASH_MISMATCH','MISSING_REQUIRED_ARTIFACT','AMBIGUOUS_PRECEDENCE','INVALID_SCHEMA','UNKNOWN_VALIDITY','PROTECTED_CONTENT_SELECTED','SECRET_RISK','PROVENANCE_GAP','DUPLICATE_CONFLICT','NONDETERMINISTIC_OUTPUT','UNSUPPORTED_INPUT','MR03_IDENTITY_MISMATCH','SOURCE_PATH_ESCAPE','PROPOSER_SCHEMA_INVALID','PROPOSAL_SOURCE_REF_INVALID'}
  self.assertTrue(required <= CODES);self.assertEqual(set(ERROR_OWNERS),CODES-{'PROPOSAL_PACKAGE_BINDING_MISMATCH'} | {'PROPOSAL_PACKAGE_BINDING_MISMATCH'});self.assertEqual(len(set(ERROR_OWNERS.values())),6)

 def test_hash_mismatch_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'bad.json').write_text(json.dumps({'expected_sha256':'0'*64}))
   with self.assertRaises(Exception) as c: discover(p)
   self.assertEqual(c.exception.code,'HASH_MISMATCH')

 def test_duplicate_conflict_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'a.json').write_text(json.dumps({'duplicate_key':'same'}));(p/'b.json').write_text(json.dumps({'duplicate_key':'same','x':1}))
   with self.assertRaises(Exception) as c: normalize(discover(p))
   self.assertEqual(c.exception.code,'DUPLICATE_CONFLICT')

 def test_nondeterministic_output_fails_closed(self):
  from hai_mr04.verifier import verify
  ctx={'schema_version':'bounded-context-package-v2','package_identity':'i','package_sha256':'s','source_reference_set':[],'protected_content_status':'RAW_EXCLUDED'}
  p={'schema_version':'proposal-v2','package_identity':'i','package_sha256':'s','package_schema_version':'bounded-context-package-v2','proposal':'x','source_refs':[],'confidence_state':'DERIVED','unresolved_issues':[],'escalation_signals':[],'no_action':False,'deterministic_output':False}
  self.assertEqual(verify(ctx,p)['code'],'NONDETERMINISTIC_OUTPUT')

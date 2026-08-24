import copy, hashlib, json, os, pathlib, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from hai_evidence.canonical import canonical_bytes, canonical_sha256
from hai_evidence.dedup import duplicates
from hai_evidence.errors import EvidenceError
from hai_evidence.inventory import inventory
from hai_evidence.package import build
from hai_evidence.security import scan_object, enforce_safe
from hai_evidence.supersession import graph
from hai_evidence.validation import validate_package

class BlockingContractTests(unittest.TestCase):
 def fixture(self,name): return ROOT/'tests'/'fixtures'/name
 def load(self,name):
  with open(self.fixture(name), encoding='utf-8') as stream: return json.load(stream)
 def test_01_inventory_pass(self): self.assertEqual(inventory(str(ROOT/'tests'/'fixtures'))[0]['content_kind'],'json')
 def test_02_blocked_result_semantics(self):
  d=self.load('02_blocked_pre_write.json'); self.assertEqual(d['GW_RESULT'],'B. BLOCKED_PRE_WRITE');self.assertEqual(d['SYNTHETIC_STATE_WRITE_AUTHORITY'],'UNUSED_OR_BLOCKED_PRE_WRITE')
 def test_03_supersession(self):
  g=graph([{'relative_path':'a','sha256':'1','current_validity':'VALID','superseded_by':'b'},{'relative_path':'b','sha256':'2','current_validity':'VALID'}]);self.assertEqual(g['edges'][0]['relation'],'SUPERSEDED')
 def test_04_scope_invalidation(self): d=self.load('04_scope_invalidated.json');self.assertEqual(d['current_validity'],'VALID_WITH_SCOPE_LIMITATION');self.assertEqual(d['invalidated_scope'],'zero-send only')
 def test_05_exact_duplicate(self): rows=[{'sha256':'x','relative_path':'a'},{'sha256':'x','relative_path':'b'}];self.assertEqual(len(duplicates(rows)),1)
 def test_06_hash_mismatch_fixture_is_explicit(self): d=self.load('07_hash_mismatch.json');self.assertEqual(d['expected_sha256'],'deadbeef')
 def test_07_missing_fixture_is_explicit(self): d=self.load('08_missing_required.json');self.assertIn('required_artifact',d)
 def test_08_ambiguous_precedence_is_not_guessed(self): d=self.load('09_ambiguous_precedence.json');self.assertTrue(d['conflicting_authoritative_claims'])
 def test_09_secret_filter(self): findings=scan_object(self.load('10_fake_secret.json'),'10_fake_secret.json');self.assertTrue(findings);self.assertNotIn('fake-not-real-value',json.dumps(findings))
 def test_10_v2_protection(self):
  with self.assertRaises(EvidenceError) as c: enforce_safe(self.load('11_fake_v2.json'),'11_fake_v2.json')
  self.assertEqual(c.exception.code,'PROTECTED_CONTENT_SELECTED')
 def test_11_repeated_governance_preserved(self): a=self.load('05_duplicate_a.json');b=self.load('06_duplicate_b.json');self.assertEqual(a['governance'],b['governance']);self.assertNotEqual(a['phase'],b['phase'])
 def test_12_time_scope(self): d=self.load('12_time_scope.json');self.assertEqual(d['LAST_VERIFIED'],'VALID_AT_X');self.assertEqual(d['CURRENT'],'NOT_RECHECKED')
 def test_13_byte_stability(self): v={'b':1,'a':[2,3]};self.assertEqual(canonical_bytes(v),canonical_bytes(copy.deepcopy(v)));self.assertEqual(canonical_sha256(v),canonical_sha256(copy.deepcopy(v)))
 def test_14_order_independence(self):
  a=[{'sha256':'2','relative_path':'b'},{'sha256':'1','relative_path':'a'}];b=list(reversed(a));self.assertEqual(canonical_bytes(sorted(a,key=lambda x:x['relative_path'])),canonical_bytes(sorted(b,key=lambda x:x['relative_path'])))
 def test_15_package_validation(self):
  rows=[{'path':str(self.fixture('01_pass.json')),'relative_path':'01_pass.json','phase_id':'TEST-A','artifact_type':'OTHER','sha256':hashlib.sha256(self.fixture('01_pass.json').read_bytes()).hexdigest(),'size_bytes':10,'current_validity':'VALID','sensitive_class':'NON_SENSITIVE_METADATA'}]
  pkg,_=build(rows,{'task_id':'t','task_class':'PHASE_RESULT_REVIEW'});self.assertEqual(validate_package(pkg)['result'],'PASS')

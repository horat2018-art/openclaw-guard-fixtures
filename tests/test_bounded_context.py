import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
from hai_mr04.bounded_context import build, package_identity_from_semantics, package_sha256_from_content
class ContextTests(unittest.TestCase):
 def rows(self,v):
  d=tempfile.TemporaryDirectory();p=pathlib.Path(d.name);(p/'a.json').write_text(json.dumps(v));return d,normalize(discover(p))
 def test_layers_and_identity(self):
  d,r=self.rows({'current_validity':'VALID','mandatory':True});p=build(r);self.assertTrue(all(k in p for k in ['L0_IDENTITY_HEADER','L1_CURRENT_STATE','L2_REQUIRED_EVIDENCE','L3_RELEVANT_HISTORICAL_DELTA','L4_PROVENANCE_REFERENCES','L5_EXCLUDED_EVIDENCE_INDEX','L6_VALIDATION_REPORT']));self.assertEqual(len(p['package_identity']),64);d.cleanup()
 def test_mandatory_retained(self):
  d,r=self.rows({'current_validity':'VALID','mandatory':True});self.assertEqual(len(build(r)['L2_REQUIRED_EVIDENCE']['mandatory']),1);d.cleanup()
 def test_unknown_required_blocks(self):
  d,r=self.rows({'current_validity':'UNKNOWN','mandatory':True});
  with self.assertRaises(Exception) as c: build(r,{'current_state_required':True})
  self.assertEqual(c.exception.code,'UNKNOWN_VALIDITY');d.cleanup()

 def test_token_budget_is_in_identity(self):
  d,r=self.rows({'current_validity':'VALID'});p=build(r);mutated=dict(p);mutated['token_budget']=dict(p['token_budget']);mutated['token_budget']['RAW_INPUT_BYTES']+=1
  self.assertNotEqual(p['package_identity'],package_identity_from_semantics(mutated));d.cleanup()

 def test_package_sha_changes_with_current_semantic_content(self):
  d,r=self.rows({'current_validity':'VALID'});p=build(r);mutated=dict(p);mutated['L1_CURRENT_STATE']={'facts':['changed']}
  self.assertNotEqual(p['package_sha256'],package_sha256_from_content(mutated));d.cleanup()

 def test_missing_required_artifact_is_owned(self):
  d,r=self.rows({'current_validity':'VALID'});
  with self.assertRaises(Exception) as c: build(r,{'required_references':['missing.json']})
  self.assertEqual(c.exception.code,'MISSING_REQUIRED_ARTIFACT');self.assertEqual(c.exception.owner,'BOUNDED_CONTEXT');d.cleanup()

 def test_historical_delta_reference_retained(self):
  d,r=self.rows({'current_validity':'SUPERSEDED','phase_id':'MR03','artifact_type':'HISTORICAL','superseded_by':'new'});p=build(r);self.assertEqual(len(p['L3_RELEVANT_HISTORICAL_DELTA']['references']),1);d.cleanup()

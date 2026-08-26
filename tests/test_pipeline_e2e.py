import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.pipeline import run
class E2ETests(unittest.TestCase):
 def source(self,v):
  d=tempfile.TemporaryDirectory();p=pathlib.Path(d.name);(p/'x.json').write_text(json.dumps(v));return d,p
 def test_normal_pass_for_review(self):
  d,p=self.source({'current_validity':'VALID','mandatory':True});r=run(str(p));self.assertEqual(r['verification']['decision'],'PASS_FOR_REVIEW');self.assertFalse(r['human_gate']['human_approval']);d.cleanup()
 def test_escalation(self):
  d,p=self.source({'current_validity':'VALID'});self.assertEqual(run(str(p),mode='escalate')['verification']['decision'],'ESCALATE');d.cleanup()
 def test_deny_malformed_proposer(self):
  d,p=self.source({'current_validity':'VALID'});self.assertEqual(run(str(p),mode='malformed')['verification']['decision'],'DENY');d.cleanup()
 def test_no_action_is_not_execution(self):
  d,p=self.source({'current_validity':'VALID'});r=run(str(p));self.assertEqual(r['human_gate']['authority_granted'],False);d.cleanup()

 def test_real_mr03_adapter_path_is_used(self):
  d,p=self.source({'current_validity':'VALID'});r=run(str(p));self.assertTrue(r['mr03_adapter_invoked']);self.assertIn('L0_IDENTITY_HEADER',r['mr03_adapter_output']);d.cleanup()

 def test_binding_fields_reach_proposal(self):
  d,p=self.source({'current_validity':'VALID'});r=run(str(p));self.assertEqual(r['proposal']['package_identity'],r['package']['package_identity']);self.assertEqual(r['proposal']['package_sha256'],r['package']['package_sha256']);d.cleanup()

 def test_stale_identity_is_denied_after_pipeline_package_mutation(self):
  from hai_mr04.verifier import verify
  d,p=self.source({'current_validity':'VALID'});r=run(str(p));r['package']['L1_CURRENT_STATE']['facts'].append({'mutated':True})
  result=verify(r['package'],r['proposal'])
  self.assertEqual(result['decision'],'DENY');self.assertEqual(result['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH');d.cleanup()

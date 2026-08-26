import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest
from hai_mr04.bounded_context import package_identity_from_semantics, package_sha256_from_content
from hai_mr04.verifier import verify
class VerifierTests(unittest.TestCase):
 def ctx(self):
  context={'schema_version':'bounded-context-package-v2','package_schema_version':'bounded-context-package-v2','package_identity':'','package_sha256':'','source_reference_set':[],'protected_content_status':'RAW_EXCLUDED','L1_CURRENT_STATE':{'facts':['stable']},'token_budget':{'RAW_INPUT_BYTES':10}}
  context['package_identity']=package_identity_from_semantics(context)
  context['package_sha256']=package_sha256_from_content(context)
  return context
 def proposal(self,context,**changes):
  proposal={'schema_version':'proposal-v2','package_identity':context['package_identity'],'package_sha256':context['package_sha256'],'package_schema_version':context['schema_version'],'proposal':'x','source_refs':[],'confidence_state':'DERIVED','unresolved_issues':[],'escalation_signals':[],'no_action':False}
  proposal.update(changes)
  return proposal
 def test_pass_is_not_approval(self):
  c=self.ctx();r=verify(c,self.proposal(c));self.assertEqual(r['decision'],'PASS_FOR_REVIEW');self.assertFalse(r['approval'])
 def test_deny_bad_schema(self): self.assertEqual(verify(self.ctx(),{})['decision'],'DENY')
 def test_deny_bad_ref(self):
  c=self.ctx();p=self.proposal(c,source_refs=[{'sha256':'0'*64}]);self.assertEqual(verify(c,p)['decision'],'DENY')
 def test_escalate_issue(self):
  c=self.ctx();p=self.proposal(c,confidence_state='U',unresolved_issues=['x']);self.assertEqual(verify(c,p)['decision'],'ESCALATE')

 def test_cross_package_binding_is_denied(self):
  c=self.ctx();p=self.proposal(c,package_identity='other',package_sha256='other')
  self.assertEqual(verify(c,p)['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH')

 def test_semantic_mutation_with_stale_pair_is_denied(self):
  c=self.ctx();p=self.proposal(c);c['L1_CURRENT_STATE']['facts'].append('mutated')
  result=verify(c,p)
  self.assertEqual(result['decision'],'DENY');self.assertEqual(result['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH')

 def test_token_budget_mutation_with_stale_identity_is_denied(self):
  c=self.ctx();p=self.proposal(c);c['token_budget']['RAW_INPUT_BYTES']=11
  result=verify(c,p)
  self.assertEqual(result['decision'],'DENY');self.assertEqual(result['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH')

 def test_declared_identity_tampering_is_denied(self):
  c=self.ctx();p=self.proposal(c);c['package_identity']='0'*64
  self.assertEqual(verify(c,p)['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH')

 def test_proposal_identity_tampering_is_denied(self):
  c=self.ctx();p=self.proposal(c,package_identity='0'*64)
  self.assertEqual(verify(c,p)['code'],'PROPOSAL_PACKAGE_BINDING_MISMATCH')

 def test_declared_and_proposal_equal_stale_identity_do_not_pass(self):
  c=self.ctx();p=self.proposal(c);c['L1_CURRENT_STATE']['facts']=['different'];c['package_identity']=p['package_identity'];c['package_sha256']=p['package_sha256']
  self.assertEqual(verify(c,p)['decision'],'DENY')

 def test_deny_precedes_escalate(self):
  c=self.ctx();p=self.proposal(c,source_refs=[{'sha256':'0'*64}],confidence_state='U',unresolved_issues=['x'],escalation_signals=['AMBIGUOUS_PRECEDENCE'])
  self.assertEqual(verify(c,p)['decision'],'DENY')

 def test_deny_precedes_pass(self):
  c=self.ctx();c['protected_content_status']='RAW_INCLUDED'
  c['package_identity']=package_identity_from_semantics(c)
  c['package_sha256']=package_sha256_from_content(c)
  p=self.proposal(c)
  self.assertEqual(p['confidence_state'],'DERIVED')
  self.assertEqual(p['unresolved_issues'],[])
  self.assertEqual(p['escalation_signals'],[])
  result=verify(c,p)
  self.assertEqual(result['decision'],'DENY')
  self.assertEqual(result['code'],'PROTECTED_CONTENT_SELECTED')

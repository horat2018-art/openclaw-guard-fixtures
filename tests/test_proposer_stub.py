import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest
from hai_mr04.proposer_stub import propose
class StubTests(unittest.TestCase):
 def ctx(self): return {'source_reference_set':[],'protected_content_status':'RAW_EXCLUDED'}
 def test_normal_schema(self):
  x=propose(self.ctx());self.assertTrue({'proposal','source_refs','confidence_state','unresolved_issues','escalation_signals','no_action'}<=x.keys())
 def test_escalation_mode(self): self.assertEqual(propose(self.ctx(),'escalate')['escalation_signals'],['AMBIGUOUS_PRECEDENCE'])

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest
from hai_mr04.token_budget import measure,classify
class TokenTests(unittest.TestCase):
 def test_metrics(self):
  m=measure('one two three',{'x':1});self.assertIn('BYTE_REDUCTION_PERCENT',m);self.assertEqual(m['TOKEN_ESTIMATE_CLASS'],'APPROXIMATE_ESTIMATE')
 def test_classes(self): self.assertEqual(classify(1),'NORMAL');self.assertEqual(classify(5001),'HIGH_CONTEXT');self.assertEqual(classify(1,protected=True),'PROTECTED_BLOCKED');self.assertEqual(classify(1,full_raw=True),'FULL_RAW_REQUIRED')
 def test_primary_metric(self): self.assertTrue('BYTE_REDUCTION_PERCENT' in measure('a b',{}))

 def test_identity_semantics_are_finalized(self):
  self.assertEqual(classify(1),'NORMAL')
  self.assertEqual(measure('one two',{'token_budget':{'raw_bytes':1}})['TOKEN_ESTIMATE_CLASS'],'APPROXIMATE_ESTIMATE')

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.pipeline import run
class DeterminismTests(unittest.TestCase):
 def source(self):
  d=tempfile.TemporaryDirectory();p=pathlib.Path(d.name);(p/'x.json').write_text(json.dumps({'current_validity':'VALID','mandatory':True}));return d,p
 def test_pipeline_bytes_stable(self):
  d,p=self.source();a=run(str(p));b=run(str(p));self.assertEqual(a,b);d.cleanup()
 def test_canonical_key_stability(self): self.assertEqual(json.dumps({'b':1,'a':2},sort_keys=True),json.dumps({'a':2,'b':1},sort_keys=True))
 def test_no_time_identity(self):
  d,p=self.source();r=run(str(p));self.assertNotIn('timestamp',json.dumps(r));d.cleanup()

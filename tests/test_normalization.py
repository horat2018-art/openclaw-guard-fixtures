import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
class NormalizationTests(unittest.TestCase):
 def make(self,v):
  d=tempfile.TemporaryDirectory();p=pathlib.Path(d.name);(p/'a.json').write_text(json.dumps(v));return d,p
 def test_required_fields(self):
  d,p=self.make({'current_validity':'VALID','mandatory':True});rows=normalize(discover(p));self.assertTrue({'sha256','artifact_type','phase_id','provenance','mandatory'}<=rows[0].keys());d.cleanup()
 def test_unknown_is_explicit(self):
  d,p=self.make({});self.assertEqual(normalize(discover(p))[0]['current_validity'],'UNKNOWN');d.cleanup()
 def test_deterministic_order(self):
  d,p=self.make({'current_validity':'VALID'});self.assertEqual(normalize(discover(p)),normalize(discover(p)));d.cleanup()

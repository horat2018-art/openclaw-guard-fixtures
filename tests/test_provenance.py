import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
from hai_mr04.provenance import validate
class ProvenanceTests(unittest.TestCase):
 def test_complete(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'a.json').write_text(json.dumps({'current_validity':'VALID'}));self.assertEqual(validate(normalize(discover(p))),'100%')
 def test_gap_rejected(self):
  with self.assertRaises(Exception) as c: validate([{'provenance':{}}])
  self.assertEqual(c.exception.code,'PROVENANCE_GAP')

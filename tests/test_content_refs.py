import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
from hai_mr04.content_refs import ref,ref_set,identity
class RefTests(unittest.TestCase):
 def rows(self):
  d=tempfile.TemporaryDirectory();p=pathlib.Path(d.name);(p/'a.json').write_text(json.dumps({'current_validity':'VALID'}));return d,normalize(discover(p))
 def test_reference_has_content_identity(self):
  d,r=self.rows();x=ref(r[0]);self.assertEqual(len(x['sha256']),64);self.assertIn('phase_id',x);d.cleanup()
 def test_order_independent_set(self):
  d,r=self.rows();self.assertEqual(identity(r),identity(list(reversed(r))));self.assertEqual(ref_set(r),ref_set(list(reversed(r))));d.cleanup()

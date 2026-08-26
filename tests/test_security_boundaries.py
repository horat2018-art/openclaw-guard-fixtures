import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest, pathlib, tempfile, json
from hai_mr04.discovery import discover
from hai_mr04.errors import HarnessError
class SecurityTests(unittest.TestCase):
 def test_no_network_import_surface(self):
  import hai_mr04.pipeline as p;self.assertFalse(hasattr(p,'requests'))
 def test_no_model_surface(self):
  import hai_mr04.proposer_stub as p;self.assertFalse(hasattr(p,'openai'))
 def test_symlink_escape(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);q=pathlib.Path(tempfile.mkdtemp())/'q';q.write_text('{}');(p/'q').symlink_to(q)
   with self.assertRaises(HarnessError) as c: discover(p)
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE')
   self.assertEqual(c.exception.owner,'DISCOVERY')

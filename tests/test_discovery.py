import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib
from hai_mr04.discovery import discover
class DiscoveryTests(unittest.TestCase):
 def test_sorted_and_hashed(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'b.json').write_text('{}');(p/'a.json').write_text('{}');x=discover(p);self.assertEqual([r['reference'] for r in x['artifacts']],['a.json','b.json'])
 def test_repeat_identity(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'a.json').write_text('{}');self.assertEqual(discover(p)['identity'],discover(p)['identity'])
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);outside=pathlib.Path(tempfile.mkdtemp())/'x';outside.write_text('{}');(p/'link').symlink_to(outside)
   with self.assertRaises(Exception) as c: discover(p)
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE')

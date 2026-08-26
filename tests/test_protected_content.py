import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json
from hai_mr04.discovery import discover
from hai_mr04.normalization import normalize
from hai_mr04.bounded_context import build
class ProtectionTests(unittest.TestCase):
 def test_protected_blocks(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'p.json').write_text(json.dumps({'protected':True,'synthetic_marker':'NOT_REAL_V2','current_validity':'VALID'}));
   with self.assertRaises(Exception) as c: build(normalize(discover(p)))
   self.assertEqual(c.exception.code,'PROTECTED_CONTENT_SELECTED')
 def test_secret_blocks(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'s.json').write_text(json.dumps({'security':'SECRET_RISK','synthetic_marker':'NOT_SECRET','current_validity':'VALID'}));
   with self.assertRaises(Exception) as c: build(normalize(discover(p)))
   self.assertEqual(c.exception.code,'SECRET_RISK')

 def test_nested_and_array_secret_blocks(self):
  for value in ({'meta':{'API-KEY':'NOT_SECRET'}},{'items':[{'password':'SYNTHETIC_ONLY'}]},{'outer':[{'inner':{'access_token':'NOT_REAL'}}]}):
   with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d);(p/'s.json').write_text(json.dumps(value))
    with self.assertRaises(Exception) as c: build(normalize(discover(p)))
    self.assertEqual(c.exception.code,'SECRET_RISK')

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest,tempfile,pathlib,json,hashlib
from hai_mr04.pipeline import run
class ImmutabilityTests(unittest.TestCase):
 def test_pipeline_reads_source_only(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);f=p/'x.json';f.write_text(json.dumps({'current_validity':'VALID'}));before=hashlib.sha256(f.read_bytes()).hexdigest();run(str(p));self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),before);self.assertEqual(list(p.iterdir()),[f])
 def test_no_output_inside_source(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);f=p/'x.json';f.write_text(json.dumps({'current_validity':'VALID'}));run(str(p));self.assertEqual([x.name for x in p.iterdir()],['x.json'])

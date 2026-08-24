import pathlib,sys,unittest,hashlib,json,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from hai_evidence.inventory import inventory
from hai_evidence.errors import EvidenceError
class ExtraTests(unittest.TestCase):
 def test_source_inventory_reads_only(self): self.assertGreater(len(inventory(str(ROOT/'tests'/'fixtures'))),0)
 def test_path_escape_rejected(self):
  from hai_evidence.inventory import _safe
  with self.assertRaises(EvidenceError): _safe(str(ROOT/'tests'/'fixtures'),str(ROOT/'README.md'))

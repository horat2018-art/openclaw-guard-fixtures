import pathlib
import sys
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

class ImportContractTests(unittest.TestCase):
    def test_repository_local_src_is_resolved(self):
        import hai_mr04
        self.assertEqual(pathlib.Path(hai_mr04.__file__).resolve().parent.parent, _SRC.resolve())
        self.assertIn(str(_SRC.resolve()), [str(pathlib.Path(p).resolve()) for p in sys.path if p])

    def test_no_external_import_bootstrap(self):
        self.assertEqual(_SRC.resolve(), pathlib.Path(__file__).resolve().parents[1] / "src")

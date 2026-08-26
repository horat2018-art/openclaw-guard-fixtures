import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import unittest
from hai_mr04.mr03_adapter import verify_identity,FROZEN
class AdapterTests(unittest.TestCase):
 def test_frozen_identity(self): self.assertEqual(verify_identity(),FROZEN)
 def test_public_boundary_is_explicit(self): self.assertTrue(callable(verify_identity));self.assertEqual(len(FROZEN),40)

 def test_malformed_output_fails_closed(self):
  from hai_mr04.mr03_adapter import _validate_output
  with self.assertRaises(Exception) as c: _validate_output({})
  self.assertEqual(c.exception.code,'INVALID_SCHEMA')

 def test_nonzero_exit_fails_closed(self):
  import tempfile, pathlib
  from unittest.mock import patch
  from types import SimpleNamespace
  from hai_mr04.mr03_adapter import invoke_read_only
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'x.json').write_text('{}')
   with patch('hai_mr04.mr03_adapter.verify_identity',return_value=FROZEN), patch('hai_mr04.mr03_adapter.subprocess.run',return_value=SimpleNamespace(returncode=1,stderr='synthetic failure')):
    with self.assertRaises(Exception) as c: invoke_read_only(str(p),{})
   self.assertEqual(c.exception.code,'MR03_IDENTITY_MISMATCH')

 def test_path_substitution_fails_closed(self):
  import tempfile, pathlib, os
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);target=root/'real';target.mkdir();link=root/'link';link.symlink_to(target, target_is_directory=True)
   with patch.dict(os.environ,{'HAI_MR03_ROOT':str(link)}):
    with self.assertRaises(Exception) as c: verify_identity()
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE')

 def test_shell_true_is_absent(self):
  import inspect
  from hai_mr04 import mr03_adapter
  self.assertNotIn('shell=True',inspect.getsource(mr03_adapter))

 def test_wrong_identity_fails_closed(self):
  from unittest.mock import patch
  with patch('hai_mr04.mr03_adapter.subprocess.check_output',return_value='0'*40):
   with self.assertRaises(Exception) as c: verify_identity()
  self.assertEqual(c.exception.code,'MR03_IDENTITY_MISMATCH')

 def test_checked_path_is_exact_subprocess_path(self):
  import json, tempfile, pathlib
  from types import SimpleNamespace
  from unittest.mock import patch
  from hai_mr04.mr03_adapter import invoke_read_only
  valid={"L0_IDENTITY_HEADER":{"qualification_exposure":0},"L1_CURRENT_STATE":{},"L2_REQUIRED_EVIDENCE":[],"L3_RELEVANT_HISTORICAL_DELTA":[],"L4_PROVENANCE_REFERENCES":[],"L5_EXCLUDED_EVIDENCE_INDEX":[],"L6_VALIDATION_REPORT":{}}
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d).resolve();seen={}
   def fake_run(argv,**kwargs):
    seen['cwd']=kwargs['cwd'];seen['pythonpath']=kwargs['env']['PYTHONPATH']
    output=pathlib.Path(argv[argv.index('--output')+1]);output.mkdir()
    (output/'optimized_package.json').write_text(json.dumps(valid))
    return SimpleNamespace(returncode=0,stderr='')
   with patch('hai_mr04.mr03_adapter._resolved_root',return_value=str(root)) as resolve, patch('hai_mr04.mr03_adapter.verify_identity',side_effect=lambda checked: seen.setdefault('checked',checked)), patch('hai_mr04.mr03_adapter.subprocess.run',side_effect=fake_run):
    result=invoke_read_only(str(root/'source'),{})
   self.assertEqual(result,valid);self.assertEqual(resolve.call_count,1);self.assertEqual(seen['cwd'],str(root));self.assertEqual(seen['pythonpath'],str(root/'src'))

 def test_second_resolution_cannot_substitute_execution_path(self):
  import json, tempfile, pathlib
  from types import SimpleNamespace
  from unittest.mock import patch
  from hai_mr04.mr03_adapter import invoke_read_only
  valid={"L0_IDENTITY_HEADER":{"qualification_exposure":0},"L1_CURRENT_STATE":{},"L2_REQUIRED_EVIDENCE":[],"L3_RELEVANT_HISTORICAL_DELTA":[],"L4_PROVENANCE_REFERENCES":[],"L5_EXCLUDED_EVIDENCE_INDEX":[],"L6_VALIDATION_REPORT":{}}
  with tempfile.TemporaryDirectory() as d:
   root_a=pathlib.Path(d,'a').resolve();root_b=pathlib.Path(d,'b').resolve();root_a.mkdir();root_b.mkdir();seen={}
   def fake_run(argv,**kwargs):
    seen['cwd']=kwargs['cwd']
    output=pathlib.Path(argv[argv.index('--output')+1]);output.mkdir()
    (output/'optimized_package.json').write_text(json.dumps(valid))
    return SimpleNamespace(returncode=0,stderr='')
   with patch('hai_mr04.mr03_adapter._resolved_root',side_effect=[str(root_a),str(root_b)]) as resolve, patch('hai_mr04.mr03_adapter.verify_identity',side_effect=lambda checked: seen.setdefault('checked',checked)), patch('hai_mr04.mr03_adapter.subprocess.run',side_effect=fake_run):
    invoke_read_only(str(root_a/'source'),{})
   self.assertEqual(resolve.call_count,1);self.assertEqual(seen['checked'],str(root_a));self.assertEqual(seen['cwd'],str(root_a))

 def test_alternate_clone_path_fails_closed(self):
  import os, tempfile, pathlib
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   clone=pathlib.Path(d,'clone');clone.mkdir()
   with patch.dict(os.environ,{'HAI_MR03_ROOT':str(clone)}):
    with self.assertRaises(Exception) as c: verify_identity()
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE')

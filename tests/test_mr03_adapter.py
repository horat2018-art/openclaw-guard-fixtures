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

 def test_checked_path_is_descriptor_pinned_subprocess_path(self):
  import json, tempfile, pathlib, os
  from types import SimpleNamespace
  from unittest.mock import patch
  from hai_mr04.mr03_adapter import invoke_read_only
  valid={"L0_IDENTITY_HEADER":{"qualification_exposure":0},"L1_CURRENT_STATE":{},"L2_REQUIRED_EVIDENCE":[],"L3_RELEVANT_HISTORICAL_DELTA":[],"L4_PROVENANCE_REFERENCES":[],"L5_EXCLUDED_EVIDENCE_INDEX":[],"L6_VALIDATION_REPORT":{}}
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d,'root').resolve();root.mkdir();seen={}
   def fake_run(argv,**kwargs):
    seen['cwd']=kwargs['cwd'];seen['pythonpath']=kwargs['env']['PYTHONPATH'];seen['pass_fds']=kwargs['pass_fds'];seen['resolved']=os.path.realpath(kwargs['cwd'])
    output=pathlib.Path(argv[argv.index('--output')+1]);output.mkdir()
    (output/'optimized_package.json').write_text(json.dumps(valid))
    return SimpleNamespace(returncode=0,stderr='')
   with patch('hai_mr04.mr03_adapter.DEFAULT_ROOT',str(root)), patch('hai_mr04.mr03_adapter._resolved_root',return_value=str(root)) as resolve, patch('hai_mr04.mr03_adapter._verify_identity_fd',return_value='x'*40), patch('hai_mr04.mr03_adapter.subprocess.run',side_effect=fake_run):
    result=invoke_read_only(str(root/'source'),{})
   self.assertEqual(result,valid);self.assertEqual(resolve.call_count,1);self.assertTrue(seen['cwd'].startswith('/proc/self/fd/'));self.assertEqual(seen['resolved'],str(root));self.assertEqual(seen['pythonpath'],seen['cwd']+'/src');self.assertEqual(len(seen['pass_fds']),1)

 def test_root_replacement_during_subprocess_fails_closed(self):
  import json, tempfile, pathlib, os
  from types import SimpleNamespace
  from unittest.mock import patch
  from hai_mr04.mr03_adapter import invoke_read_only
  valid={"L0_IDENTITY_HEADER":{"qualification_exposure":0},"L1_CURRENT_STATE":{},"L2_REQUIRED_EVIDENCE":[],"L3_RELEVANT_HISTORICAL_DELTA":[],"L4_PROVENANCE_REFERENCES":[],"L5_EXCLUDED_EVIDENCE_INDEX":[],"L6_VALIDATION_REPORT":{}}
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d,'root').resolve();root.mkdir();moved=pathlib.Path(d,'moved').resolve();seen={}
   def fake_run(argv,**kwargs):
    root.rename(moved);root.mkdir();seen['executed_root']=os.path.realpath(kwargs['cwd'])
    output=pathlib.Path(argv[argv.index('--output')+1]);output.mkdir()
    (output/'optimized_package.json').write_text(json.dumps(valid))
    return SimpleNamespace(returncode=0,stderr='')
   with patch('hai_mr04.mr03_adapter.DEFAULT_ROOT',str(root)), patch('hai_mr04.mr03_adapter._resolved_root',return_value=str(root)), patch('hai_mr04.mr03_adapter._verify_identity_fd',return_value='x'*40), patch('hai_mr04.mr03_adapter.subprocess.run',side_effect=fake_run):
    with self.assertRaises(Exception) as c: invoke_read_only(str(root/'source'),{})
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE');self.assertEqual(seen['executed_root'],str(moved))

 def test_alternate_clone_path_fails_closed(self):
  import os, tempfile, pathlib
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   clone=pathlib.Path(d,'clone');clone.mkdir()
   with patch.dict(os.environ,{'HAI_MR03_ROOT':str(clone)}):
    with self.assertRaises(Exception) as c: verify_identity()
   self.assertEqual(c.exception.code,'SOURCE_PATH_ESCAPE')

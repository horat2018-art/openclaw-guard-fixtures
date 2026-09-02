import ast
from pathlib import Path
import unittest

from hai_mr05 import failures


class BoundaryTests(unittest.TestCase):
    def test_source_has_no_external_client_or_execution_imports(self):
        source_root = Path(__file__).parents[1] / 'src' / 'hai_mr05'
        globally_banned = (
            'import requests', 'import httpx', 'import aiohttp', 'import socket',
            'import urllib', 'import openai', 'import anthropic', 'import boto3',
            'os.getenv', 'os.environ', 'socket.', 'requests.', 'httpx.', 'aiohttp.',
        )
        dependency_operational_tokens = ('import subprocess', 'subprocess.', 'open(')
        source_read_tokens = ('os.open(', 'os.read(', 'os.fstat(', 'os.lstat(')
        for path in source_root.glob('*.py'):
            text = path.read_text(encoding='utf-8')
            for token in globally_banned:
                with self.subTest(path=path.name, token=token):
                    self.assertNotIn(token, text)
            if path.name == 'dependency_runtime.py':
                for token in dependency_operational_tokens:
                    with self.subTest(path=path.name, required_operational_token=token): self.assertIn(token, text)
                self.assertIn('"latest_resolution": False', text)
                self.assertIn('"alternate_clone": False', text)
                self.assertIn('AUTO_RETRY_IMPLEMENTATION_COUNT = 0', text)
                self.assertIn('AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0', text)
            elif path.name == 'source_acquisition.py':
                for token in ('import subprocess', 'subprocess.'):
                    with self.subTest(path=path.name, token=token): self.assertNotIn(token, text)
                for token in source_read_tokens:
                    with self.subTest(path=path.name, required_source_read_token=token): self.assertIn(token, text)
                self.assertIn('FILESYSTEM_SOURCE_READ_COUNT = 1', text)
                self.assertIn('AUTO_RETRY_IMPLEMENTATION_COUNT = 0', text)
                self.assertIn('AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0', text)
            else:
                for token in dependency_operational_tokens + source_read_tokens:
                    with self.subTest(path=path.name, token=token): self.assertNotIn(token, text)
                with self.subTest(path=path.name, token='latest'): self.assertNotIn('latest', text.lower())

    def test_source_imports_are_stdlib_or_local_only(self):
        source_root = Path(__file__).parents[1] / 'src' / 'hai_mr05'
        prohibited = {'requests','httpx','aiohttp','socket','urllib','openai','anthropic','boto3','http','ssl'}
        for path in source_root.glob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import): names = [alias.name.split('.')[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module: names = [node.module.split('.')[0]]
                else: continue
                for name in names:
                    with self.subTest(path=path.name, module=name): self.assertNotIn(name, prohibited)
                    if name == 'subprocess':
                        with self.subTest(path=path.name, module=name, boundary='operational-only'): self.assertEqual(path.name, 'dependency_runtime.py')

    def test_fail_closed_exception_is_available(self):
        with self.assertRaises(failures.MR05PhaseNotImplementedError): failures.phase_not_implemented('boundary-test')

    def test_implemented_module_legacy_boundary_still_fails_closed(self):
        from hai_mr05 import canonical, metrics, provenance
        with self.assertRaises(failures.MR05PhaseNotImplementedError): canonical.not_implemented()
        with self.assertRaises(failures.MR05PhaseNotImplementedError): metrics.not_implemented()
        with self.assertRaises(failures.MR05PhaseNotImplementedError): provenance.not_implemented()

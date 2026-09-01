import ast
from pathlib import Path
import unittest

from hai_mr05 import failures


class BoundaryTests(unittest.TestCase):
    def test_source_has_no_external_client_or_execution_imports(self):
        source_root = Path(__file__).parents[1] / 'src' / 'hai_mr05'
        banned = (
            'import requests', 'import httpx', 'import aiohttp', 'import socket',
            'import urllib', 'import subprocess', 'import openai', 'import anthropic',
            'import boto3', 'os.getenv', 'os.environ', 'socket.', 'requests.',
            'httpx.', 'aiohttp.',
        )
        for path in source_root.glob('*.py'):
            text = path.read_text(encoding='utf-8')
            for token in banned:
                with self.subTest(path=path.name, token=token):
                    self.assertNotIn(token, text)
            with self.subTest(path=path.name, token='latest'):
                self.assertNotIn('latest', text.lower())

    def test_source_imports_are_stdlib_or_local_only(self):
        source_root = Path(__file__).parents[1] / 'src' / 'hai_mr05'
        prohibited = {
            'requests', 'httpx', 'aiohttp', 'socket', 'urllib', 'subprocess',
            'openai', 'anthropic', 'boto3', 'http', 'ssl',
        }
        for path in source_root.glob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split('.')[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split('.')[0]]
                else:
                    continue
                for name in names:
                    with self.subTest(path=path.name, module=name):
                        self.assertNotIn(name, prohibited)

    def test_fail_closed_exception_is_available(self):
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            failures.phase_not_implemented('boundary-test')

    def test_implemented_module_legacy_boundary_still_fails_closed(self):
        from hai_mr05 import canonical, metrics, provenance

        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            canonical.not_implemented()
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            metrics.not_implemented()
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            provenance.not_implemented()

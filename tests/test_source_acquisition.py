import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import source_acquisition
from hai_mr05.discovery import CapturedSource, SourceDescriptor
from hai_mr05.failures import FailureCode


class SourceAcquisitionTests(unittest.TestCase):
    def _capture(self, root, relative_path="sample.bin", **kwargs):
        return source_acquisition.capture_source(
            approved_root=str(root), relative_path=relative_path,
            source_alias=kwargs.pop("source_alias", "fixture"),
            source_type=kwargs.pop("source_type", "LOCAL_FILE"),
            classification=kwargs.pop("classification", "INTERNAL"),
            provenance_owner=kwargs.pop("provenance_owner", "MR07B_TEST"),
            content_kind=kwargs.pop("content_kind", "BINARY"),
            observational_metadata=kwargs.pop("observational_metadata", {}), **kwargs)

    def test_successful_immutable_capture_and_exact_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); raw = b"immutable-source-bytes"; (root / "sample.bin").write_bytes(raw)
            result = self._capture(root)
            self.assertIsInstance(result.captured_source, CapturedSource)
            self.assertIsInstance(result.captured_source.descriptor, SourceDescriptor)
            self.assertEqual(result.captured_source.raw_bytes, raw)
            self.assertEqual(result.captured_source.descriptor.content_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(result.captured_source.descriptor.content_size_bytes, len(raw))
            self.assertEqual(result.captured_source.descriptor.immutability_status, "IMMUTABLE_CAPTURE")
            self.assertEqual(result.captured_source.descriptor.availability_status, "AVAILABLE")

    def test_capture_identity_is_repeatable_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / "sample.bin"; path.write_bytes(b"one")
            first = self._capture(root); second = self._capture(root)
            self.assertEqual(first.capture_identity, second.capture_identity)
            path.write_bytes(b"two-two"); changed = self._capture(root)
            self.assertNotEqual(first.capture_identity, changed.capture_identity)

    def test_root_identity_changes_with_exact_root(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            pa, pb = Path(a), Path(b); (pa / "sample.bin").write_bytes(b"same"); (pb / "sample.bin").write_bytes(b"same")
            first = self._capture(pa); second = self._capture(pb)
            self.assertNotEqual(first.approved_root_identity, second.approved_root_identity)
            self.assertNotEqual(first.capture_identity, second.capture_identity)

    def test_root_is_validated_exactly_once_per_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "sample.bin").write_bytes(b"x")
            original = source_acquisition._validated_root
            with mock.patch.object(source_acquisition, "_validated_root", wraps=original) as validated:
                self._capture(root)
            self.assertEqual(validated.call_count, 1)

    def test_approved_root_identity_does_not_revalidate_filesystem(self):
        with mock.patch.object(source_acquisition, "_validated_root", side_effect=AssertionError("must not revalidate")):
            identity = source_acquisition.approved_root_identity("/already/validated/root")
        self.assertEqual(len(identity), 64)

    def test_nonexistent_nonabsolute_and_non_directory_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); missing = root / "missing"; file_root = root / "file"; file_root.write_bytes(b"x")
            for candidate in (str(missing), "relative/root", str(file_root)):
                with self.subTest(root=candidate), self.assertRaises(source_acquisition.SourceAcquisitionError):
                    source_acquisition.capture_source(approved_root=candidate, relative_path="x", source_alias="fixture", provenance_owner="TEST")

    def test_root_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); real = base / "real"; real.mkdir(); link = base / "link"; link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(link)
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_unsafe_relative_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "safe").write_bytes(b"x")
            for value in ("../escape", "/absolute", "./safe", "a/../safe", "a//b", "a\nb"):
                with self.subTest(path=value), self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root, relative_path=value)
                self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_symlink_intermediate_and_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); outside = root / "outside"; outside.mkdir(); (outside / "data").write_bytes(b"x")
            (root / "dirlink").symlink_to(outside, target_is_directory=True); (root / "targetlink").symlink_to(outside / "data")
            for relative in ("dirlink/data", "targetlink"):
                with self.subTest(relative=relative), self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root, relative_path=relative)
                self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_descriptor_relative_anchored_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); nested = root / "a"; nested.mkdir(); (nested / "sample.bin").write_bytes(b"x")
            real_open = source_acquisition.os.open; calls = []
            def recording_open(path, flags, *args, **kwargs):
                calls.append((path, flags, kwargs.get("dir_fd")))
                return real_open(path, flags, *args, **kwargs)
            with mock.patch.object(source_acquisition.os, "open", side_effect=recording_open):
                result = self._capture(root, relative_path="a/sample.bin")
            self.assertEqual(result.captured_source.raw_bytes, b"x")
            self.assertEqual(calls[0][0], str(root)); self.assertIsNone(calls[0][2])
            self.assertEqual(calls[1][0], "a"); self.assertIsInstance(calls[1][2], int)
            self.assertEqual(calls[2][0], "sample.bin"); self.assertIsInstance(calls[2][2], int)
            if hasattr(os, "O_DIRECTORY"): self.assertTrue(calls[1][1] & os.O_DIRECTORY)
            if hasattr(os, "O_NOFOLLOW"):
                self.assertTrue(calls[1][1] & os.O_NOFOLLOW); self.assertTrue(calls[2][1] & os.O_NOFOLLOW)

    def test_intermediate_entry_substitution_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); nested = root / "a"; nested.mkdir(); (nested / "sample.bin").write_bytes(b"x")
            real_stat = source_acquisition.os.stat
            def changed_stat(path, *args, **kwargs):
                info = real_stat(path, *args, **kwargs)
                if path == "a" and kwargs.get("dir_fd") is not None:
                    values = list(info); values[1] = info.st_ino + 1; return os.stat_result(values)
                return info
            with mock.patch.object(source_acquisition.os, "stat", side_effect=changed_stat):
                with self.assertRaises(source_acquisition.SourceAcquisitionError) as raised:
                    self._capture(root, relative_path="a/sample.bin")
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_final_entry_substitution_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "sample.bin").write_bytes(b"x")
            real_stat = source_acquisition.os.stat
            def changed_stat(path, *args, **kwargs):
                info = real_stat(path, *args, **kwargs)
                if path == "sample.bin" and kwargs.get("dir_fd") is not None:
                    values = list(info); values[1] = info.st_ino + 1; return os.stat_result(values)
                return info
            with mock.patch.object(source_acquisition.os, "stat", side_effect=changed_stat):
                with self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root)
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_missing_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(Path(tmp), relative_path="missing.bin")
            self.assertEqual(raised.exception.code, FailureCode.MR05_MISSING_SOURCE.value)

    def test_directory_and_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "directory").mkdir(); os.mkfifo(root / "pipe")
            for relative in ("directory", "pipe"):
                with self.subTest(relative=relative), self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root, relative_path=relative)
                self.assertEqual(raised.exception.code, FailureCode.UNSUPPORTED_INPUT.value)

    def test_detected_source_state_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "sample.bin").write_bytes(b"stable")
            real_fstat = source_acquisition.os.fstat; regular_calls = {"count": 0}
            def changed(fd):
                info = real_fstat(fd)
                if stat_is_regular(info.st_mode):
                    regular_calls["count"] += 1
                    if regular_calls["count"] == 2:
                        values = list(info); values[6] = info.st_size + 1; return os.stat_result(values)
                return info
            with mock.patch.object(source_acquisition.os, "fstat", side_effect=changed):
                with self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root)
            self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value); self.assertFalse(raised.exception.retry_allowed)

    def test_descriptor_identity_changes_with_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "sample.bin").write_bytes(b"abc")
            first = self._capture(root, classification="INTERNAL"); second = self._capture(root, classification="PUBLIC")
            self.assertNotEqual(first.captured_source.descriptor.source_id, second.captured_source.descriptor.source_id)

    def test_invalid_metadata_fails_invalid_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "sample.bin").write_bytes(b"x")
            cases = ({"source_type":"NOPE"},{"classification":"NOPE"},{"content_kind":"NOPE"},{"source_alias":"../bad"},{"provenance_owner":""},{"observational_metadata":[]})
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(source_acquisition.SourceAcquisitionError) as raised: self._capture(root, **kwargs)
                self.assertEqual(raised.exception.code, FailureCode.INVALID_SCHEMA.value)

    def test_execution_surface_is_exact(self):
        self.assertEqual(source_acquisition.FILESYSTEM_SOURCE_READ_COUNT, 1)
        for name in ("FILESYSTEM_DEPENDENCY_EXECUTION_COUNT","SUBPROCESS_EXECUTION_COUNT","NETWORK_IMPLEMENTATION_COUNT","MODEL_CALL_IMPLEMENTATION_COUNT","PROVIDER_CLIENT_IMPLEMENTATION_COUNT","AUTH_IMPLEMENTATION_COUNT","CONTROLLER_IMPLEMENTATION_COUNT","HUMAN_GATE_EXECUTION_COUNT","EVIDENCE_PERSISTENCE_COUNT","AUTO_RETRY_IMPLEMENTATION_COUNT","AUTO_FALLBACK_IMPLEMENTATION_COUNT"):
            with self.subTest(counter=name): self.assertEqual(getattr(source_acquisition, name), 0)

    def test_source_has_no_forbidden_operational_dependencies(self):
        text = Path(source_acquisition.__file__).read_text(encoding="utf-8")
        for token in ("import subprocess","subprocess.","import socket","import requests","import httpx","import urllib","import openai","import anthropic","import boto3","os.environ","os.getenv"):
            with self.subTest(token=token): self.assertNotIn(token, text)


def stat_is_regular(mode):
    import stat
    return stat.S_ISREG(mode)


if __name__ == "__main__": unittest.main()

import contextlib
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hai_evidence.canonical import file_sha256
from hai_evidence.cli import main
from hai_evidence.errors import EvidenceError
from hai_evidence.package import build
from hai_evidence.selection import select


class RemediationBlockingTests(unittest.TestCase):
    def fixture(self, name):
        return ROOT / "tests" / "fixtures" / name

    def row(self, path, **extra):
        data = {
            "path": str(path), "relative_path": path.name, "phase_id": "SYNTHETIC",
            "artifact_type": "TEST_RESULT", "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size, "content_kind": "json",
            "current_validity": "VALID", "sensitive_class": "NON_SENSITIVE_METADATA",
            "superseded_by": "NONE", "invalidated_by": "NONE",
        }
        data.update(extra)
        return data

    def package_cli(self, source, output, task):
        task_path = pathlib.Path(tempfile.mktemp(suffix=".json"))
        task_path.write_text(json.dumps(task), encoding="utf-8")
        try:
            return main(["package", "--source", str(source), "--output", str(output), "--task", str(task_path)])
        finally:
            task_path.unlink(missing_ok=True)

    def test_MR03BR_T_F001_01_output_equals_source_blocks_before_creation(self):
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "source"; source.mkdir()
            (source / "evidence.json").write_text('{"phase":"T","current_validity":"VALID"}\n')
            before = (source / "evidence.json").read_bytes()
            self.assertNotEqual(self.package_cli(source, source, {}), 0)
            self.assertEqual((source / "evidence.json").read_bytes(), before)

    def test_MR03BR_T_F001_02_output_direct_child_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "source"; source.mkdir(); output = source / "out"
            (source / "evidence.json").write_text('{"phase":"T"}\n')
            self.assertNotEqual(self.package_cli(source, output, {}), 0)
            self.assertFalse(output.exists())

    def test_MR03BR_T_F001_03_output_deeply_nested_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "source"; source.mkdir(); output = source / "a" / "b" / "c"
            (source / "evidence.json").write_text('{"phase":"T"}\n')
            self.assertNotEqual(self.package_cli(source, output, {}), 0)
            self.assertFalse(output.exists())

    def test_MR03BR_T_F001_04_symlink_resolved_output_under_source_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td); source = base / "source"; source.mkdir(); inside = source / "inside"; inside.mkdir()
            link = base / "output-link"; link.symlink_to(inside, target_is_directory=True)
            (source / "evidence.json").write_text('{"phase":"T"}\n')
            self.assertNotEqual(self.package_cli(source, link / "new", {}), 0)
            self.assertFalse((inside / "new").exists())

    def test_MR03BR_T_F001_05_safe_sibling_output_passes(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td); source = base / "source"; source.mkdir(); output = base / "output"
            (source / "evidence.json").write_text('{"phase":"T","current_validity":"VALID"}\n')
            self.assertEqual(self.package_cli(source, output, {}), 0)
            self.assertTrue((output / "optimized_package.json").is_file())

    def test_MR03BR_T_F001_06_safe_unrelated_output_passes(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td); source = base / "source"; source.mkdir(); output = pathlib.Path(tempfile.mkdtemp()) / "output"
            (source / "evidence.json").write_text('{"phase":"T","current_validity":"VALID"}\n')
            try:
                self.assertEqual(self.package_cli(source, output, {}), 0)
                self.assertTrue((output / "optimized_package.json").is_file())
            finally:
                import shutil; shutil.rmtree(output.parent)

    def test_MR03BR_T_F002_01_protected_selection_blocks(self):
        path = self.fixture("13_protected_package.json")
        with self.assertRaises(EvidenceError) as caught:
            build([self.row(path)], {})
        self.assertEqual(caught.exception.code, "PROTECTED_CONTENT_SELECTED")

    def test_MR03BR_T_F002_02_protected_raw_value_absent(self):
        path = self.fixture("13_protected_package.json")
        try:
            build([self.row(path)], {})
        except EvidenceError as exc:
            self.assertNotIn("synthetic-only-marker", str(exc))
            return
        self.fail("protected content was not blocked")

    def test_MR03BR_T_F002_03_protected_provenance_error_has_no_raw(self):
        path = self.fixture("13_protected_package.json")
        with self.assertRaises(EvidenceError) as caught:
            build([self.row(path)], {})
        self.assertEqual(caught.exception.details.get("source"), path.name)
        self.assertNotIn("synthetic-only-marker", json.dumps(caught.exception.details))

    def test_MR03BR_T_F002_04_normal_evidence_still_packages(self):
        path = self.fixture("01_pass.json")
        payload, _ = build([self.row(path)], {})
        self.assertEqual(payload["L0_IDENTITY_HEADER"]["qualification_exposure"], 0)

    def verify(self, artifact, expected):
        inv = artifact.parent / "inventory.json"
        inv.write_text(json.dumps({"entries":[{"path":str(artifact),"sha256":expected}]}), encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["verify", str(inv)])
        return code, err.getvalue()

    def test_MR03BR_T_F003_01_correct_sha_passes(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "a.txt"; artifact.write_bytes(b"abc")
            self.assertEqual(self.verify(artifact, hashlib.sha256(b"abc").hexdigest())[0], 0)

    def test_MR03BR_T_F003_02_wrong_sha_is_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "a.txt"; artifact.write_bytes(b"abc")
            code, err = self.verify(artifact, hashlib.sha256(b"xyz").hexdigest())
            self.assertNotEqual(code, 0); self.assertIn("HASH_MISMATCH", err)

    def test_MR03BR_T_F003_03_missing_artifact_is_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "missing"
            code, err = self.verify(artifact, "0" * 64)
            self.assertNotEqual(code, 0); self.assertIn("MISSING_REQUIRED_ARTIFACT", err)

    def test_MR03BR_T_F003_04_empty_file_correct_sha_passes(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "empty"; artifact.write_bytes(b"")
            self.assertEqual(self.verify(artifact, hashlib.sha256(b"").hexdigest())[0], 0)

    def test_MR03BR_T_F003_05_binary_sha_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "binary"; artifact.write_bytes(bytes(range(256)))
            expected = hashlib.sha256(bytes(range(256))).hexdigest()
            self.assertEqual(self.verify(artifact, expected)[0], 0)
            self.assertEqual(self.verify(artifact, expected)[0], 0)

    def test_MR03BR_T_F004_01_single_valid_authority_passes(self):
        path = self.fixture("14_valid_authority.json")
        selected, _ = select([self.row(path, authority_level=1, claim_scope="synthetic", claim_value="A")], {"current_state_required": True})
        self.assertEqual(len(selected), 1)

    def test_MR03BR_T_F004_02_unknown_required_blocks(self):
        path = self.fixture("15_unknown_authority.json")
        with self.assertRaisesRegex(EvidenceError, "unknown"):
            select([self.row(path, current_validity="UNKNOWN", authority_level=1, claim_scope="synthetic", claim_value="UNKNOWN")], {"current_state_required": True})

    def test_MR03BR_T_F004_03_unknown_optional_is_preserved(self):
        path = self.fixture("15_unknown_authority.json")
        selected, _ = select([self.row(path, current_validity="UNKNOWN")], {"current_state_required": False})
        self.assertEqual(selected[0]["current_validity"], "UNKNOWN")

    def test_MR03BR_T_F004_04_same_precedence_conflict_blocks(self):
        a = self.fixture("16_conflicting_authority_a.json"); b = self.fixture("17_conflicting_authority_b.json")
        rows = [self.row(a, authority_level=1, claim_scope="synthetic", claim_value="A"), self.row(b, authority_level=1, claim_scope="synthetic", claim_value="B")]
        with self.assertRaisesRegex(EvidenceError, "conflicting"):
            select(rows, {"current_state_required": True})

    def test_MR03BR_T_F004_05_explicit_supersession_resolves(self):
        a = self.fixture("16_conflicting_authority_a.json"); b = self.fixture("17_conflicting_authority_b.json")
        rows = [self.row(a, relative_path="a.json", authority_level=1, claim_scope="synthetic", claim_value="A", superseded_by="b.json"), self.row(b, relative_path="b.json", authority_level=1, claim_scope="synthetic", claim_value="B")]
        selected, excluded = select(rows, {"current_state_required": True})
        self.assertEqual([r["relative_path"] for r in selected], ["b.json"])
        self.assertEqual(excluded[0]["reason"], "SUPERSEDED")

    def test_MR03BR_T_F004_06_scope_invalidation_preserves_unaffected_scope(self):
        a = self.fixture("14_valid_authority.json")
        rows = [self.row(a, relative_path="state.json", claim_scope="state", invalidated_by="scope-x"), self.row(a, relative_path="other.json", claim_scope="other")]
        selected, _ = select(rows, {"current_state_required": True})
        self.assertEqual({r["relative_path"] for r in selected}, {"state.json", "other.json"})


if __name__ == "__main__":
    unittest.main()

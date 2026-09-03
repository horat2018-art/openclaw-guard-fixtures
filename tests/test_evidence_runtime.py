import errno
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hai_mr05 import evidence
from hai_mr05.failures import FailureCode


class EvidenceRuntimeTests(unittest.TestCase):
    @staticmethod
    def _run():
        return evidence.build_run_record(
            repository_commit='8b540ff1f1928ba6f333c7c73899b9aee01b4d30',
            task_identity='1' * 64,
            contract_identities=('3' * 64, '2' * 64),
            dependency_identities=('5' * 64, '4' * 64),
            input_identities=('7' * 64, '6' * 64),
        )

    @classmethod
    def _manifest(cls):
        run = cls._run()
        return evidence.build_evidence_manifest(
            run_identity=run.run_identity,
            artifact_identities=('9' * 64, '8' * 64),
            provenance_identity='a' * 64,
            metrics_identity='b' * 64,
            final_result_identity='c' * 64,
            failure_identities=('e' * 64, 'd' * 64),
            operational_counters={
                'filesystem_evidence_write_count': 1,
                'network_count': 0,
                'model_call_count': 0,
            },
        )

    def test_run_identity_is_deterministic_order_normalized_and_round_trips(self):
        first = self._run()
        second = evidence.build_run_record(
            repository_commit=first.repository_commit,
            task_identity=first.task_identity,
            contract_identities=tuple(reversed(first.contract_identities)),
            dependency_identities=tuple(reversed(first.dependency_identities)),
            input_identities=tuple(reversed(first.input_identities)),
        )
        self.assertEqual(first.run_identity, second.run_identity)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(evidence.RunRecord.from_mapping(first.to_dict()).run_identity, first.run_identity)
        self.assertNotIn('message', first.identity_payload())
        self.assertNotIn('timestamp', first.identity_payload())
        self.assertNotIn('failure_identity', first.identity_payload())

    def test_manifest_identity_and_canonical_bytes_are_repeatable(self):
        first = self._manifest()
        second = evidence.EvidenceManifest.from_mapping(first.to_dict())
        self.assertEqual(first.manifest_identity, second.manifest_identity)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertTrue(first.canonical_bytes().endswith(b'\n'))
        self.assertEqual(hashlib.sha256(first.canonical_bytes()).hexdigest(), hashlib.sha256(second.canonical_bytes()).hexdigest())

    def test_exact_schema_and_identity_validation_fail_closed(self):
        run = self._run().to_dict()
        run['unexpected'] = True
        with self.assertRaises(evidence.EvidenceValidationError):
            evidence.RunRecord.from_mapping(run)
        manifest = self._manifest().to_dict()
        manifest['schema_version'] = '2.0.0'
        with self.assertRaises(evidence.EvidenceValidationError):
            evidence.EvidenceManifest.from_mapping(manifest)
        with self.assertRaises(evidence.EvidenceValidationError):
            evidence.build_run_record(
                repository_commit='bad', task_identity='1' * 64,
                contract_identities=('2' * 64,), dependency_identities=('3' * 64,),
                input_identities=('4' * 64,),
            )

    def test_persist_create_once_verifies_bytes_and_grants_no_authority(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            result = evidence.persist_evidence(
                approved_root=tmp,
                relative_path='manifest.json',
                manifest=manifest,
            )
            final = Path(tmp) / 'manifest.json'
            raw = final.read_bytes()
            self.assertEqual(raw, manifest.canonical_bytes())
            self.assertEqual(result.content_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(result.byte_count, len(raw))
            self.assertEqual(result.run_identity, manifest.run_identity)
            self.assertEqual(result.manifest_identity, manifest.manifest_identity)
            self.assertFalse(result.human_approval)
            self.assertFalse(result.controller_progress_authority)
            self.assertFalse(result.source_write_authority)
            self.assertFalse(result.git_authority)
            self.assertFalse(result.model_provider_authority)
            self.assertFalse((Path(tmp) / f'.mr08-{manifest.manifest_identity}.tmp').exists())

    def test_existing_final_destination_fails_closed_without_overwrite(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            final = Path(tmp) / 'manifest.json'
            final.write_bytes(b'preserve-me')
            with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.DUPLICATE_CONFLICT.value)
            self.assertEqual(final.read_bytes(), b'preserve-me')

    def test_relative_path_escape_and_final_symlink_fail_closed(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            for unsafe in ('../manifest.json', '/manifest.json', './manifest.json', 'a//manifest.json', 'a\\manifest.json'):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                        evidence.persist_evidence(approved_root=tmp, relative_path=unsafe, manifest=manifest)
                    self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)
            target = Path(tmp) / 'target'
            target.write_bytes(b'x')
            (Path(tmp) / 'manifest.json').symlink_to(target)
            with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_intermediate_symlink_fails_closed(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / 'real'
            real.mkdir()
            (Path(tmp) / 'linked').symlink_to(real, target_is_directory=True)
            with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                evidence.persist_evidence(approved_root=tmp, relative_path='linked/manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_root_is_validated_exactly_once_per_persistence_operation(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            original = evidence._validated_root
            with mock.patch.object(evidence, '_validated_root', wraps=original) as wrapped:
                evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(wrapped.call_count, 1)

    def test_root_symlink_substitution_fails_closed(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as outer:
            real = Path(outer) / 'real'
            real.mkdir()
            linked = Path(outer) / 'linked'
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                evidence.persist_evidence(approved_root=str(linked), relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_short_write_fails_closed_and_does_not_publish_final(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(evidence.os, 'write', return_value=len(manifest.canonical_bytes()) - 1):
                with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                    evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)
            self.assertFalse((Path(tmp) / 'manifest.json').exists())
            self.assertTrue((Path(tmp) / f'.mr08-{manifest.manifest_identity}.tmp').exists())

    def test_post_write_sha_verification_fails_closed(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(evidence.os, 'read', side_effect=[b'corrupt', b'']):
                with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                    evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)
            self.assertFalse((Path(tmp) / 'manifest.json').exists())

    def test_file_fsync_failure_fails_closed_without_publication(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(evidence.os, 'fsync', side_effect=OSError(errno.EIO, 'fsync failed')):
                with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                    evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.MR05_INTERNAL_INVARIANT.value)
            self.assertFalse((Path(tmp) / 'manifest.json').exists())

    def test_no_replace_publication_failure_does_not_fallback(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(evidence.os, 'link', side_effect=OSError(errno.EIO, 'link failed')) as linked:
                with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                    evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.MR05_INTERNAL_INVARIANT.value)
            self.assertEqual(linked.call_count, 1)
            self.assertFalse((Path(tmp) / 'manifest.json').exists())

    def test_publication_race_collision_is_duplicate_conflict(self):
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(evidence.os, 'link', side_effect=FileExistsError(errno.EEXIST, 'exists')):
                with self.assertRaises(evidence.EvidencePersistenceError) as raised:
                    evidence.persist_evidence(approved_root=tmp, relative_path='manifest.json', manifest=manifest)
            self.assertEqual(raised.exception.code, FailureCode.DUPLICATE_CONFLICT.value)

    def test_operational_counters_are_frozen_zero_outside_evidence_write(self):
        self.assertEqual(evidence.EVIDENCE_PERSISTENCE_COUNT, 1)
        self.assertEqual(evidence.FILESYSTEM_EVIDENCE_WRITE_COUNT, 1)
        for name in (
            'SUBPROCESS_EXECUTION_COUNT', 'NETWORK_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT', 'PROVIDER_CLIENT_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT', 'CONTROLLER_IMPLEMENTATION_COUNT',
            'HUMAN_GATE_EXECUTION_COUNT', 'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
        ):
            self.assertEqual(getattr(evidence, name), 0)


if __name__ == '__main__':
    unittest.main()

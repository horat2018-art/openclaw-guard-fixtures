import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from hai_mr05 import dependency_runtime, mr03_adapter, mr04_adapter
from hai_mr05.contracts import (
    MR03_CONTROLLED_WORKTREE,
    MR03_EXPECTED_COMMIT,
    MR04_CONTROLLED_WORKTREE,
    MR04_EXPECTED_COMMIT,
)
from hai_mr05.failures import FailureCode


class DependencyRuntimeTests(unittest.TestCase):
    TASK_ID = 'a' * 64
    NORMALIZATION_ID = 'b' * 64
    SOURCE_SET_ID = 'c' * 64
    CAPTURE_ID = 'd' * 64
    MR03_RESULT_ID = 'e' * 64

    @staticmethod
    def _mr03_payload():
        return {
            'L0_IDENTITY_HEADER': {
                'policy_version': 'MR03-PACKAGE-V1',
                'task_id': 'fixture-task',
                'qualification_exposure': 0,
            },
            'L1_CURRENT_STATE': {'task_class': 'FIXTURE'},
            'L2_REQUIRED_EVIDENCE': [],
            'L3_RELEVANT_HISTORICAL_DELTA': [],
            'L4_PROVENANCE_REFERENCES': [
                {
                    'sha256': 'f' * 64,
                    'source_path': '/capture/a.json',
                    'relative_path': 'a.json',
                    'phase_id': 'MR03',
                    'artifact_type': 'EVIDENCE',
                }
            ],
            'L5_EXCLUDED_EVIDENCE_INDEX': [],
            'L6_VALIDATION_REPORT': {
                'mandatory_field_retention': '100%',
                'provenance_reference_retention': '100%',
                'known_fact_regression_count': 0,
            },
        }

    @staticmethod
    def _byte_budget():
        return {
            'budget_identity': '1' * 64,
            'max_raw_bytes': 100000,
            'max_normalized_bytes': 100000,
            'max_package_bytes': 100000,
            'max_cloud_context_bytes': 100000,
        }

    @staticmethod
    def _token_metadata():
        return {
            'estimator_name': 'non_whitespace_groups_div4',
            'estimator_version': '1.0.0',
            'authority': 'ADVISORY_ONLY',
            'input_bytes': 100,
            'estimated_tokens': 25,
            'confidence': 'ADVISORY',
        }

    def test_exact_frozen_dependencies_verify_and_worktrees_are_clean(self):
        mr03_before = subprocess.check_output(
            ['git', '-C', MR03_CONTROLLED_WORKTREE, 'status', '--porcelain=v1'], text=True
        )
        mr04_before = subprocess.check_output(
            ['git', '-C', MR04_CONTROLLED_WORKTREE, 'status', '--porcelain=v1'], text=True
        )
        mr03 = dependency_runtime.verify_mr03_dependency()
        mr04 = dependency_runtime.verify_mr04_dependency()
        self.assertEqual(mr03['commit'], MR03_EXPECTED_COMMIT)
        self.assertEqual(mr04['commit'], MR04_EXPECTED_COMMIT)
        self.assertEqual(mr04['tree'], mr03_adapter.MR04_EXPECTED_TREE)
        self.assertEqual(mr04['pathset_sha256'], mr03_adapter.MR04_PATHSET_SHA256)
        self.assertEqual(mr04['contentset_sha256'], mr03_adapter.MR04_CONTENTSET_SHA256)
        self.assertTrue(mr03['checked_path_equals_execution_path'])
        self.assertTrue(mr04['checked_path_equals_executed_path'])
        self.assertEqual(
            subprocess.check_output(
                ['git', '-C', MR03_CONTROLLED_WORKTREE, 'status', '--porcelain=v1'], text=True
            ),
            mr03_before,
        )
        self.assertEqual(
            subprocess.check_output(
                ['git', '-C', MR04_CONTROLLED_WORKTREE, 'status', '--porcelain=v1'], text=True
            ),
            mr04_before,
        )

    def test_alternate_dependency_roots_are_rejected(self):
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as mr03:
            dependency_runtime.verify_mr03_dependency('/tmp/not-mr03')
        self.assertEqual(mr03.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as mr04:
            dependency_runtime.verify_mr04_dependency('/tmp/not-mr04')
        self.assertEqual(mr04.exception.code, FailureCode.SOURCE_PATH_ESCAPE.value)

    def test_mr04_commit_tree_pathset_and_contentset_mismatch_fail_closed(self):
        with mock.patch.object(dependency_runtime, '_exact_root', return_value='0' * 40):
            with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
                dependency_runtime.verify_mr04_dependency()
            self.assertEqual(
                raised.exception.code,
                FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH.value,
            )
        with mock.patch.object(
            dependency_runtime, '_exact_root', return_value=MR04_EXPECTED_COMMIT
        ), mock.patch.object(
            dependency_runtime.subprocess,
            'check_output',
            return_value='0' * 40 + '\n',
        ), mock.patch.object(
            dependency_runtime,
            '_mr04_fileset',
            return_value=(mr03_adapter.MR04_PATHSET_SHA256, mr03_adapter.MR04_CONTENTSET_SHA256),
        ):
            with self.assertRaises(dependency_runtime.DependencyRuntimeError):
                dependency_runtime.verify_mr04_dependency()
        for pathset, contentset in (
            ('0' * 64, mr03_adapter.MR04_CONTENTSET_SHA256),
            (mr03_adapter.MR04_PATHSET_SHA256, '0' * 64),
        ):
            with mock.patch.object(
                dependency_runtime, '_exact_root', return_value=MR04_EXPECTED_COMMIT
            ), mock.patch.object(
                dependency_runtime.subprocess,
                'check_output',
                return_value=mr03_adapter.MR04_EXPECTED_TREE + '\n',
            ), mock.patch.object(
                dependency_runtime, '_mr04_fileset', return_value=(pathset, contentset)
            ):
                with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
                    dependency_runtime.verify_mr04_dependency()
                self.assertEqual(
                    raised.exception.code,
                    FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH.value,
                )

    def test_mr03_invocation_identity_is_repeatable_and_mutation_sensitive(self):
        frozen = {
            'commit': MR03_EXPECTED_COMMIT,
            'root_policy': 'EXACT_FROZEN_MR03_ROOT',
            'resolve_once': True,
            'checked_path_equals_execution_path': True,
        }
        with mock.patch.object(dependency_runtime, 'verify_mr03_dependency', return_value=frozen):
            first = dependency_runtime.build_mr03_invocation(
                task_identity=self.TASK_ID,
                normalization_identity=self.NORMALIZATION_ID,
                source_set_identity=self.SOURCE_SET_ID,
                capture_identity=self.CAPTURE_ID,
            )
            second = dependency_runtime.build_mr03_invocation(
                task_identity=self.TASK_ID,
                normalization_identity=self.NORMALIZATION_ID,
                source_set_identity=self.SOURCE_SET_ID,
                capture_identity=self.CAPTURE_ID,
            )
            changed = dependency_runtime.build_mr03_invocation(
                task_identity='9' * 64,
                normalization_identity=self.NORMALIZATION_ID,
                source_set_identity=self.SOURCE_SET_ID,
                capture_identity=self.CAPTURE_ID,
            )
        self.assertEqual(first, second)
        self.assertNotEqual(first['invocation_identity'], changed['invocation_identity'])
        self.assertEqual(first['call_policy']['call_mode'], dependency_runtime.MR03_CALL_MODE)
        self.assertFalse(first['call_policy']['shell'])
        self.assertEqual(first['call_policy']['timeout_seconds'], 10)
        self.assertEqual(first['call_policy']['retry'], 'ZERO_BY_DEFAULT')
        self.assertFalse(first['call_policy']['alternate_clone'])
        self.assertFalse(first['call_policy']['latest_resolution'])

    def test_mr03_exact_seven_layer_output_and_qualification_exposure(self):
        valid = self._mr03_payload()
        self.assertEqual(dependency_runtime._validate_mr03_payload(valid), valid)
        malformed = dict(valid)
        malformed.pop('L6_VALIDATION_REPORT')
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._validate_mr03_payload(malformed)
        self.assertEqual(
            raised.exception.code,
            FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value,
        )
        exposed = self._mr03_payload()
        exposed['L0_IDENTITY_HEADER']['qualification_exposure'] = 1
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._validate_mr03_payload(exposed)
        self.assertEqual(
            raised.exception.code,
            FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value,
        )

    def test_mr03_nested_schema_rejects_missing_unknown_wrong_type_and_coercion(self):
        cases = []

        missing = self._mr03_payload()
        del missing['L0_IDENTITY_HEADER']['task_id']
        cases.append(missing)

        unknown = self._mr03_payload()
        unknown['L0_IDENTITY_HEADER']['unexpected'] = 'x'
        cases.append(unknown)

        wrong_type = self._mr03_payload()
        wrong_type['L2_REQUIRED_EVIDENCE'] = 'not-an-array'
        cases.append(wrong_type)

        wrong_report = self._mr03_payload()
        wrong_report['L6_VALIDATION_REPORT']['known_fact_regression_count'] = True
        cases.append(wrong_report)

        coercion = self._mr03_payload()
        coercion['L0_IDENTITY_HEADER']['qualification_exposure'] = '0'
        cases.append(coercion)

        bad_reference = self._mr03_payload()
        bad_reference['L4_PROVENANCE_REFERENCES'][0]['extra'] = 'forbidden'
        cases.append(bad_reference)

        bad_hash = self._mr03_payload()
        bad_hash['L4_PROVENANCE_REFERENCES'][0]['sha256'] = 'F' * 64
        cases.append(bad_hash)

        for index, payload in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(
                dependency_runtime.DependencyRuntimeError
            ) as raised:
                dependency_runtime._validate_mr03_payload(payload)
            self.assertEqual(
                raised.exception.code,
                FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value,
            )
            self.assertFalse(raised.exception.retry_allowed)

    def test_mr03_required_evidence_and_excluded_index_are_exact(self):
        evidence = self._mr03_payload()
        evidence['L2_REQUIRED_EVIDENCE'] = [
            {
                'phase_id': 'phase',
                'result': 'PASS',
                'current_validity': 'CURRENT',
                'important_hashes': ['a' * 64],
                'provenance': 'fixture',
            }
        ]
        evidence['L5_EXCLUDED_EVIDENCE_INDEX'] = [
            {'path': 'secret.txt', 'reason': 'PROTECTED'}
        ]
        self.assertEqual(dependency_runtime._validate_mr03_payload(evidence), evidence)

        bad_evidence = self._mr03_payload()
        bad_evidence['L2_REQUIRED_EVIDENCE'] = [{'phase_id': 'only-one-field'}]
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._validate_mr03_payload(bad_evidence)
        self.assertEqual(raised.exception.code, FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value)

        bad_excluded = self._mr03_payload()
        bad_excluded['L5_EXCLUDED_EVIDENCE_INDEX'] = [{'path': 'x', 'reason': ''}]
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._validate_mr03_payload(bad_excluded)
        self.assertEqual(raised.exception.code, FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value)

    def test_mr03_timeout_and_unknown_failures_map_without_retry(self):
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._map_mr03_exception(
                subprocess.TimeoutExpired(cmd=['fixture'], timeout=10)
            )
        self.assertEqual(raised.exception.code, FailureCode.MR05_MR03_CALL_TIMEOUT.value)
        self.assertFalse(raised.exception.retry_allowed)
        with self.assertRaises(dependency_runtime.DependencyRuntimeError) as raised:
            dependency_runtime._map_mr03_exception(RuntimeError('boom'))
        self.assertEqual(raised.exception.code, FailureCode.MR05_MR03_CALL_FAILURE.value)
        self.assertFalse(raised.exception.retry_allowed)

    def test_mr03_preserves_identity_path_and_security_codes(self):
        for code in (
            FailureCode.MR03_IDENTITY_MISMATCH.value,
            FailureCode.SOURCE_PATH_ESCAPE.value,
            FailureCode.PROTECTED_CONTENT_SELECTED.value,
            FailureCode.SECRET_RISK.value,
        ):
            source_error = SimpleNamespace(code=code)
            exc = RuntimeError(code)
            exc.code = source_error.code
            with self.subTest(code=code), self.assertRaises(
                dependency_runtime.DependencyRuntimeError
            ) as raised:
                dependency_runtime._map_mr03_exception(exc)
            self.assertEqual(raised.exception.code, code)
            self.assertFalse(raised.exception.retry_allowed)

    def test_invoke_mr03_calls_exact_frozen_adapter_once_and_returns_deterministic_result(self):
        payload = self._mr03_payload()
        adapter = SimpleNamespace(invoke_read_only=mock.Mock(return_value=payload))
        frozen03 = {
            'commit': MR03_EXPECTED_COMMIT,
            'root_policy': 'EXACT_FROZEN_MR03_ROOT',
            'resolve_once': True,
            'checked_path_equals_execution_path': True,
        }
        with mock.patch.object(dependency_runtime, 'verify_mr03_dependency', return_value=frozen03), mock.patch.object(
            dependency_runtime, 'verify_mr04_dependency', return_value={}
        ), mock.patch.object(
            dependency_runtime, '_load_mr04_module', return_value=adapter
        ):
            first = dependency_runtime.invoke_mr03(
                '/capture',
                {'task_id': 'fixture-task'},
                task_identity=self.TASK_ID,
                normalization_identity=self.NORMALIZATION_ID,
                source_set_identity=self.SOURCE_SET_ID,
                capture_identity=self.CAPTURE_ID,
            )
            second = dependency_runtime.invoke_mr03(
                '/capture',
                {'task_id': 'fixture-task'},
                task_identity=self.TASK_ID,
                normalization_identity=self.NORMALIZATION_ID,
                source_set_identity=self.SOURCE_SET_ID,
                capture_identity=self.CAPTURE_ID,
            )
        self.assertEqual(adapter.invoke_read_only.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(first['mr03_failure_status']['status'], 'PASS')
        self.assertEqual(first['mr03_provenance']['qualification_exposure'], 0)
        self.assertNotIn('invocation', first)

    def test_mr04_invocation_identity_is_repeatable_and_mutation_sensitive(self):
        frozen = {
            'commit': MR04_EXPECTED_COMMIT,
            'tree': mr03_adapter.MR04_EXPECTED_TREE,
            'pathset_sha256': mr03_adapter.MR04_PATHSET_SHA256,
            'contentset_sha256': mr03_adapter.MR04_CONTENTSET_SHA256,
            'resolve_once': True,
            'checked_path_equals_executed_path': True,
        }
        with mock.patch.object(dependency_runtime, 'verify_mr04_dependency', return_value=frozen):
            first = dependency_runtime.build_mr04_invocation(
                task_identity=self.TASK_ID,
                source_set_identity=self.SOURCE_SET_ID,
                normalization_identity=self.NORMALIZATION_ID,
                mr03_result_identity=self.MR03_RESULT_ID,
                byte_budget=self._byte_budget(),
                token_estimate_metadata=self._token_metadata(),
            )
            second = dependency_runtime.build_mr04_invocation(
                task_identity=self.TASK_ID,
                source_set_identity=self.SOURCE_SET_ID,
                normalization_identity=self.NORMALIZATION_ID,
                mr03_result_identity=self.MR03_RESULT_ID,
                byte_budget=self._byte_budget(),
                token_estimate_metadata=self._token_metadata(),
            )
            changed_budget = self._byte_budget()
            changed_budget['max_package_bytes'] += 1
            changed = dependency_runtime.build_mr04_invocation(
                task_identity=self.TASK_ID,
                source_set_identity=self.SOURCE_SET_ID,
                normalization_identity=self.NORMALIZATION_ID,
                mr03_result_identity=self.MR03_RESULT_ID,
                byte_budget=changed_budget,
                token_estimate_metadata=self._token_metadata(),
            )
        self.assertEqual(first, second)
        self.assertNotEqual(first['invocation_identity'], changed['invocation_identity'])
        self.assertEqual(first['call_mode'], 'FROZEN_MR04_LOWER_LEVEL_COMPOSITION')

    def test_mr04_byte_budget_rejects_missing_unknown_wrong_type_and_nonpositive(self):
        frozen = {
            'commit': MR04_EXPECTED_COMMIT,
            'tree': mr03_adapter.MR04_EXPECTED_TREE,
            'pathset_sha256': mr03_adapter.MR04_PATHSET_SHA256,
            'contentset_sha256': mr03_adapter.MR04_CONTENTSET_SHA256,
            'resolve_once': True,
            'checked_path_equals_executed_path': True,
        }
        budgets = []
        missing = self._byte_budget()
        del missing['max_cloud_context_bytes']
        budgets.append(missing)
        unknown = self._byte_budget()
        unknown['extra'] = 1
        budgets.append(unknown)
        wrong_type = self._byte_budget()
        wrong_type['max_raw_bytes'] = '100000'
        budgets.append(wrong_type)
        boolean_coercion = self._byte_budget()
        boolean_coercion['max_raw_bytes'] = True
        budgets.append(boolean_coercion)
        zero = self._byte_budget()
        zero['max_package_bytes'] = 0
        budgets.append(zero)
        bad_identity = self._byte_budget()
        bad_identity['budget_identity'] = 'A' * 64
        budgets.append(bad_identity)

        with mock.patch.object(dependency_runtime, 'verify_mr04_dependency', return_value=frozen):
            for index, budget in enumerate(budgets):
                with self.subTest(case=index), self.assertRaises(
                    dependency_runtime.DependencyRuntimeError
                ) as raised:
                    dependency_runtime.build_mr04_invocation(
                        task_identity=self.TASK_ID,
                        source_set_identity=self.SOURCE_SET_ID,
                        normalization_identity=self.NORMALIZATION_ID,
                        mr03_result_identity=self.MR03_RESULT_ID,
                        byte_budget=budget,
                        token_estimate_metadata=self._token_metadata(),
                    )
                self.assertEqual(raised.exception.code, FailureCode.INVALID_SCHEMA.value)
                self.assertFalse(raised.exception.retry_allowed)

    def test_mr04_token_metadata_rejects_missing_unknown_types_enums_and_coercion(self):
        frozen = {
            'commit': MR04_EXPECTED_COMMIT,
            'tree': mr03_adapter.MR04_EXPECTED_TREE,
            'pathset_sha256': mr03_adapter.MR04_PATHSET_SHA256,
            'contentset_sha256': mr03_adapter.MR04_CONTENTSET_SHA256,
            'resolve_once': True,
            'checked_path_equals_executed_path': True,
        }
        cases = []
        missing = self._token_metadata()
        del missing['confidence']
        cases.append(missing)
        unknown = self._token_metadata()
        unknown['extra'] = 'x'
        cases.append(unknown)
        wrong_type = self._token_metadata()
        wrong_type['input_bytes'] = '100'
        cases.append(wrong_type)
        boolean_coercion = self._token_metadata()
        boolean_coercion['estimated_tokens'] = False
        cases.append(boolean_coercion)
        bad_name = self._token_metadata()
        bad_name['estimator_name'] = 'other'
        cases.append(bad_name)
        bad_version = self._token_metadata()
        bad_version['estimator_version'] = '2.0.0'
        cases.append(bad_version)
        bad_authority = self._token_metadata()
        bad_authority['authority'] = 'AUTHORITATIVE'
        cases.append(bad_authority)
        bad_confidence = self._token_metadata()
        bad_confidence['confidence'] = 'HIGH'
        cases.append(bad_confidence)
        negative = self._token_metadata()
        negative['input_bytes'] = -1
        cases.append(negative)

        with mock.patch.object(dependency_runtime, 'verify_mr04_dependency', return_value=frozen):
            for index, metadata in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(
                    dependency_runtime.DependencyRuntimeError
                ) as raised:
                    dependency_runtime.build_mr04_invocation(
                        task_identity=self.TASK_ID,
                        source_set_identity=self.SOURCE_SET_ID,
                        normalization_identity=self.NORMALIZATION_ID,
                        mr03_result_identity=self.MR03_RESULT_ID,
                        byte_budget=self._byte_budget(),
                        token_estimate_metadata=metadata,
                    )
                self.assertEqual(raised.exception.code, FailureCode.INVALID_SCHEMA.value)
                self.assertFalse(raised.exception.retry_allowed)

    def test_invoke_mr04_uses_only_qualified_lower_level_callables(self):
        payload = self._mr03_payload()
        package_identity = '2' * 64
        package_sha = '3' * 64
        package = {
            'schema_version': 'bounded-context-package-v2',
            'package_schema_version': 'bounded-context-package-v2',
            'package_identity': package_identity,
            'package_sha256': package_sha,
            'L0_IDENTITY_HEADER': {},
            'L1_CURRENT_STATE': {},
            'L2_REQUIRED_EVIDENCE': {},
            'L3_RELEVANT_HISTORICAL_DELTA': {},
            'L4_PROVENANCE_REFERENCES': [],
            'L5_EXCLUDED_EVIDENCE_INDEX': [],
            'L6_VALIDATION_REPORT': {},
            'source_reference_set': [],
            'security_status': 'SAFE_METADATA_ONLY',
            'protected_content_status': 'RAW_EXCLUDED',
            'token_budget': {'RAW_INPUT_BYTES': 1},
            'mr03_adapter_output': payload,
            'escalation_signals': [],
        }
        discovery_module = SimpleNamespace(discover=mock.Mock(return_value={'artifacts': []}))
        normalization_module = SimpleNamespace(normalize=mock.Mock(return_value=[]))
        provenance_module = SimpleNamespace(validate=mock.Mock(return_value='100%'))
        context_module = SimpleNamespace(
            build=mock.Mock(return_value=package),
            package_identity_from_semantics=mock.Mock(return_value=package_identity),
            package_sha256_from_content=mock.Mock(return_value=package_sha),
        )
        modules = {
            'hai_mr04.discovery': discovery_module,
            'hai_mr04.normalization': normalization_module,
            'hai_mr04.provenance': provenance_module,
            'hai_mr04.bounded_context': context_module,
        }
        mr03_result = {'result_identity': self.MR03_RESULT_ID, 'mr03_payload': payload}
        with mock.patch.object(dependency_runtime, 'verify_mr04_dependency', return_value={}), mock.patch.object(
            dependency_runtime,
            '_load_mr04_module',
            side_effect=lambda name: modules[name],
        ):
            first = dependency_runtime.invoke_mr04(
                '/capture',
                {'task_id': 'fixture'},
                mr03_result,
                task_identity=self.TASK_ID,
                source_set_identity=self.SOURCE_SET_ID,
                normalization_identity=self.NORMALIZATION_ID,
                byte_budget=self._byte_budget(),
                token_estimate_metadata=self._token_metadata(),
            )
            second = dependency_runtime.invoke_mr04(
                '/capture',
                {'task_id': 'fixture'},
                mr03_result,
                task_identity=self.TASK_ID,
                source_set_identity=self.SOURCE_SET_ID,
                normalization_identity=self.NORMALIZATION_ID,
                byte_budget=self._byte_budget(),
                token_estimate_metadata=self._token_metadata(),
            )
        self.assertEqual(first, second)
        self.assertEqual(discovery_module.discover.call_count, 2)
        self.assertEqual(normalization_module.normalize.call_count, 2)
        self.assertEqual(provenance_module.validate.call_count, 2)
        self.assertEqual(context_module.build.call_count, 2)
        self.assertEqual(first['package_identity'], package_identity)
        self.assertEqual(first['package_sha256'], package_sha)
        self.assertEqual(first['verification_fields']['decision'], 'ESCALATE')
        self.assertFalse(first['verification_fields']['approval'])
        self.assertFalse(first['human_gate_fields']['authority_granted'])
        self.assertNotIn('invocation', first)

    def test_operational_surface_is_exact_and_has_no_retry_fallback_model_network_or_auth(self):
        self.assertEqual(dependency_runtime.MR03_EXECUTION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(dependency_runtime.MR04_EXECUTION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(dependency_runtime.SUBPROCESS_EXECUTION_COUNT, 1)
        self.assertEqual(dependency_runtime.FILESYSTEM_DEPENDENCY_EXECUTION_COUNT, 1)
        for name in (
            'NETWORK_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT',
            'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
            'PROVIDER_CLIENT_IMPLEMENTATION_COUNT',
            'CONTROLLER_IMPLEMENTATION_COUNT',
            'HUMAN_GATE_EXECUTION_COUNT',
            'EVIDENCE_PERSISTENCE_COUNT',
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(dependency_runtime, name), 0)
        for module in (mr03_adapter, mr04_adapter):
            self.assertEqual(module.MR03_EXECUTION_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.MR04_EXECUTION_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.SUBPROCESS_EXECUTION_COUNT, 0)
            self.assertEqual(module.NETWORK_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.MODEL_CALL_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.AUTH_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.AUTO_RETRY_IMPLEMENTATION_COUNT, 0)
            self.assertEqual(module.AUTO_FALLBACK_IMPLEMENTATION_COUNT, 0)


if __name__ == '__main__':
    unittest.main()

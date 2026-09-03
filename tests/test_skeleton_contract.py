import importlib
import inspect
import unittest

from hai_mr05 import canonical, context_builder, contracts, controller, discovery, failures, identity, metrics, mr03_adapter, mr04_adapter, normalization, provenance, verifier
from hai_mr05.failures import Failure, FailureCode, FailureOwner, FailureSeverity, FailureState
from hai_mr05.metrics import Metrics
from hai_mr05.provenance import ProvenanceChain, ProvenanceEdge, ProvenanceNode, RelationType

MODULE_NAMES = ('controller', 'contracts', 'canonical', 'identity', 'discovery', 'normalization', 'mr03_adapter', 'mr04_adapter', 'context_builder', 'disclosure', 'cloud_boundary', 'proposal', 'verifier', 'human_gate', 'provenance', 'metrics', 'failures', 'evidence', 'cli')


class SkeletonContractTests(unittest.TestCase):
    def test_all_frozen_package_modules_import(self):
        for name in MODULE_NAMES:
            with self.subTest(name=name):
                self.assertIsNotNone(importlib.import_module(f"hai_mr05.{name}"))

    def test_frozen_references_are_exact(self):
        self.assertEqual(contracts.MR05A_CONTRACT_SHA256, '99a52798cafc038bf3c9db20eacc7f5fa3cadc16468afdb39697d9c9b7d06811')
        self.assertEqual(contracts.MR05B_MASTER_CONTRACT_SHA256, '20462c72898252b9a31670c08a7c253e9a1a65d42363bc25151a2bebbff7c6bd')
        self.assertEqual(contracts.MR05B_CONTRACT_SET_SHA256, 'a78c2574bc15692e1e8e56b4ff1a91b19b11a4b0e4fc808db3577a158ef45cc9')
        self.assertEqual(contracts.MR03_EXPECTED_COMMIT, '945559bf0f1811cb2f88e827ff1412081f1fbd75')
        self.assertEqual(contracts.MR04_EXPECTED_COMMIT, '8ce9eb8a542799e00088a6654e1061405fde7d33')
        self.assertEqual(contracts.MR05C_R2_CONTRACT_SHA256, 'c7e561000b43677b65ffe8ce46ba44d679de9c75c1febe2471114bccd7072cf9')
        self.assertEqual(contracts.MR05D_R2_CONTRACT_SHA256, '44fac0d7abe60487202b7937ebe1055a347c1ab30dd0ef90e0e4fcccd1826000')
        self.assertEqual(contracts.MR05_PACKAGE_NAME, 'hai_mr05')
        self.assertEqual(contracts.SCHEMA_VERSIONS['mr05.verification'], '1.0.0')

    def test_callable_placeholders_fail_closed(self):
        for name in MODULE_NAMES:
            module = importlib.import_module(f"hai_mr05.{name}")
            if name in {'contracts', 'identity', 'failures', 'discovery', 'normalization', 'verifier', 'evidence', 'controller'}:
                continue
            if name == 'cli':
                callable_placeholder = module.main
            else:
                callable_placeholder = module.not_implemented
            with self.subTest(name=name), self.assertRaises(failures.MR05PhaseNotImplementedError):
                callable_placeholder()

    def test_canonical_json_is_compact_sorted_and_repeatable(self):
        first = {
            'z': {'β': 2, 'a': '✓'},
            'a': [3, {'b': True, 'a': None}],
        }
        second = {
            'a': [3, {'a': None, 'b': True}],
            'z': {'a': '✓', 'β': 2},
        }
        expected = '{"a":[3,{"a":null,"b":true}],"z":{"a":"✓","β":2}}\n'.encode('utf-8')
        self.assertEqual(canonical.canonical_json_bytes(first), expected)
        self.assertEqual(canonical.canonical_json_bytes(first), canonical.canonical_json_bytes(second))
        self.assertEqual(canonical.canonical_json_text(first), expected.decode('utf-8'))
        self.assertEqual(canonical.canonical_pathset_bytes(['tests/b.py', 'src/a.py']), b'src/a.py\ntests/b.py\n')

    def test_canonical_rejects_duplicate_keys_surrogates_and_identity_floats(self):
        with self.assertRaises(canonical.DuplicateJSONKeyError):
            canonical.parse_json_no_duplicates('{"a":1,"a":2}')
        with self.assertRaises(canonical.UnsupportedIdentityValueError):
            canonical.canonical_json_bytes({'value': 1.5})
        self.assertEqual(canonical.canonical_json_bytes({'value': 1.5}, identity_critical=False), b'{"value":1.5}\n')
        with self.assertRaises(canonical.CanonicalizationError):
            canonical.canonical_json_bytes({'value': '\ud800'})
        with self.assertRaises(canonical.CanonicalizationError):
            canonical.canonical_pathset_bytes(['src/a.py', 'src/a.py'])

    def test_identity_hashes_and_invalid_formats_fail_closed(self):
        self.assertEqual(identity.sha256_bytes(b'abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(identity.sha256_canonical({'a': 1}), 'e346432021b04179518d9614f3560ccd71354a4ee101ddcb893d6959a9d6301c')
        one = identity.identity_from_fields({'value': 'stable'})
        self.assertEqual(one, identity.identity_from_fields({'value': 'stable'}))
        self.assertNotEqual(one, identity.identity_from_fields({'value': 'changed'}))
        self.assertEqual(identity.require_sha256('a' * 64), 'a' * 64)
        self.assertEqual(identity.require_git_commit('b' * 40), 'b' * 40)
        for invalid in ('A' * 64, 'a' * 63, 'not-a-hash', None):
            with self.subTest(value=invalid), self.assertRaises(identity.IdentityValidationError):
                identity.require_sha256(invalid)
        with self.assertRaises(identity.IdentityValidationError):
            identity.require_git_commit('a' * 64)
        self.assertEqual(
            identity.schema_bound_identity('mr05.metrics', {'raw_source_bytes': 1}),
            identity.schema_bound_identity('mr05.metrics', {'raw_source_bytes': 1}),
        )
        with self.assertRaises(identity.IdentityValidationError):
            identity.schema_bound_identity('mr05.metrics', {'schema_version': '2.0.0'})

    def test_failure_codes_are_unique_and_envelopes_are_immutable(self):
        values = [code.value for code in FailureCode]
        self.assertEqual(len(values), len(set(values)))
        self.assertEqual(failures.failure_code_for_semantic('MISSING_PROVENANCE'), FailureCode.PROVENANCE_GAP)
        self.assertEqual(failures.failure_code_for_semantic('MODEL_TIMEOUT'), FailureCode.MR05_MODEL_TIMEOUT)
        self.assertEqual(failures.failure_owner_for(FailureCode.MR05_MODEL_TIMEOUT), FailureOwner.MODEL_BOUNDARY)
        envelope = Failure(
            schema_version='1.0.0',
            failure_code=FailureCode.MR05_MODEL_TIMEOUT,
            failure_owner=FailureOwner.MODEL_BOUNDARY,
            severity=FailureSeverity.HIGH,
            state=FailureState.FAILED,
            run_identity='a' * 64,
            related_identity=None,
            message='provider timeout',
            human_escalation_required=True,
        )
        self.assertEqual(envelope.retry_allowed, False)
        self.assertEqual(len(envelope.failure_identity), 64)
        self.assertEqual(Failure.from_mapping(envelope.to_dict()).failure_identity, envelope.failure_identity)
        complete_mapping = envelope.to_dict()
        missing_identity = dict(complete_mapping)
        del missing_identity['failure_identity']
        with self.assertRaises(failures.FailureValidationError):
            Failure.from_mapping(missing_identity)
        malformed_identity = dict(complete_mapping)
        malformed_identity['failure_identity'] = 'A' * 64
        with self.assertRaises(failures.FailureValidationError):
            Failure.from_mapping(malformed_identity)
        empty_details = dict(complete_mapping)
        empty_details['safe_details'] = {}
        self.assertEqual(Failure.from_mapping(empty_details).failure_identity, envelope.failure_identity)
        unknown_details = dict(complete_mapping)
        unknown_details['safe_details'] = {'unexpected': 'value'}
        with self.assertRaises(failures.FailureValidationError):
            Failure.from_mapping(unknown_details)
        multiple_unknown_details = dict(complete_mapping)
        multiple_unknown_details['safe_details'] = {'first': 1, 'second': 2}
        with self.assertRaises(failures.FailureValidationError):
            Failure.from_mapping(multiple_unknown_details)
        changed_message = Failure(
            schema_version='1.0.0', failure_code=FailureCode.MR05_MODEL_TIMEOUT,
            failure_owner=FailureOwner.MODEL_BOUNDARY, severity=FailureSeverity.HIGH,
            state=FailureState.FAILED, run_identity='a' * 64, related_identity=None,
            message='same identity, different observation', human_escalation_required=True,
        )
        self.assertEqual(envelope.failure_identity, changed_message.failure_identity)
        with self.assertRaises(failures.FailureValidationError):
            Failure(
                schema_version='1.0.0', failure_code=FailureCode.MR05_MODEL_TIMEOUT,
                failure_owner=FailureOwner.VERIFICATION, severity=FailureSeverity.HIGH,
                state=FailureState.FAILED, run_identity='a' * 64, related_identity=None,
                message='wrong owner',
            )
        with self.assertRaises(failures.FailureValidationError):
            Failure(
                schema_version='1.0.0', failure_code=FailureCode.MR05_MODEL_TIMEOUT,
                failure_owner=FailureOwner.MODEL_BOUNDARY, severity=FailureSeverity.HIGH,
                state=FailureState.FAILED, run_identity='short', related_identity=None,
                message='invalid identity',
            )

    def test_provenance_preserves_nodes_sorts_edges_and_is_repeatable(self):
        node_a = ProvenanceNode('SOURCE_IDENTITY', 'a' * 64, 'source/a')
        node_b = ProvenanceNode('TASK_IDENTITY', 'b' * 64, 'task/b')
        edge_ab = ProvenanceEdge('a' * 64, 'b' * 64, RelationType.DERIVED_FROM)
        edge_ba = ProvenanceEdge('b' * 64, 'a' * 64, RelationType.BINDS)
        first = ProvenanceChain(nodes=(node_b, node_a), edges=(edge_ba, edge_ab))
        repeated = ProvenanceChain(nodes=(node_b, node_a), edges=(edge_ab, edge_ba))
        alternate_nodes = ProvenanceChain(nodes=(node_a, node_b), edges=(edge_ab, edge_ba))
        self.assertEqual(first.nodes, (node_b, node_a))
        self.assertEqual(first.edges, repeated.edges)
        self.assertEqual(first.canonical_bytes(), repeated.canonical_bytes())
        self.assertEqual(first.provenance_identity, repeated.provenance_identity)
        self.assertNotEqual(first.provenance_identity, alternate_nodes.provenance_identity)
        self.assertEqual(ProvenanceChain.from_mapping(first.to_dict()).provenance_identity, first.provenance_identity)
        self.assertEqual(ProvenanceChain.from_mapping(first.to_dict()).nodes, first.nodes)
        self.assertEqual(first.to_dict()['coverage_percent'], 100)
        with self.assertRaises(provenance.ProvenanceValidationError):
            ProvenanceNode('EMPTY', '', 'artifact')
        with self.assertRaises(provenance.ProvenanceValidationError):
            ProvenanceChain(nodes=(), edges=())
        with self.assertRaises(provenance.ProvenanceValidationError):
            ProvenanceChain.from_mapping({'schema_version': '1.0.0', 'nodes': [], 'edges': [], 'coverage_percent': 100})
        with self.assertRaises(provenance.ProvenanceValidationError):
            ProvenanceEdge('a' * 64, 'b' * 64, 'UNKNOWN')

    def test_metrics_formula_zero_edge_and_advisory_token_policy(self):
        result = Metrics(
            raw_source_bytes=100,
            normalized_bytes=80,
            package_bytes=70,
            cloud_context_bytes=25,
            raw_estimated_tokens=20,
            cloud_estimated_tokens=5,
        )
        self.assertEqual(result.byte_reduction_percent, 75.0)
        self.assertEqual(result.estimated_token_reduction_percent, 75.0)
        self.assertEqual(result.metrics_identity, Metrics.from_mapping(result.to_dict()).metrics_identity)
        payload = result.identity_payload()
        expected_preimage_fields = {
            'schema_version', 'raw_source_bytes', 'normalized_bytes', 'package_bytes',
            'cloud_context_bytes', 'metric_formula_version', 'raw_estimated_tokens',
            'cloud_estimated_tokens', 'model_call_count', 'model_retry_count',
            'failure_count', 'source_ref_count', 'missing_source_ref_count',
            'identity_mismatch_count',
        }
        self.assertEqual(set(payload), expected_preimage_fields)
        self.assertNotIn('byte_reduction_percent', payload)
        self.assertNotIn('estimated_token_reduction_percent', payload)
        self.assertEqual(payload['metric_formula_version'], 'MR05-METRICS-FORMULAS-1.0.0')
        self.assertEqual(metrics.BYTE_REDUCTION_FORMULA_VERSION, 'MR05-BYTE-REDUCTION-1.0.0')
        self.assertEqual(metrics.TOKEN_REDUCTION_FORMULA_VERSION, 'MR05-TOKEN-REDUCTION-1.0.0')
        self.assertNotEqual(
            result.metrics_identity,
            identity.sha256_canonical({**payload, 'metric_formula_version': 'MR05-METRICS-FORMULAS-9.9.9'}),
        )
        self.assertNotEqual(
            result.metrics_identity,
            Metrics(raw_source_bytes=101, normalized_bytes=80, package_bytes=70, cloud_context_bytes=25,
                    raw_estimated_tokens=20, cloud_estimated_tokens=5).metrics_identity,
        )
        self.assertNotEqual(
            result.metrics_identity,
            Metrics(raw_source_bytes=100, normalized_bytes=80, package_bytes=70, cloud_context_bytes=26,
                    raw_estimated_tokens=20, cloud_estimated_tokens=5).metrics_identity,
        )
        self.assertNotEqual(
            result.metrics_identity,
            Metrics(raw_source_bytes=100, normalized_bytes=81, package_bytes=70, cloud_context_bytes=25,
                    raw_estimated_tokens=20, cloud_estimated_tokens=5).metrics_identity,
        )
        self.assertNotEqual(
            result.metrics_identity,
            Metrics(raw_source_bytes=100, normalized_bytes=80, package_bytes=71, cloud_context_bytes=25,
                    raw_estimated_tokens=20, cloud_estimated_tokens=5).metrics_identity,
        )
        self.assertNotEqual(
            result.metrics_identity,
            Metrics(raw_source_bytes=100, normalized_bytes=80, package_bytes=70, cloud_context_bytes=25,
                    raw_estimated_tokens=20, cloud_estimated_tokens=5, model_call_count=1).metrics_identity,
        )
        self.assertEqual(metrics.byte_reduction_percent(100, 25), 75.0)
        self.assertEqual(metrics.token_reduction_percent(20, 5), 75.0)
        zero = Metrics(raw_source_bytes=0, cloud_context_bytes=13)
        self.assertEqual(zero.byte_reduction_percent, 0.0)
        self.assertEqual(zero.zero_denominator, True)
        self.assertEqual(zero.identity_payload()['metric_formula_version'], 'MR05-METRICS-FORMULAS-1.0.0')
        self.assertEqual(metrics.TOKEN_ESTIMATE_AUTHORITY, 'ADVISORY_ONLY')
        with self.assertRaises(metrics.MetricsValidationError):
            Metrics(raw_source_bytes=-1)
        with self.assertRaises(metrics.MetricsValidationError):
            Metrics(raw_source_bytes=10, cloud_context_bytes=5, model_retry_count=1)
        with self.assertRaises(metrics.MetricsValidationError):
            Metrics(raw_source_bytes=10, cloud_context_bytes=5, byte_reduction_percent=49.0)
        with self.assertRaises(metrics.MetricsValidationError):
            Metrics(raw_source_bytes=10, cloud_context_bytes=5, byte_reduction_percent=float('nan'))
        with self.assertRaises(metrics.MetricsValidationError):
            Metrics(raw_source_bytes=10, cloud_context_bytes=5, byte_reduction_percent=float('inf'))
        presentation_equivalent = result.to_dict()
        presentation_equivalent['byte_reduction_percent'] = 75
        presentation_equivalent['estimated_token_reduction_percent'] = 75
        self.assertEqual(Metrics.from_mapping(presentation_equivalent).metrics_identity, result.metrics_identity)

    @staticmethod
    def _task():
        return {
            'schema_version': '1.0.0',
            'task_id': 'mr05g-test-task',
            'task_type': 'EVIDENCE_REVIEW',
            'task_text': 'Review supplied deterministic evidence.',
            'requested_output_type': 'EVIDENCE_REVIEW',
            'allowed_scope': ['inspect supplied data'],
            'prohibited_scope': ['execute external actions'],
            'human_constraints': {
                'approval_required': True,
                'no_execution': True,
                'no_external_side_effects': True,
                'trust_level': 'LEVEL 0',
                'live_cloud_allowed': False,
                'local_model_source_authority': False,
            },
            'source_scope': {
                'approved_source_aliases': ['fixture'],
                'allowed_source_types': ['LOCAL_FILE'],
            },
            'risk_class_if_known': 'UNKNOWN',
        }

    @staticmethod
    def _descriptor(path, raw):
        payload = {
            'schema_version': '1.0.0',
            'source_type': 'LOCAL_FILE',
            'canonical_locator': {'source_alias': 'fixture', 'relative_path': path},
            'content_identity': {'algorithm': 'SHA-256', 'sha256': identity.sha256_bytes(raw)},
            'content_size_bytes': len(raw),
            'classification': 'PUBLIC',
            'immutability_status': 'IMMUTABLE_CAPTURE',
            'availability_status': 'AVAILABLE',
            'provenance_owner': 'test-fixture',
        }
        return {**payload, 'source_id': discovery.source_descriptor_identity(payload)}

    def test_discovery_is_deterministic_and_sorted(self):
        first_source = self._descriptor('b.json', b'{"b":2}')
        second_source = self._descriptor('a.json', b'{"a":1}')
        task = self._task()
        first = discovery.discover(task, [first_source, second_source], max_item_count=2, max_bytes=100)
        second = discovery.discover(task, [second_source, first_source], max_item_count=2, max_bytes=100)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.model_call_count, 0)
        self.assertEqual(
            [item.source_id for item in first.selected_sources],
            sorted(item.source_id for item in first.selected_sources),
        )
        self.assertEqual(discovery.DiscoveryResult.from_mapping(first.to_dict()).discovery_identity, first.discovery_identity)

    def test_discovery_rejects_invalid_values_and_unsafe_references(self):
        source = self._descriptor('safe.json', b'{}')
        task = self._task()
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.discover(task, [source], max_item_count=True, max_bytes=10)
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.discover(task, [source], max_item_count=1, max_bytes=10.0)
        malformed = dict(source)
        malformed['unexpected'] = 'must reject'
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.discover(task, [malformed], max_item_count=1, max_bytes=10)
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.validate_relative_path('../escape')
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.validate_canonical_locator('/fixture/safe.json')
        with self.assertRaises(discovery.DiscoveryValidationError):
            discovery.discover(task, [source])

    def test_normalization_is_deterministic_and_preserves_binding(self):
        source_a = self._descriptor('a.json', b'{"a":1}')
        source_b = self._descriptor('b.json', b'{"b":2}')
        task = self._task()
        discovered = discovery.discover(task, [source_b, source_a], max_item_count=2, max_bytes=100)
        rows = [
            normalization.NormalizedItem.from_source(
                discovered.selected_sources[0],
                phase_id='MR05G',
                artifact_type='EVIDENCE',
                current_validity='VALID',
                supersession='NONE',
                classification='PUBLIC',
                mandatory=True,
            ).to_dict(),
            normalization.NormalizedItem.from_source(
                discovered.selected_sources[1],
                phase_id='MR05G',
                artifact_type='EVIDENCE',
                current_validity='UNKNOWN',
                supersession='NONE',
                classification='PUBLIC',
                mandatory=False,
            ).to_dict(),
        ]
        first = normalization.normalize(discovered, list(reversed(rows)))
        second = normalization.normalize(discovered, rows)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.input_bytes, discovered.total_selected_bytes)
        self.assertEqual(
            first.output_bytes,
            len(canonical.canonical_json_bytes([row.to_dict() for row in first.normalized_items])),
        )
        self.assertEqual(
            normalization.NormalizationResult.from_mapping(first.to_dict()).normalization_identity,
            first.normalization_identity,
        )

    def test_normalization_rejects_provenance_gaps_and_coercion(self):
        source = self._descriptor('a.json', b'{}')
        discovered = discovery.discover(self._task(), [source], max_item_count=1, max_bytes=10)
        row = normalization.NormalizedItem.from_source(
            discovered.selected_sources[0],
            phase_id='MR05G',
            artifact_type='EVIDENCE',
            current_validity='VALID',
            supersession='NONE',
            classification='PUBLIC',
            mandatory=True,
        ).to_dict()
        wrong_provenance = dict(row)
        wrong_provenance['provenance'] = dict(row['provenance'])
        wrong_provenance['provenance']['source_id'] = 'a' * 64
        with self.assertRaises(normalization.NormalizationValidationError):
            normalization.normalize(discovered, [wrong_provenance])
        coerced = dict(row)
        coerced['mandatory'] = 1
        with self.assertRaises(normalization.NormalizationValidationError):
            normalization.normalize(discovered, [coerced])
        unknown_field = dict(row)
        unknown_field['content'] = '{}'
        with self.assertRaises(normalization.NormalizationValidationError):
            normalization.normalize(discovered, [unknown_field])
        invalid_relation = dict(row)
        invalid_relation['current_validity'] = 'SUPERSEDED'
        with self.assertRaises(normalization.NormalizationValidationError):
            normalization.normalize(discovered, [invalid_relation])

    def test_discovery_and_normalization_have_no_execution_surface(self):
        for module in (discovery, normalization):
            source = inspect.getsource(module)
            for forbidden in ('import socket', 'import subprocess', 'import requests', 'import httpx', 'import urllib', 'import openai', 'import anthropic', 'import boto3', 'open(', 'os.environ', 'os.getenv'):
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)
        self.assertEqual(discovery.MODEL_CALL_COUNT, 0)

    def _binding_context(self):
        source = self._descriptor('binding.json', b'{"binding":1}')
        discovered = discovery.discover(self._task(), [source], max_item_count=1, max_bytes=100)
        row = normalization.NormalizedItem.from_source(
            discovered.selected_sources[0],
            phase_id='MR05G',
            artifact_type='EVIDENCE',
            current_validity='VALID',
            supersession='NONE',
            classification='PUBLIC',
            mandatory=True,
        )
        normalized = normalization.normalize(discovered, [row])
        source_ref = {
            'schema_version': '1.0.0',
            **discovered.selected_sources[0].to_dict(),
        }
        return discovered, normalized, source_ref

    @staticmethod
    def _dependency_record(discovered, normalized, source_ref, role, upstream=None):
        if role == 'MR03_PACKAGER':
            dependency = {
                'dependency_role': 'MR03_PACKAGER',
                'dependency_logical_id': 'MR03',
                'expected_dependency_class': 'FROZEN_MR03_EVIDENCE_PACKAGER',
                'dependency_contract_identity': None,
                'dependency_version_identity': 'MR03-PACKAGE-V1',
                'dependency_content_identity': {
                    'kind': 'COMMITTED_FILESET',
                    'sha256': '3e85d8eebc1eef05a5ee6e9f18701e0686cb21c0cec6599df32ec09e1168dc48',
                },
                'dependency_snapshot': {
                    'commit': '945559bf0f1811cb2f88e827ff1412081f1fbd75',
                    'parent': '44ef1ef7f202c8a7ff85cb8f3a329d9ef76fd5e3',
                    'tree': '09dfcd9ff69362ae019b2876a66ec78d54008337',
                    'pathset_sha256': None,
                },
            }
        else:
            dependency = {
                'dependency_role': 'MR04_GUARD',
                'dependency_logical_id': 'MR04',
                'expected_dependency_class': 'FROZEN_MR04_LOWER_LEVEL_COMPOSITION',
                'dependency_contract_identity': '0e110454fdd399db1564a2f7fdc581faabbea190ba0d668fc674243bbb414e32',
                'dependency_version_identity': None,
                'dependency_content_identity': {
                    'kind': 'CONTENTSET',
                    'sha256': 'a1da9509f5e5acc102be249978323bc9706cc893f178f96b70b9317750687b5f',
                },
                'dependency_snapshot': {
                    'commit': '8ce9eb8a542799e00088a6654e1061405fde7d33',
                    'parent': '85c3f65e23aba4c7307b5870d73c8192a72b46f5',
                    'tree': 'a8944259034b699c285e2b8551ad60e3ee79d5c2',
                    'pathset_sha256': '2b58d0ee14b2c8280b608ea9a8717228c68675d15630a80a2d06f63212ba4640',
                },
            }
        dependency.update(
            {
                'schema_version': '1.0.0',
                'source_ref': source_ref,
                'input_binding': {
                    'task_identity': discovered.task_identity,
                    'source_set_identity': discovered.source_set_identity,
                    'discovery_identity': discovered.discovery_identity,
                    'normalization_identity': normalized.normalization_identity,
                    'upstream_dependency_identity': upstream,
                },
            }
        )
        return dependency

    def test_frozen_dependency_bindings_are_valid_repeatable_and_independently_identified(self):
        discovered, normalized, source_ref = self._binding_context()
        mr03_record = self._dependency_record(discovered, normalized, source_ref, 'MR03_PACKAGER')
        mr03 = mr03_adapter.bind_mr03_dependency(mr03_record, discovered, normalized, source_ref)
        mr03_repeat = mr03_adapter.bind_mr03_dependency(
            dict(reversed(list(mr03_record.items()))),
            discovered.to_dict(),
            normalized.to_dict(),
            discovered.selected_sources[0],
        )
        self.assertEqual(mr03.to_dict(), mr03_repeat.to_dict())
        self.assertEqual(mr03.binding_identity, 'ba614ef64ed477787b02fdab47028df93d396b15899f01d2646c5b3dfbd11553')
        self.assertEqual(mr03.binding_identity, identity.sha256_canonical(mr03.identity_payload))
        self.assertEqual(mr03.canonical_identity_bytes(), canonical.canonical_json_bytes(mr03.identity_payload))
        self.assertEqual(
            mr03_adapter.DependencyBinding.from_mapping(mr03.to_dict()).to_dict(),
            mr03.to_dict(),
        )

        upstream = 'c' * 64
        mr04_record = self._dependency_record(discovered, normalized, source_ref, 'MR04_GUARD', upstream)
        mr04 = mr04_adapter.bind_mr04_dependency(
            mr04_record,
            discovered,
            normalized,
            upstream,
            source_ref,
        )
        self.assertEqual(mr04.dependency_role, 'MR04_GUARD')
        self.assertEqual(mr04.dependency_snapshot['commit'], '8ce9eb8a542799e00088a6654e1061405fde7d33')
        self.assertEqual(mr04.binding_identity, 'c78560010e8598ca5af5462a5381f7e586ee65a03dfd5879bb9ebaf494b284bd')
        self.assertEqual(mr04.binding_identity, identity.sha256_canonical(mr04.identity_payload))
        self.assertEqual(
            mr04_adapter.DependencyBinding.from_mapping(mr04.to_dict()).binding_identity,
            mr04.binding_identity,
        )

    def test_selected_source_membership_rejects_fabricated_refs_for_both_adapters(self):
        discovered, normalized, source_ref = self._binding_context()
        mutations = (
            ('source_id', {'source_id': 'a' * 64}),
            ('canonical_locator', {'canonical_locator': 'fixture/substituted.json'}),
            ('content_sha256', {'content_sha256': 'b' * 64}),
            ('content_size_bytes', {'content_size_bytes': source_ref['content_size_bytes'] + 1}),
            (
                'fabricated_source_ref',
                {
                    'source_id': 'a' * 64,
                    'canonical_locator': 'fixture/substituted.json',
                    'content_sha256': 'b' * 64,
                    'content_size_bytes': source_ref['content_size_bytes'] + 1,
                },
            ),
        )
        for role in ('MR03_PACKAGER', 'MR04_GUARD'):
            for label, changes in mutations:
                with self.subTest(adapter=role, mutation=label):
                    fabricated = dict(source_ref)
                    fabricated.update(changes)
                    self.assertEqual(fabricated['source_set_identity'], discovered.source_set_identity)
                    for field, value in changes.items():
                        self.assertNotEqual(value, source_ref[field])
                    upstream = None if role == 'MR03_PACKAGER' else 'c' * 64
                    candidate = self._dependency_record(
                        discovered,
                        normalized,
                        fabricated,
                        role,
                        upstream,
                    )
                    with self.assertRaises(mr03_adapter.DependencyBindingValidationError) as raised:
                        if role == 'MR03_PACKAGER':
                            mr03_adapter.bind_mr03_dependency(
                                candidate,
                                discovered,
                                normalized,
                                fabricated,
                            )
                        else:
                            mr04_adapter.bind_mr04_dependency(
                                candidate,
                                discovered,
                                normalized,
                                upstream,
                                fabricated,
                            )
                    self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)

    def test_dependency_binding_identity_is_sensitive_to_semantic_input_mutation(self):
        discovered, normalized, source_ref = self._binding_context()
        record = self._dependency_record(discovered, normalized, source_ref, 'MR03_PACKAGER')
        base = mr03_adapter.bind_mr03_dependency(record, discovered, normalized, source_ref)
        raw = base.to_dict()

        changed_input = {key: value for key, value in raw.items() if key != 'binding_identity'}
        changed_input['input_binding'] = dict(changed_input['input_binding'])
        changed_input['input_binding']['task_identity'] = 'b' * 64
        changed = mr03_adapter.DependencyBinding(**changed_input)
        self.assertNotEqual(base.binding_identity, changed.binding_identity)

        changed_source = {key: value for key, value in raw.items() if key != 'binding_identity'}
        changed_source['source_ref'] = dict(changed_source['source_ref'])
        changed_source['source_ref']['content_sha256'] = 'd' * 64
        changed_source_binding = mr03_adapter.DependencyBinding(**changed_source)
        self.assertNotEqual(base.binding_identity, changed_source_binding.binding_identity)

        reordered = dict(reversed(list(raw.items())))
        self.assertEqual(
            mr03_adapter.DependencyBinding.from_mapping(reordered).binding_identity,
            base.binding_identity,
        )

    def test_dependency_binding_rejects_malformed_conflicting_and_coerced_inputs(self):
        discovered, normalized, source_ref = self._binding_context()
        base = self._dependency_record(discovered, normalized, source_ref, 'MR03_PACKAGER')

        invalid_cases = []
        invalid_hash = __import__('copy').deepcopy(base)
        invalid_hash['dependency_snapshot']['tree'] = 'A' * 64
        invalid_cases.append(invalid_hash)
        missing_identity = __import__('copy').deepcopy(base)
        del missing_identity['input_binding']['normalization_identity']
        invalid_cases.append(missing_identity)
        unknown_role = __import__('copy').deepcopy(base)
        unknown_role['dependency_role'] = 'UNKNOWN'
        invalid_cases.append(unknown_role)
        unsupported_schema = __import__('copy').deepcopy(base)
        unsupported_schema['schema_version'] = '2.0.0'
        invalid_cases.append(unsupported_schema)
        unknown_field = __import__('copy').deepcopy(base)
        unknown_field['unexpected'] = 'reject'
        invalid_cases.append(unknown_field)
        coerced = __import__('copy').deepcopy(base)
        coerced['dependency_snapshot']['commit'] = True
        invalid_cases.append(coerced)
        conflicting_id = __import__('copy').deepcopy(base)
        conflicting_id['dependency_logical_id'] = 'MR04'
        invalid_cases.append(conflicting_id)
        inconsistent_snapshot = __import__('copy').deepcopy(base)
        inconsistent_snapshot['dependency_snapshot']['parent'] = 'f' * 40
        invalid_cases.append(inconsistent_snapshot)
        unsafe_locator = __import__('copy').deepcopy(base)
        unsafe_locator['source_ref']['canonical_locator'] = '../escape'
        invalid_cases.append(unsafe_locator)
        missing_contract_and_version = __import__('copy').deepcopy(base)
        missing_contract_and_version['dependency_version_identity'] = None
        invalid_cases.append(missing_contract_and_version)
        wrong_declared_identity = __import__('copy').deepcopy(base)
        wrong_declared_identity['binding_identity'] = '0' * 64
        invalid_cases.append(wrong_declared_identity)

        for candidate in invalid_cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                mr03_adapter.DependencyBindingValidationError
            ):
                mr03_adapter.bind_mr03_dependency(candidate, discovered, normalized, source_ref)

        without_record_identity = __import__('copy').deepcopy(base)
        with self.assertRaises(mr03_adapter.DependencyBindingValidationError):
            mr03_adapter.DependencyBinding.from_mapping(without_record_identity)

        mr04 = self._dependency_record(discovered, normalized, source_ref, 'MR04_GUARD', 'c' * 64)
        mr04['input_binding']['upstream_dependency_identity'] = None
        with self.assertRaises(mr04_adapter.DependencyBindingValidationError):
            mr04_adapter.bind_mr04_dependency(mr04, discovered, normalized, 'c' * 64, source_ref)
        with self.assertRaises(mr04_adapter.DependencyBindingValidationError):
            mr04_adapter.bind_mr04_dependency(
                self._dependency_record(discovered, normalized, source_ref, 'MR04_GUARD', 'c' * 64),
                discovered,
                normalized,
                True,
                source_ref,
            )

    def test_dependency_binding_lookup_is_immutable_and_boundaries_stay_zero(self):
        from types import MappingProxyType

        discovered, normalized, source_ref = self._binding_context()
        record = self._dependency_record(discovered, normalized, source_ref, 'MR03_PACKAGER')
        binding = mr03_adapter.bind_mr03_dependency(record, discovered, normalized, source_ref)
        self.assertIsInstance(binding.dependency_content_identity, MappingProxyType)
        self.assertIsInstance(binding.dependency_snapshot, MappingProxyType)
        self.assertIsInstance(binding.source_ref, MappingProxyType)
        self.assertIsInstance(binding.input_binding, MappingProxyType)
        with self.assertRaises(TypeError):
            binding.dependency_snapshot['commit'] = 'f' * 40
        exported = binding.to_dict()
        exported['dependency_snapshot']['commit'] = 'f' * 40
        self.assertEqual(binding.dependency_snapshot['commit'], '945559bf0f1811cb2f88e827ff1412081f1fbd75')

        zero_names = (
            'MR03_EXECUTION_IMPLEMENTATION_COUNT',
            'MR04_EXECUTION_IMPLEMENTATION_COUNT',
            'SUBPROCESS_EXECUTION_COUNT',
            'FILESYSTEM_DEPENDENCY_EXECUTION_COUNT',
            'NETWORK_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT',
            'BOUNDED_CONTEXT_IMPLEMENTATION_COUNT',
            'VERIFIER_IMPLEMENTATION_COUNT',
            'CONTROLLER_IMPLEMENTATION_COUNT',
            'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
        )
        for module in (mr03_adapter, mr04_adapter):
            source = inspect.getsource(module)
            for forbidden in (
                'import socket', 'import subprocess', 'import requests', 'import httpx',
                'import urllib', 'import openai', 'import anthropic', 'import boto3',
                'subprocess.', 'socket.', 'requests.', 'httpx.', 'urllib.', 'open(',
                'os.environ', 'os.getenv', 'pathlib.Path',
            ):
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)
            for name in zero_names:
                with self.subTest(module=module.__name__, counter=name):
                    self.assertEqual(getattr(module, name), 0)
            with self.subTest(module=module.__name__, operational_marker='not_implemented'):
                with self.assertRaises(failures.MR05PhaseNotImplementedError):
                    module.not_implemented()

    def _context_fixture(self, *, source_order=('a', 'b'), row_specs=None):
        row_specs = {} if row_specs is None else row_specs
        raw = {'a': b'{"a":1}', 'b': b'{"b":2}'}
        descriptors = {
            name: self._descriptor(f'{name}.json', raw[name])
            for name in raw
        }
        discovered = discovery.discover(
            self._task(),
            [descriptors[name] for name in source_order],
            max_item_count=2,
            max_bytes=1000,
        )
        rows = []
        for reference in discovered.selected_sources:
            options = {
                'phase_id': 'MR05M',
                'artifact_type': 'EVIDENCE',
                'current_validity': 'VALID',
                'supersession': 'NONE',
                'classification': 'PUBLIC',
                'mandatory': True,
            }
            options.update(row_specs.get(reference.canonical_locator, {}))
            rows.append(normalization.NormalizedItem.from_source(reference, **options))
        normalized = normalization.normalize(discovered, rows)
        source_ref = {
            'schema_version': '1.0.0',
            **discovered.selected_sources[0].to_dict(),
        }
        mr03_record = self._dependency_record(
            discovered, normalized, source_ref, 'MR03_PACKAGER'
        )
        mr03 = mr03_adapter.bind_mr03_dependency(
            mr03_record, discovered, normalized, source_ref
        )
        mr04_record = self._dependency_record(
            discovered, normalized, source_ref, 'MR04_GUARD', mr03.binding_identity
        )
        mr04 = mr04_adapter.bind_mr04_dependency(
            mr04_record,
            discovered,
            normalized,
            mr03.binding_identity,
            source_ref,
        )
        metric = Metrics(
            raw_source_bytes=discovered.total_selected_bytes,
            normalized_bytes=normalized.output_bytes,
            package_bytes=normalized.output_bytes,
            source_ref_count=len(discovered.selected_sources),
        )
        required = (
            ('TASK_IDENTITY', discovered.task_identity),
            ('SOURCE_SET_IDENTITY', discovered.source_set_identity),
            ('DISCOVERY_IDENTITY', discovered.discovery_identity),
            ('NORMALIZATION_IDENTITY', normalized.normalization_identity),
            ('MR03_BINDING_IDENTITY', mr03.binding_identity),
            ('MR04_BINDING_IDENTITY', mr04.binding_identity),
            ('METRICS_IDENTITY', metric.metrics_identity),
        )
        chain = provenance.ProvenanceChain(
            nodes=tuple(
                provenance.ProvenanceNode(name, value, f'fixture/{name.lower()}')
                for name, value in required
            ),
            edges=(),
        )
        return discovered, normalized, (mr03, mr04), chain, metric

    @staticmethod
    def _build_context(inputs, *, max_context_bytes):
        discovered, normalized, bindings, chain, metric = inputs
        return context_builder.build_context(
            discovered,
            normalized,
            bindings,
            chain,
            metric,
            max_context_bytes=max_context_bytes,
        )

    def test_context_builds_atomic_public_metadata_and_round_trips(self):
        inputs = self._context_fixture()
        package = self._build_context(inputs, max_context_bytes=100000)
        self.assertEqual(package.schema_id, context_builder.CONTEXT_SCHEMA_ID)
        self.assertEqual(package.context_item_count, 2)
        self.assertEqual(
            package.included_item_identities,
            tuple(item.item_identity for item in package.context_items),
        )
        self.assertEqual(package.omitted_item_identities, ())
        body = package.to_dict()
        body.pop('context_byte_count')
        body.pop('context_identity')
        self.assertEqual(package.context_byte_count, len(canonical.canonical_json_bytes(body)))
        self.assertEqual(
            package.context_identity,
            identity.sha256_canonical(package.identity_payload),
        )
        self.assertEqual(
            context_builder.BoundedContextPackage.from_mapping(package.to_dict()),
            package,
        )
        with self.assertRaises(TypeError):
            package.input_identities['task_identity'] = 'a' * 64
        with self.assertRaises(TypeError):
            package.context_items[0].content['phase_id'] = 'forged'
        self.assertNotIn('raw_bytes', package.to_dict())

    def test_context_order_and_dependency_order_are_input_independent(self):
        first_inputs = self._context_fixture(source_order=('a', 'b'))
        second_inputs = self._context_fixture(source_order=('b', 'a'))
        first = self._build_context(first_inputs, max_context_bytes=100000)
        discovered, normalized, bindings, chain, metric = second_inputs
        second = context_builder.build_context(
            discovered,
            normalized,
            tuple(reversed(bindings)),
            chain,
            metric,
            max_context_bytes=100000,
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.context_identity, second.context_identity)
        self.assertEqual(
            list(first.included_item_identities),
            sorted(first.included_item_identities),
        )
        self.assertEqual(
            list(first.dependency_binding_identities),
            sorted(first.dependency_binding_identities),
        )

    def test_context_byte_boundary_is_exact_and_never_repacked(self):
        inputs = self._context_fixture(source_order=('a',))
        budget = self._build_context(inputs, max_context_bytes=100000).context_byte_count
        for _ in range(8):
            package = self._build_context(inputs, max_context_bytes=budget)
            if package.context_byte_count == budget:
                break
            budget = package.context_byte_count
        exact = self._build_context(inputs, max_context_bytes=budget)
        self.assertEqual(exact.context_byte_count, budget)
        self.assertEqual(
            self._build_context(inputs, max_context_bytes=budget + 1).context_byte_count,
            budget,
        )
        with self.assertRaises(context_builder.ContextBuildValidationError) as raised:
            self._build_context(inputs, max_context_bytes=budget - 1)
        self.assertEqual(
            raised.exception.code,
            failures.FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET.value,
        )
        with self.assertRaises(context_builder.ContextBuildValidationError) as oversized:
            self._build_context(inputs, max_context_bytes=1)
        self.assertEqual(
            oversized.exception.code,
            failures.FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET.value,
        )

    def test_context_policy_omits_optional_unsafe_items_and_rejects_mandatory(self):
        optional_inputs = self._context_fixture(
            row_specs={'fixture/b.json': {'classification': 'PROTECTED', 'mandatory': False}}
        )
        package = self._build_context(optional_inputs, max_context_bytes=100000)
        self.assertEqual(package.context_item_count, 1)
        self.assertEqual(len(package.omitted_item_identities), 1)
        self.assertEqual(
            package.omitted_item_identities[0].omission_reason,
            'PROTECTED_CONTENT',
        )
        mandatory_inputs = self._context_fixture(
            row_specs={'fixture/b.json': {'classification': 'PROTECTED', 'mandatory': True}}
        )
        with self.assertRaises(context_builder.ContextBuildValidationError) as raised:
            self._build_context(mandatory_inputs, max_context_bytes=100000)
        self.assertEqual(
            raised.exception.code,
            failures.FailureCode.PROTECTED_CONTENT_SELECTED.value,
        )

    def test_context_rejects_zero_input_forgery_duplicates_and_malformed_budget(self):
        inputs = self._context_fixture(source_order=('a',))
        discovered, normalized, bindings, chain, metric = inputs
        with self.assertRaises(context_builder.ContextBuildValidationError) as budget:
            self._build_context(inputs, max_context_bytes=True)
        self.assertEqual(budget.exception.code, failures.FailureCode.INVALID_SCHEMA.value)

        forged = __import__('copy').deepcopy(bindings[0].to_dict())
        forged['binding_identity'] = '0' * 64
        with self.assertRaises(context_builder.ContextBuildValidationError) as binding:
            self._build_context(
                (discovered, normalized, (forged, bindings[1]), chain, metric),
                max_context_bytes=100000,
            )
        self.assertEqual(binding.exception.code, failures.FailureCode.HASH_MISMATCH.value)

        with self.assertRaises(context_builder.ContextBuildValidationError) as duplicate:
            self._build_context(
                (discovered, normalized, (bindings[0], bindings[0]), chain, metric),
                max_context_bytes=100000,
            )
        self.assertEqual(
            duplicate.exception.code,
            failures.FailureCode.DUPLICATE_CONFLICT.value,
        )

        empty = normalization.NormalizationResult(
            schema_version='1.0.0',
            discovery_identity=discovered.discovery_identity,
            normalized_items=(),
            normalization_policy_version='1.0.0',
            input_bytes=discovered.total_selected_bytes,
            output_bytes=len(canonical.canonical_json_bytes([])),
        )
        with self.assertRaises(context_builder.ContextBuildValidationError) as zero:
            self._build_context(
                (discovered, empty, bindings, chain, metric),
                max_context_bytes=100000,
            )
        self.assertEqual(zero.exception.code, failures.FailureCode.PROVENANCE_GAP.value)

        package = self._build_context(inputs, max_context_bytes=100000)
        mutated = __import__('copy').deepcopy(package.to_dict())
        mutated['context_items'][0]['item_identity'] = '0' * 64
        with self.assertRaises(context_builder.ContextBuildValidationError) as item:
            context_builder.BoundedContextPackage.from_mapping(mutated)
        self.assertEqual(item.exception.code, failures.FailureCode.HASH_MISMATCH.value)
        mutated = __import__('copy').deepcopy(package.to_dict())
        mutated['unexpected'] = 'reject'
        with self.assertRaises(context_builder.ContextBuildValidationError) as unknown:
            context_builder.BoundedContextPackage.from_mapping(mutated)
        self.assertEqual(unknown.exception.code, failures.FailureCode.INVALID_SCHEMA.value)

        conflicting_nodes = chain.nodes + (
            provenance.ProvenanceNode(
                'CONFLICTING_NAME',
                chain.nodes[0].identity_value,
                'fixture/conflict',
            ),
        )
        conflicting_chain = provenance.ProvenanceChain(nodes=conflicting_nodes, edges=())
        with self.assertRaises(context_builder.ContextBuildValidationError) as conflict:
            self._build_context(
                (discovered, normalized, bindings, conflicting_chain, metric),
                max_context_bytes=100000,
            )
        self.assertEqual(
            conflict.exception.code,
            failures.FailureCode.DUPLICATE_CONFLICT.value,
        )

    def test_context_accepts_exact_mappings_and_rejects_unknown_schema(self):
        inputs = self._context_fixture(source_order=('a', 'b'))
        discovered, normalized, bindings, chain, metric = inputs
        discovered_mapping = dict(reversed(list(discovered.to_dict().items())))
        normalized_mapping = dict(reversed(list(normalized.to_dict().items())))
        binding_mappings = [
            dict(reversed(list(binding.to_dict().items())))
            for binding in reversed(bindings)
        ]
        chain_mapping = dict(reversed(list(chain.to_dict().items())))
        metric_mapping = dict(reversed(list(metric.to_dict().items())))
        package = context_builder.build_context(
            discovered_mapping,
            normalized_mapping,
            binding_mappings,
            chain_mapping,
            metric_mapping,
            100000,
        )
        self.assertEqual(package.context_item_count, 2)
        self.assertEqual(
            package,
            self._build_context(inputs, max_context_bytes=100000),
        )
        output = package.to_dict()
        output['schema_id'] = 'mr05.unknown'
        with self.assertRaises(context_builder.ContextBuildValidationError) as raised:
            context_builder.BoundedContextPackage.from_mapping(output)
        self.assertEqual(
            raised.exception.code,
            failures.FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value,
        )

    def test_context_boundary_has_no_external_execution_surface(self):
        source = inspect.getsource(context_builder)
        for forbidden in (
            'import socket', 'import subprocess', 'import requests', 'import httpx',
            'import urllib', 'import openai', 'import anthropic', 'import boto3',
            'subprocess.', 'socket.', 'requests.', 'httpx.', 'urllib.', 'open(',
            'os.environ', 'os.getenv', 'pathlib.Path',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        for name in (
            'MR03_EXECUTION_IMPLEMENTATION_COUNT',
            'MR04_EXECUTION_IMPLEMENTATION_COUNT',
            'FILESYSTEM_SOURCE_READ_COUNT',
            'FILESYSTEM_DEPENDENCY_EXECUTION_COUNT',
            'SUBPROCESS_EXECUTION_COUNT',
            'NETWORK_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT',
            'VERIFIER_IMPLEMENTATION_COUNT',
            'CONTROLLER_IMPLEMENTATION_COUNT',
            'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
        ):
            with self.subTest(counter=name):
                self.assertEqual(getattr(context_builder, name), 0)
        self.assertEqual(context_builder.BOUNDED_CONTEXT_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(context_builder.MODEL_CALL_COUNT, 0)
        self.assertEqual(context_builder.PARTIAL_ITEM_TRUNCATION, 'NOT_ALLOWED')
        self.assertEqual(
            context_builder.BOUNDED_CONTEXT_OVERFLOW_POLICY,
            'BLOCK_ENTIRE_CONTEXT_NO_REPACK',
        )

    @staticmethod
    def _verifier_inputs():
        input_identities = {
            field: chr(ord('a') + index) * 64
            for index, field in enumerate(verifier.INPUT_IDENTITY_FIELDS)
        }
        dependency_identities = ('f' * 64, '0' * 64)
        provenance_identity = '1' * 64
        metrics_identity = '2' * 64
        return (
            input_identities,
            dependency_identities,
            provenance_identity,
            metrics_identity,
            verifier.FROZEN_CONTRACT_IDENTITIES,
        )

    @staticmethod
    def _verifier_checks(input_identity, overrides=None):
        overrides = {} if overrides is None else overrides
        return [
            verifier.build_verifier_check(
                rule_id=rule.rule_id,
                input_identity=input_identity,
                check_result=overrides.get(rule.rule_id, {}).get('check_result', 'PASS'),
                failure_identity=overrides.get(rule.rule_id, {}).get('failure_identity'),
                decision=overrides.get(rule.rule_id, {}).get('decision'),
                decision_reason_code=overrides.get(rule.rule_id, {}).get('decision_reason_code'),
            )
            for rule in verifier.RULE_CATALOG
        ]

    @staticmethod
    def _verifier_failure(code, run_identity='3' * 64):
        return Failure(
            schema_version='1.0.0',
            failure_code=code,
            failure_owner=failures.failure_owner_for(code),
            severity=FailureSeverity.HIGH,
            state=FailureState.FAILED,
            run_identity=run_identity,
            related_identity='e' * 64,
            message='bounded deterministic test failure',
            human_escalation_required=(code == FailureCode.AMBIGUOUS_PRECEDENCE),
        )

    def _verifier_result(self, *, overrides=None, failure_records=(), checks=None):
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        if checks is None:
            checks = self._verifier_checks(inputs['context_identity'], overrides)
        return verifier.build_verifier_result(
            inputs,
            dependencies,
            provenance_id,
            metrics_id,
            contracts_set,
            checks,
            failure_records,
        )

    def test_verifier_all_passes_yield_pass_for_review(self):
        result = self._verifier_result()
        self.assertEqual(result.decision, 'PASS_FOR_REVIEW')
        self.assertEqual(result.decision_reason_code, verifier.CHECK_PASS_REASON)
        self.assertEqual(result.missing_rule_ids, ())
        self.assertEqual(len(result.checks), len(verifier.RULE_CATALOG))
        self.assertEqual(
            result.verifier_identity,
            identity.sha256_canonical(result.identity_payload),
        )

    def test_verifier_pass_for_review_is_not_approval_or_execution_authority(self):
        result = self._verifier_result()
        self.assertEqual(result.decision, 'PASS_FOR_REVIEW')
        self.assertNotIn(result.decision, {'APPROVED', 'EXECUTE', 'COMMIT', 'PUSH'})
        self.assertEqual(verifier.PASS_FOR_REVIEW_IS_APPROVAL, 'NO')

    def test_verifier_deny_precedes_escalate_and_pass(self):
        deny = self._verifier_failure(FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM)
        escalate = self._verifier_failure(FailureCode.AMBIGUOUS_PRECEDENCE, '4' * 64)
        overrides = {
            'CLAIM_SUPPORT': {
                'check_result': 'FAIL',
                'failure_identity': deny.failure_identity,
                'decision_reason_code': deny.failure_code.value,
            },
            'CONTRADICTION_PRECEDENCE': {
                'check_result': 'FAIL',
                'failure_identity': escalate.failure_identity,
                'decision_reason_code': escalate.failure_code.value,
            },
        }
        result = self._verifier_result(
            overrides=overrides,
            failure_records=(escalate, deny),
        )
        self.assertEqual(result.decision, 'DENY')
        self.assertEqual(result.decision_reason_code, deny.failure_code.value)

    def test_verifier_escalate_precedes_pass_for_review(self):
        escalate = self._verifier_failure(FailureCode.AMBIGUOUS_PRECEDENCE)
        overrides = {
            'CONTRADICTION_PRECEDENCE': {
                'check_result': 'FAIL',
                'failure_identity': escalate.failure_identity,
                'decision_reason_code': escalate.failure_code.value,
            },
        }
        result = self._verifier_result(
            overrides=overrides,
            failure_records=(escalate,),
        )
        self.assertEqual(result.decision, 'ESCALATE')
        self.assertEqual(result.decision_reason_code, 'AMBIGUOUS_PRECEDENCE')

    def test_verifier_missing_required_evidence_denies(self):
        result = self._verifier_result(checks=())
        self.assertEqual(result.decision, 'DENY')
        self.assertEqual(result.decision_reason_code, 'MISSING_REQUIRED_ARTIFACT')
        self.assertEqual(set(result.missing_rule_ids), set(verifier.RULE_IDS))

    def test_verifier_direct_derivation_binds_required_rule_coverage(self):
        inputs, _, _, _, _ = self._verifier_inputs()
        complete = self._verifier_checks(inputs['context_identity'])
        cases = (
            ('V21 incomplete one-check coverage', (complete[0],), (), 'DENY'),
            ('one missing rule', tuple(complete[:-1]), (), 'DENY'),
            ('multiple missing rules', tuple(complete[:-2]), (), 'DENY'),
            ('empty checks', (), (), 'DENY'),
            ('complete all-pass', tuple(complete), (), 'PASS_FOR_REVIEW'),
        )
        for label, checks, supplied_missing, expected in cases:
            with self.subTest(case=label):
                self.assertEqual(
                    verifier.derive_final_decision(checks, supplied_missing),
                    expected,
                )

        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.derive_final_decision(
                (complete[0],),
                ('SCHEMA_EXACT',),
            )
        self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)

    def test_verifier_direct_derivation_preserves_precedence_and_order(self):
        inputs, _, _, _, _ = self._verifier_inputs()
        complete = self._verifier_checks(inputs['context_identity'])
        self.assertEqual(
            verifier.derive_final_decision(tuple(reversed(complete))),
            'PASS_FOR_REVIEW',
        )

        escalate = self._verifier_failure(FailureCode.AMBIGUOUS_PRECEDENCE)
        escalate_checks = self._verifier_checks(
            inputs['context_identity'],
            {
                'CONTRADICTION_PRECEDENCE': {
                    'check_result': 'FAIL',
                    'failure_identity': escalate.failure_identity,
                    'decision_reason_code': escalate.failure_code.value,
                },
            },
        )
        self.assertEqual(
            verifier.derive_final_decision(escalate_checks),
            'ESCALATE',
        )

        deny = self._verifier_failure(FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM)
        deny_checks = self._verifier_checks(
            inputs['context_identity'],
            {
                'CLAIM_SUPPORT': {
                    'check_result': 'FAIL',
                    'failure_identity': deny.failure_identity,
                    'decision_reason_code': deny.failure_code.value,
                },
            },
        )
        self.assertEqual(verifier.derive_final_decision(deny_checks), 'DENY')

    def test_verifier_check_and_contract_order_is_input_independent(self):
        first = self._verifier_result()
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        second = verifier.build_verifier_result(
            dict(reversed(list(inputs.items()))),
            tuple(reversed(dependencies)),
            provenance_id,
            metrics_id,
            tuple(reversed(contracts_set)),
            tuple(reversed(first.checks)),
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.verifier_identity, second.verifier_identity)

    def test_verifier_forged_rule_identity_is_rejected(self):
        check = verifier.build_verifier_check(
            rule_id=verifier.RULE_IDS[0],
            input_identity='e' * 64,
            check_result='PASS',
        ).to_dict()
        check['rule_identity'] = '0' * 64
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.VerifierCheckRecord.from_mapping(check)
        self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)

    def test_verifier_forged_contract_identity_is_rejected(self):
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        forged = [dict(record) for record in contracts_set]
        forged[0]['contract_identity'] = '0' * 64
        checks = self._verifier_checks(inputs['context_identity'])
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.build_verifier_result(
                inputs, dependencies, provenance_id, metrics_id, forged, checks
            )
        self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)

    def test_verifier_unknown_rule_version_and_schema_fail_closed(self):
        valid = verifier.build_verifier_check(
            rule_id=verifier.RULE_IDS[0],
            input_identity='e' * 64,
            check_result='PASS',
        ).to_dict()
        unknown_rule = dict(valid)
        unknown_rule['rule_id'] = 'UNKNOWN_RULE'
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.VerifierCheckRecord.from_mapping(unknown_rule)
        unknown_version = dict(valid)
        unknown_version['rule_version'] = '9.0.0'
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.VerifierCheckRecord.from_mapping(unknown_version)
        unknown_schema = dict(valid)
        unknown_schema['schema_id'] = 'mr05.unknown'
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.VerifierCheckRecord.from_mapping(unknown_schema)
        self.assertEqual(
            raised.exception.code,
            FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR.value,
        )

    def test_verifier_duplicate_rule_and_conflicting_evidence_fail_closed(self):
        check = verifier.build_verifier_check(
            rule_id=verifier.RULE_IDS[0],
            input_identity='e' * 64,
            check_result='PASS',
        )
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        with self.assertRaises(verifier.VerifierValidationError) as duplicate:
            verifier.build_verifier_result(
                inputs,
                dependencies,
                provenance_id,
                metrics_id,
                contracts_set,
                (check, check),
            )
        self.assertEqual(duplicate.exception.code, FailureCode.DUPLICATE_CONFLICT.value)

        deny = self._verifier_failure(FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM)
        escalate = self._verifier_failure(FailureCode.AMBIGUOUS_PRECEDENCE, '4' * 64)
        overrides = {
            'CLAIM_SUPPORT': {
                'check_result': 'FAIL',
                'failure_identity': deny.failure_identity,
                'decision_reason_code': deny.failure_code.value,
            },
            'CONTRADICTION_PRECEDENCE': {
                'check_result': 'FAIL',
                'failure_identity': escalate.failure_identity,
                'decision_reason_code': escalate.failure_code.value,
            },
        }
        result = self._verifier_result(
            overrides=overrides,
            failure_records=(deny, escalate),
        )
        self.assertEqual(result.decision, 'DENY')

    def test_verifier_failure_identity_and_owner_validation_are_fail_closed(self):
        with self.assertRaises(verifier.VerifierValidationError) as malformed:
            verifier.build_verifier_check(
                rule_id='CLAIM_SUPPORT',
                input_identity='e' * 64,
                check_result='FAIL',
                failure_identity='A' * 64,
                decision_reason_code='MR05_PROPOSAL_UNSUPPORTED_CLAIM',
            )
        self.assertEqual(malformed.exception.code, FailureCode.HASH_MISMATCH.value)
        bad_owner = self._verifier_failure(FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM)
        with self.assertRaises(failures.FailureValidationError):
            Failure(
                schema_version='1.0.0',
                failure_code=FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM,
                failure_owner=FailureOwner.VERIFICATION,
                severity=FailureSeverity.HIGH,
                state=FailureState.FAILED,
                run_identity='3' * 64,
                related_identity='e' * 64,
                message='wrong owner',
            )
        self.assertNotEqual(bad_owner.failure_owner, FailureOwner.VERIFICATION)

    def test_verifier_invalid_check_decision_and_unknown_fields_fail_closed(self):
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.build_verifier_check(
                rule_id='SCHEMA_EXACT',
                input_identity='e' * 64,
                check_result='PASS',
                decision='DENY',
            )
        valid = verifier.build_verifier_check(
            rule_id='SCHEMA_EXACT',
            input_identity='e' * 64,
            check_result='PASS',
        ).to_dict()
        valid['unexpected'] = 'reject'
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.VerifierCheckRecord.from_mapping(valid)
        self.assertEqual(raised.exception.code, FailureCode.INVALID_SCHEMA.value)
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.build_verifier_check(
                rule_id='SCHEMA_EXACT',
                input_identity='e' * 64,
                check_result=1,
            )

    def test_verifier_identity_is_repeatable_and_sensitive_to_governed_inputs(self):
        first = self._verifier_result()
        repeated = self._verifier_result()
        self.assertEqual(first.verifier_identity, repeated.verifier_identity)
        self.assertEqual(
            verifier.compute_verifier_identity(first.to_dict()),
            first.verifier_identity,
        )
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        changed_inputs = dict(inputs)
        changed_inputs['context_identity'] = '9' * 64
        changed_checks = self._verifier_checks(changed_inputs['context_identity'])
        changed = verifier.build_verifier_result(
            changed_inputs,
            dependencies,
            provenance_id,
            metrics_id,
            contracts_set,
            changed_checks,
        )
        self.assertNotEqual(first.verifier_identity, changed.verifier_identity)

    def test_verifier_policy_version_and_declared_identity_mutations_fail_closed(self):
        result = self._verifier_result()
        mutated_policy = result.to_dict()
        mutated_policy['verification_policy_version'] = 'MR05-VERIFIER-POLICY-9.9.9'
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.VerifierResult.from_mapping(mutated_policy)
        mutated_identity = result.to_dict()
        mutated_identity['verifier_identity'] = '0' * 64
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.VerifierResult.from_mapping(mutated_identity)
        self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)
        preimage = result.identity_payload
        preimage['decision'] = 'DENY'
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.verifier_identity_from_preimage(preimage)

    def test_verifier_unknown_failure_reference_and_reason_fail_closed(self):
        inputs, dependencies, provenance_id, metrics_id, contracts_set = self._verifier_inputs()
        forged = {
            'CLAIM_SUPPORT': {
                'check_result': 'FAIL',
                'failure_identity': '3' * 64,
                'decision_reason_code': 'MR05_PROPOSAL_UNSUPPORTED_CLAIM',
            },
        }
        checks = self._verifier_checks(inputs['context_identity'], forged)
        with self.assertRaises(verifier.VerifierValidationError) as raised:
            verifier.build_verifier_result(
                inputs, dependencies, provenance_id, metrics_id, contracts_set, checks
            )
        self.assertEqual(raised.exception.code, FailureCode.HASH_MISMATCH.value)

    def test_verifier_identity_preimage_and_canonical_output_are_exact(self):
        result = self._verifier_result()
        self.assertEqual(
            tuple(result.identity_payload),
            verifier.VERIFIER_IDENTITY_PREIMAGE,
        )
        self.assertEqual(
            verifier.canonical_verifier_bytes(result),
            canonical.canonical_json_bytes(result.to_dict()),
        )
        self.assertEqual(
            verifier.VerifierResult.from_mapping(result.to_dict()).to_dict(),
            result.to_dict(),
        )

    def test_verifier_unknown_decision_and_nonpass_reason_fail_closed(self):
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.build_verifier_check(
                rule_id='SCHEMA_EXACT',
                input_identity='e' * 64,
                check_result='PASS',
                decision='APPROVE',
            )
        with self.assertRaises(verifier.VerifierValidationError):
            verifier.build_verifier_check(
                rule_id='SCHEMA_EXACT',
                input_identity='e' * 64,
                check_result='FAIL',
                failure_identity='3' * 64,
                decision_reason_code='NOT_A_FAILURE_CODE',
            )

    def test_verifier_boundary_has_no_external_execution_surface(self):
        source = inspect.getsource(verifier)
        for forbidden in (
            'import socket', 'import subprocess', 'import requests', 'import httpx',
            'import urllib', 'import openai', 'import anthropic', 'import boto3',
            'subprocess.', 'socket.', 'requests.', 'httpx.', 'urllib.', 'open(',
            'os.environ', 'os.getenv', 'pathlib.Path',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        zero_names = (
            'LIVE_VERIFICATION_EXECUTION_COUNT',
            'CONTROLLER_IMPLEMENTATION_COUNT',
            'OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT',
            'MR03_EXECUTION_IMPLEMENTATION_COUNT',
            'MR04_EXECUTION_IMPLEMENTATION_COUNT',
            'FILESYSTEM_SOURCE_READ_COUNT',
            'SUBPROCESS_EXECUTION_COUNT',
            'NETWORK_IMPLEMENTATION_COUNT',
            'PROVIDER_CLIENT_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT',
            'MODEL_ROUTING_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT',
            'HUMAN_APPROVAL_EXECUTION_COUNT',
            'STATE_TRANSITION_EXECUTION_COUNT',
            'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
        )
        for name in zero_names:
            with self.subTest(counter=name):
                self.assertEqual(getattr(verifier, name), 0)
        self.assertEqual(verifier.VERIFIER_IMPLEMENTATION_COUNT, 1)
        with self.assertRaises(failures.MR05PhaseNotImplementedError):
            verifier.not_implemented()

    def test_controller_fail_closed_override_bypasses_human_gate_requirement(self):
        result = controller.qualify_transition(controller.TRANSITION_FAIL_CLOSED)
        self.assertEqual(controller.FAIL_CLOSED_OVERRIDE, 'ENABLED')
        self.assertEqual(result.semantic_status, 'QUALIFIED / PASS')
        self.assertFalse(result.human_gate_required)
        self.assertTrue(result.fail_closed_override_applied)
        self.assertEqual(result.implementation_authority, 'NONE')

    def test_controller_progress_transition_requires_human_gate(self):
        result = controller.qualify_transition(controller.TRANSITION_PROGRESS)
        self.assertEqual(
            controller.HUMAN_GATE_REQUIRED_TO_LEAVE_SEMANTICS,
            'PROGRESS_TRANSITIONS_ONLY',
        )
        self.assertEqual(result.semantic_status, 'HUMAN_GATE_REQUIRED')
        self.assertTrue(result.human_gate_required)
        self.assertFalse(result.fail_closed_override_applied)
        self.assertTrue(
            controller.human_gate_required_for_transition(controller.TRANSITION_PROGRESS)
        )
        self.assertEqual(result.implementation_authority, 'NONE')

    def test_controller_hold_and_review_gate_are_qualified_without_write_authority(self):
        expected = (
            (controller.TRANSITION_HOLD, controller.HOLD_TRANSITION_SEMANTICS),
            (
                controller.TRANSITION_READY_FOR_HUMAN_REVIEW_GATE,
                controller.READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS,
            ),
        )
        for transition_kind, semantic_status in expected:
            with self.subTest(transition_kind=transition_kind):
                result = controller.qualify_transition(transition_kind)
                self.assertEqual(semantic_status, 'QUALIFIED / PASS')
                self.assertEqual(result.semantic_status, semantic_status)
                self.assertFalse(result.human_gate_required)
                self.assertFalse(result.fail_closed_override_applied)
                self.assertEqual(result.implementation_authority, 'NONE')
        self.assertEqual(controller.PASS_FOR_REVIEW_IS_IMPLEMENTATION_AUTHORITY, 'NO')

    def test_controller_policy_unknowns_fail_closed_and_operational_surface_stays_zero(self):
        for value in ('', 'PASS_FOR_REVIEW', 'APPROVE', None, 1):
            with self.subTest(value=value), self.assertRaises(controller.ControllerPolicyError):
                controller.qualify_transition(value)
        self.assertEqual(controller.OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(controller.MR03_EXECUTION_IMPLEMENTATION_COUNT, 1)
        self.assertEqual(controller.MR04_EXECUTION_IMPLEMENTATION_COUNT, 1)
        zero_names = (
            'STATE_TRANSITION_EXECUTION_COUNT',
            'HUMAN_APPROVAL_EXECUTION_COUNT',
            'FILESYSTEM_WRITE_IMPLEMENTATION_COUNT',
            'SUBPROCESS_EXECUTION_COUNT',
            'NETWORK_IMPLEMENTATION_COUNT',
            'PROVIDER_CLIENT_IMPLEMENTATION_COUNT',
            'MODEL_CALL_IMPLEMENTATION_COUNT',
            'MODEL_ROUTING_IMPLEMENTATION_COUNT',
            'AUTH_IMPLEMENTATION_COUNT',
            'AUTO_RETRY_IMPLEMENTATION_COUNT',
            'AUTO_FALLBACK_IMPLEMENTATION_COUNT',
        )
        self.assertEqual(controller.CONTROLLER_IMPLEMENTATION_COUNT, 1)
        for name in zero_names:
            with self.subTest(counter=name):
                self.assertEqual(getattr(controller, name), 0)
        source = inspect.getsource(controller)
        for forbidden in (
            'import socket', 'import subprocess', 'import requests', 'import httpx',
            'import urllib', 'import openai', 'import anthropic', 'import boto3',
            'subprocess.', 'socket.', 'requests.', 'httpx.', 'urllib.', 'open(',
            'os.environ', 'os.getenv', 'pathlib.Path',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

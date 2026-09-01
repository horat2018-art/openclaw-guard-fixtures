import unittest

from hai_mr05 import contracts, failures


class DependencyPinTests(unittest.TestCase):
    def test_full_commit_pins(self):
        self.assertEqual(contracts.MR03_EXPECTED_COMMIT, '945559bf0f1811cb2f88e827ff1412081f1fbd75')
        self.assertEqual(contracts.MR04_EXPECTED_COMMIT, '8ce9eb8a542799e00088a6654e1061405fde7d33')
        self.assertEqual(len(contracts.MR03_EXPECTED_COMMIT), 40)
        self.assertEqual(len(contracts.MR04_EXPECTED_COMMIT), 40)
        self.assertTrue(contracts.is_known_schema('mr05.metrics'))
        self.assertEqual(contracts.schema_version_for('mr05.metrics'), '1.0.0')

    def test_contract_pins_and_schema_versions(self):
        self.assertEqual(contracts.MR05A_CONTRACT_SHA256, '99a52798cafc038bf3c9db20eacc7f5fa3cadc16468afdb39697d9c9b7d06811')
        self.assertEqual(contracts.MR05B_MASTER_CONTRACT_SHA256, '20462c72898252b9a31670c08a7c253e9a1a65d42363bc25151a2bebbff7c6bd')
        self.assertEqual(contracts.MR05B_CONTRACT_SET_SHA256, 'a78c2574bc15692e1e8e56b4ff1a91b19b11a4b0e4fc808db3577a158ef45cc9')
        self.assertEqual(contracts.MR05C_PD_CONTRACT_SHA256, '7ed85094454da0362ab47d66e59b81a6e42283685809573a60cffe93df9549df')
        self.assertEqual(contracts.MR05C_R2_CONTRACT_SHA256, 'c7e561000b43677b65ffe8ce46ba44d679de9c75c1febe2471114bccd7072cf9')
        self.assertEqual(contracts.MR05D_R2_CONTRACT_SHA256, '44fac0d7abe60487202b7937ebe1055a347c1ab30dd0ef90e0e4fcccd1826000')
        self.assertEqual(set(contracts.SCHEMA_VERSIONS.values()), {'1.0.0'})
        self.assertEqual(len(contracts.SCHEMA_VERSIONS), 26)

    def test_frozen_mappings_and_versions_fail_closed(self):
        schema_before = contracts.schema_version_for('mr05.metrics')
        owner_before = failures.failure_owner_for(failures.FailureCode.MR05_MODEL_TIMEOUT)
        with self.assertRaises(TypeError):
            contracts.SCHEMA_VERSIONS['mr05.metrics'] = '2.0.0'
        with self.assertRaises(TypeError):
            failures.FAILURE_CODE_OWNERS[failures.FailureCode.MR05_MODEL_TIMEOUT] = failures.FailureOwner.VERIFICATION
        schema_backing = vars(contracts).get('_SCHEMA_VERSION_VALUES')
        if schema_backing is not None:
            with self.assertRaises(TypeError):
                schema_backing['mr05.metrics'] = '2.0.0'
        owner_backing = vars(failures).get('_FAILURE_OWNER_VALUES')
        if owner_backing is not None:
            with self.assertRaises(TypeError):
                owner_backing[failures.FailureCode.MR05_MODEL_TIMEOUT] = failures.FailureOwner.VERIFICATION
        self.assertEqual(contracts.schema_version_for('mr05.metrics'), schema_before)
        self.assertEqual(failures.failure_owner_for(failures.FailureCode.MR05_MODEL_TIMEOUT), owner_before)
        with self.assertRaises(contracts.UnknownSchemaMajorVersionError):
            contracts.validate_schema_version('mr05.metrics', '2.0.0')
        with self.assertRaises(contracts.UnsupportedSchemaVersionError):
            contracts.validate_schema_version('mr05.metrics', '1.1.0')
        with self.assertRaises(contracts.UnknownSchemaMajorVersionError):
            contracts.schema_version_for('mr05.not-frozen')
        self.assertEqual(
            contracts.require_frozen_contract_reference(
                'MR05B_CONTRACT_SET_SHA256',
                'a78c2574bc15692e1e8e56b4ff1a91b19b11a4b0e4fc808db3577a158ef45cc9',
            ),
            'a78c2574bc15692e1e8e56b4ff1a91b19b11a4b0e4fc808db3577a158ef45cc9',
        )
        with self.assertRaises(contracts.ContractValidationError):
            contracts.require_frozen_contract_reference('MR05B_CONTRACT_SET_SHA256', '0' * 64)

import pickle
from unittest import TestCase

from data_vault import VaultEnvironment, get_synced_params
from keepercommander.params import KeeperParams

vault_env = VaultEnvironment()


class TestParamsPickling(TestCase):
    def test_pickling(self):
        params = get_synced_params()
        pickled_params = pickle.dumps(get_synced_params())

        self.assertIsInstance(pickled_params, bytes)

        actual = pickle.loads(pickled_params)

        self.assertIsInstance(actual, KeeperParams)
        self.assertEqual(len(actual.record_cache), 3)
        self.assertIsNone(actual.account_uid_bytes)
        self.assertIsNone(actual.auth_verifier)
        self.assertIsNone(actual.automators)
        self.assertIsNone(actual.available_team_cache)
        self.assertEqual(actual.batch_mode, params.batch_mode)
        self.assertIsNone(actual.client_key)
        self.assertIsNone(actual.clone_code)
        self.assertEqual(actual.config_filename, params.config_filename)
        self.assertIsNone(actual.current_folder)
        self.assertIsNone(actual.data_key)
        self.assertEqual(actual.debug, params.debug)
        self.assertIsNone(actual.device_private_key)
        self.assertIsNone(actual.device_token)
        self.assertIsNone(actual.ecc_key)
        self.assertIsNone(actual.enforcements)
        self.assertIsNone(actual.enterprise)
        self.assertIsNone(actual.enterprise_ec_key)
        self.assertEqual(actual.enterprise_id, params.enterprise_id)
        self.assertIsNone(actual.enterprise_loader)
        self.assertIsNone(actual.enterprise_rsa_key)
        self.assertEqual(actual.iterations, params.iterations)
        self.assertIsNone(actual.license)
        self.assertEqual(actual.logout_timer, 0)
        self.assertIsNone(actual.msp_tree_key)
        self.assertEqual(actual.password, "")
        self.assertFalse(actual.pending_share_requests)
        self.assertIsNone(actual.proxy)
        self.assertEqual(actual.rest_context, params.rest_context)
        self.assertEqual(actual.revision, params.revision)
        self.assertIsNone(actual.rsa_key)
        self.assertIsNone(actual.rsa_key2)
        self.assertIsNone(actual.salt)
        self.assertEqual(actual.server, params.server)
        self.assertIsNone(actual.session_token)
        self.assertIsNone(actual.session_token_bytes)
        self.assertIsNone(actual.settings)
        self.assertIsNone(actual.ssh_agent)
        self.assertIsNone(actual.sso_login_info)
        self.assertEqual(actual.sync_data, params.sync_data)
        self.assertIsNone(actual.sync_down_token)
        self.assertEqual(actual.root_folder, params.root_folder)
        self.assertEqual(actual.cache, params.cache)
        self.assertEqual(len(actual.shared_folder_cache), 1)
        self.assertEqual(len(actual.team_cache), 1)
        self.assertEqual(len(actual.cache.folder_cache), 2)
        self.assertEqual(len(params.cache.folder_cache), 2)
        self.assert_key_unencrypted(actual)

    def assert_key_unencrypted(self, params):
        for r in params.record_cache.values():
            self.assertTrue('record_key_unencrypted' in r)
        for sf in params.shared_folder_cache.values():
            self.assertTrue('shared_folder_key_unencrypted' in sf)
        for t in params.team_cache.values():
            self.assertTrue('team_key_unencrypted' in t)

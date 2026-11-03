from unittest import TestCase, mock
from collections import namedtuple

import pytest

from data_vault import VaultEnvironment, get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import api, enforcement, generator, loginv3
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2

vault_env = VaultEnvironment()


class TestPasswordGenerator(TestCase):
    def test_generator_exclude(self):
        gen = generator.KeeperPasswordGenerator(length=20, caps=-2, lower=-2, digits=-2, symbols=0)
        self.assertEqual(gen.category_map[4][0], 14)
        password = gen.generate()
        strength = generator.get_password_strength(password)
        self.assertEqual(strength.length, 20)
        self.assertEqual(strength.symbols, 0)

    def test_generator_fail(self):
        with self.assertRaises(Exception):
            generator.KeeperPasswordGenerator(length=20, caps=0, lower=0, digits=0, symbols=0)


class TestSearch(TestCase):
    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_search_records(self):
        params = get_synced_params()

        records = api.search_records(params, '')
        self.assertEqual(len(records), len(params.record_cache))

        records = api.search_records(params, 'RECORD')
        self.assertEqual(len(records), len(params.record_cache))

        records = api.search_records(params, 'Record 1')
        self.assertEqual(len(records), 1)

        records = api.search_records(params, 'INVALID')
        self.assertEqual(len(records), 0)

    def test_search_shared_folders(self):
        params = get_synced_params()

        # Empty search returns all shared folders
        sfs = api.search_shared_folders(params, '')
        self.assertEqual(len(sfs), len(params.shared_folder_cache))

        sfs = api.search_shared_folders(params, 'folder')
        self.assertEqual(len(sfs), len(params.shared_folder_cache))

        sfs = api.search_shared_folders(params, '1')
        self.assertEqual(len(sfs), 1)

        sfs = api.search_shared_folders(params, 'INVALID')
        self.assertEqual(len(sfs), 0)

    def test_search_nested_share_folders(self):
        params = get_synced_params()
        params.nested_share_folders = {
            'nsf_uid_1': {'name': 'Test Folder 1'},
            'nsf_uid_2': {'name': 'Test Folder 2'},
            'nsf_uid_3': {'name': 'Another Folder'},
        }

        # Empty search returns all NSF folders
        nsfs = api.search_nested_share_folders(params, '')
        self.assertEqual(len(nsfs), 3)

        # Token search matches name
        nsfs = api.search_nested_share_folders(params, 'test')
        self.assertEqual(len(nsfs), 2)

        # UID match
        nsfs = api.search_nested_share_folders(params, 'nsf_uid_1')
        self.assertEqual(len(nsfs), 1)
        self.assertEqual(nsfs[0], ('nsf_uid_1', 'Test Folder 1'))

        # No match
        nsfs = api.search_nested_share_folders(params, 'INVALID')
        self.assertEqual(len(nsfs), 0)

        # Missing nested_share_folders attribute
        params_no_nsf = get_synced_params()
        delattr(params_no_nsf, 'nested_share_folders')
        nsfs = api.search_nested_share_folders(params_no_nsf, '')
        self.assertEqual(len(nsfs), 0)

    def test_search_teams(self):
        params = get_synced_params()

        # Empty search returns all teams
        teams = api.search_teams(params, '')
        self.assertEqual(len(teams), len(params.team_cache))

        teams = api.search_shared_folders(params, 'team')
        self.assertEqual(len(teams), len(params.shared_folder_cache))

        teams = api.search_shared_folders(params, '1')
        self.assertEqual(len(teams), 1)

        teams = api.search_shared_folders(params, 'INVALID')
        self.assertEqual(len(teams), 0)

    def test_accept_account_transfer_consent(self):
        params = get_connected_params()
        params.settings = {
            'must_perform_account_share_by': '1632370067000',
            'share_account_to': [{
                'role_id': 123456789,
                'public_key': vault_env.encoded_public_key
            }]
        }
        with mock.patch('builtins.print'), mock.patch('builtins.input', return_value='accept'):

            KeeperApiHelper.communicate_expect(['share_account'])
            self.assertTrue(api.accept_account_transfer_consent(params))
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_decline_account_transfer_consent(self):
        params = get_connected_params()
        params.settings = {
            'must_perform_account_share_by': '1632370067000',
            'share_account_to': [{
                'role_id': 123456789,
                'public_key': vault_env.encoded_public_key
            }]
        }
        with mock.patch('builtins.print'), mock.patch('builtins.input', return_value='decline'):
            self.assertFalse(api.accept_account_transfer_consent(params))


class TestPBKDF2AuthenticationValidation:
    @pytest.mark.parametrize(('salt_bytes', 'iterations', 'message'), [
        (b'', 1, 'salt'),
        (bytes(16), 1, 'below the required minimum'),
    ])
    def test_login_rejects_weak_server_parameters_before_prompt(
            self, monkeypatch, salt_bytes, iterations, message):
        response = APIRequest_pb2.LoginResponse()
        response.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH
        salt = response.salt.add()
        salt.salt = salt_bytes
        salt.iterations = iterations

        monkeypatch.setattr(loginv3.LoginV3API, 'get_device_id', lambda *args, **kwargs: b'device')
        monkeypatch.setattr(loginv3.LoginV3API, 'startLoginMessage', lambda *args, **kwargs: response)

        class NoPasswordPrompt:
            def on_password(self, _step):
                pytest.fail('Commander prompted before validating the server KDF parameters')

        with pytest.raises(ValueError, match=message):
            loginv3.LoginV3Flow(login_ui=NoPasswordPrompt()).login(KeeperParams())

    def test_reentry_rejects_weak_server_parameters_before_sending_hash(self, monkeypatch):
        params = KeeperParams()
        params.user = 'user@example.com'
        params.session_token = 'test-session'
        params.settings = {}
        endpoints = []

        def fake_communicate_rest(_params, _request, endpoint, **_kwargs):
            endpoints.append(endpoint)
            if endpoint == 'authentication/get_salt_and_iterations':
                salt = APIRequest_pb2.Salt()
                salt.salt = bytes(16)
                salt.iterations = 1
                return salt
            pytest.fail(f'Unexpected endpoint: {endpoint}')

        monkeypatch.setattr(enforcement.api, 'communicate_rest', fake_communicate_rest)
        monkeypatch.setattr(enforcement.getpass, 'getpass', lambda prompt='': 'test-password')

        assert enforcement.MasterPasswordReentryEnforcer._validate_master_or_alternate_password(params) is False
        assert endpoints == ['authentication/get_salt_and_iterations']

    def test_reentry_uses_cached_account_iterations_instead_of_server_floor(self, monkeypatch):
        params = KeeperParams()
        params.user = 'user@example.com'
        params.session_token = 'test-session'
        params.settings = {}
        params.salt = b'0123456789abcdef'
        params.iterations = 1_100_000
        endpoints = []
        derived_iterations = []

        def fake_derive_keyhash_v1(_password, _salt, iterations):
            derived_iterations.append(iterations)
            return b'test-auth-hash'

        def fake_communicate_rest(_params, request, endpoint, **_kwargs):
            endpoints.append(endpoint)
            if endpoint == 'authentication/get_salt_and_iterations':
                # If queried, this is a downgrade from the established account count.
                salt = APIRequest_pb2.Salt()
                salt.salt = params.salt
                salt.iterations = 1_000_000
                return salt
            if endpoint == 'authentication/validate_master_password':
                response = APIRequest_pb2.MasterPasswordReentryResponse()
                response.status = APIRequest_pb2.MP_SUCCESS
                assert request.pbkdf2Password
                return response
            pytest.fail(f'Unexpected endpoint: {endpoint}')

        monkeypatch.setattr(enforcement.api, 'communicate_rest', fake_communicate_rest)
        monkeypatch.setattr(enforcement.getpass, 'getpass', lambda prompt='': 'test-password')
        monkeypatch.setattr(enforcement.crypto, 'derive_keyhash_v1', fake_derive_keyhash_v1)

        assert enforcement.MasterPasswordReentryEnforcer._validate_master_or_alternate_password(params) is True
        assert derived_iterations == [1_100_000]
        assert endpoints == ['authentication/validate_master_password']

    def test_alternate_password_derivation_rejects_weak_parameters(self):
        params = KeeperParams()
        params.password = 'test-password'
        params.salt = bytes(16)
        params.iterations = 1
        response = APIRequest_pb2.LoginResponse()
        response.encryptedDataKeyType = APIRequest_pb2.BY_ALTERNATE

        with pytest.raises(ValueError, match='below the required minimum'):
            loginv3.LoginV3Flow.get_data_key(params, response)

    def test_account_recovery_rejects_weak_answer_before_sending_hash(self, monkeypatch):
        params = KeeperParams()
        endpoints = []

        def fake_communicate_rest(_params, _request, endpoint, **_kwargs):
            endpoints.append(endpoint)
            if endpoint == 'authentication/account_recovery_verify_code':
                response = APIRequest_pb2.AccountRecoveryVerifyCodeResponse()
                response.backupKeyType = APIRequest_pb2.BKT_SEC_ANSWER
                response.securityQuestion = 'Test question'
                response.salt = bytes(16)
                response.iterations = 1
                return response
            return None

        monkeypatch.setattr(loginv3.api, 'communicate_rest', fake_communicate_rest)
        monkeypatch.setattr('builtins.input', lambda _prompt='': 'test-code')
        monkeypatch.setattr(loginv3.getpass, 'getpass', lambda **_kwargs: 'test-answer')

        with pytest.raises(ValueError, match='below the required minimum'):
            loginv3.LoginV3Flow().handle_account_recovery(params, b'login-token')
        assert endpoints == [
            'authentication/master_password_recovery_verification_v2',
            'authentication/account_recovery_verify_code',
        ]

    @pytest.mark.parametrize('payload', [b'', bytes(99)])
    def test_login_rejects_malformed_encryption_params(self, payload):
        params = KeeperParams()
        params.iterations = 1_000_000
        response = APIRequest_pb2.LoginResponse()
        response.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
        response.encryptedDataKey = payload

        with pytest.raises(ValueError, match='Invalid encrypted data key parameters'):
            loginv3.LoginV3Flow.get_data_key(params, response)

    def test_login_rejects_encryption_iteration_mismatch(self):
        params = KeeperParams()
        params.iterations = 1_000_000
        response = APIRequest_pb2.LoginResponse()
        response.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
        response.encryptedDataKey = b'\x01' + (1_000_001).to_bytes(3, byteorder='big') + bytes(96)

        with pytest.raises(ValueError, match='do not match'):
            loginv3.LoginV3Flow.get_data_key(params, response)

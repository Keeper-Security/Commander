from unittest import TestCase, mock
from collections import namedtuple

import pytest

from data_vault import VaultEnvironment, get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import api, constants, enforcement, generator, loginv3, utils
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

    def test_login_allows_legacy_100k_iterations(self, monkeypatch):
        params = KeeperParams()
        params.user = 'legacy@example.com'
        params.config = {}
        response = APIRequest_pb2.LoginResponse()
        response.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH
        salt = response.salt.add()
        salt.salt = b'0123456789abcdef'
        salt.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS

        rejected_response = APIRequest_pb2.LoginResponse()
        rejected_response.loginState = APIRequest_pb2.ACCOUNT_LOCKED
        sent_iterations = []

        monkeypatch.setattr(loginv3.LoginV3API, 'get_device_id', lambda *args, **kwargs: b'device')
        monkeypatch.setattr(loginv3.LoginV3API, 'startLoginMessage', lambda *args, **kwargs: response)

        def fake_derive_keyhash_v1(_password, _salt, iterations):
            sent_iterations.append(iterations)
            return b'test-auth-hash'

        def fake_validate_auth_hash(_params, _token):
            return rejected_response

        monkeypatch.setattr(loginv3.crypto, 'derive_keyhash_v1', fake_derive_keyhash_v1)
        monkeypatch.setattr(loginv3.LoginV3API, 'validateAuthHashMessage', fake_validate_auth_hash)

        class PasswordUi:
            def on_password(self, step):
                step.verify_password('legacy-password')

        with pytest.raises(Exception, match='LOCKED'):
            loginv3.LoginV3Flow(login_ui=PasswordUi()).login(params)
        assert sent_iterations == [constants.PBKDF2_LEGACY_MIN_ITERATIONS]

    def test_login_rejects_count_below_previously_seen_count(self, monkeypatch):
        params = KeeperParams()
        params.user = 'legacy@example.com'
        params.config = {
            'pbkdf2_iterations': {
                'legacy@example.com': {'master': constants.PBKDF2_ITERATIONS}
            }
        }
        response = APIRequest_pb2.LoginResponse()
        response.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH
        salt = response.salt.add()
        salt.salt = b'0123456789abcdef'
        salt.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS

        monkeypatch.setattr(loginv3.LoginV3API, 'get_device_id', lambda *args, **kwargs: b'device')
        monkeypatch.setattr(loginv3.LoginV3API, 'startLoginMessage', lambda *args, **kwargs: response)

        class NoPasswordPrompt:
            def on_password(self, _step):
                pytest.fail('Commander prompted before checking the stored iteration count')

        with pytest.raises(ValueError, match='required minimum of 1000000'):
            loginv3.LoginV3Flow(login_ui=NoPasswordPrompt()).login(params)

    def test_successful_legacy_login_remembers_count_and_offers_upgrade(self, monkeypatch):
        params = KeeperParams()
        params.user = 'legacy@example.com'
        params.password = 'legacy-password'
        params.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
        params.config = {}
        data_key = bytes(range(32))
        upgrade_calls = []
        response = APIRequest_pb2.LoginResponse()
        response.primaryUsername = params.user
        response.encryptedSessionToken = b'encrypted-session'
        response.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
        response.encryptedDataKey = utils.create_encryption_params(
            params.password, bytes(16), params.iterations, data_key)

        monkeypatch.setattr(loginv3.LoginV3Flow, 'populateAccountSummary', lambda _params: None)
        monkeypatch.setattr(loginv3.loader, 'store_config_properties', lambda _params: None)
        monkeypatch.setattr(loginv3.sys, 'stdin', type('InteractiveInput', (), {'isatty': lambda _self: True})())
        monkeypatch.setattr('builtins.input', lambda _prompt='': 'yes')

        def fake_change_master_password(_params):
            upgrade_calls.append(True)
            _params.iterations = constants.PBKDF2_ITERATIONS
            utils.store_pbkdf2_iterations(
                _params.config, _params.user, _params.iterations, 'master')

        monkeypatch.setattr(
            loginv3.LoginV3Flow, 'change_master_password',
            staticmethod(fake_change_master_password))

        loginv3.LoginV3Flow.post_login_processing(params, response)

        assert params.data_key == data_key
        assert upgrade_calls == [True]
        assert utils.get_stored_pbkdf2_iterations(
            params.config, params.user, 'master') == constants.PBKDF2_ITERATIONS

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

    def test_persistent_reentry_rejects_count_below_stored_account_count(self, monkeypatch):
        params = KeeperParams()
        params.user = 'user@example.com'
        params.session_token = 'test-session'
        params.settings = {}
        params.config = {
            'pbkdf2_iterations': {
                'user@example.com': {'master': constants.PBKDF2_ITERATIONS}
            }
        }
        endpoints = []

        def fake_communicate_rest(_params, _request, endpoint, **_kwargs):
            endpoints.append(endpoint)
            salt = APIRequest_pb2.Salt()
            salt.salt = b'0123456789abcdef'
            salt.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
            return salt

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

    def test_account_recovery_accepts_legacy_100k_parameters(self, monkeypatch):
        params = KeeperParams()
        endpoints = []
        derived_iterations = []
        recovery_phrase = 'legacy recovery answer'
        data_key = bytes(range(32))

        def fake_communicate_rest(_params, request, endpoint, **_kwargs):
            endpoints.append(endpoint)
            if endpoint == 'authentication/master_password_recovery_verification_v2':
                return None
            if endpoint == 'authentication/account_recovery_verify_code':
                response = APIRequest_pb2.AccountRecoveryVerifyCodeResponse()
                response.backupKeyType = APIRequest_pb2.BKT_SEC_ANSWER
                response.securityQuestion = 'Test question'
                response.salt = b'0123456789abcdef'
                response.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
                return response
            if endpoint == 'authentication/get_data_key_backup_v3':
                assert request.securityAnswerHash
                response = APIRequest_pb2.GetDataKeyBackupV3Response()
                response.dataKeyBackup = utils.create_encryption_params(
                    recovery_phrase, bytes(16), constants.PBKDF2_LEGACY_MIN_ITERATIONS, data_key)
                response.encryptedSessionToken = b'encrypted-session'
                response.minimumPbkdf2Iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
                return response
            pytest.fail(f'Unexpected endpoint: {endpoint}')

        original_derive = loginv3.crypto.derive_keyhash_v1

        def capture_derive(password, salt, iterations):
            derived_iterations.append(iterations)
            return original_derive(password, salt, iterations)

        monkeypatch.setattr(loginv3.api, 'communicate_rest', fake_communicate_rest)
        monkeypatch.setattr(loginv3.crypto, 'derive_keyhash_v1', capture_derive)
        monkeypatch.setattr('builtins.input', lambda _prompt='': 'test-code')
        monkeypatch.setattr(loginv3.getpass, 'getpass', lambda **_kwargs: recovery_phrase)
        monkeypatch.setattr(loginv3.LoginV3Flow, 'change_master_password', lambda *_args: True)
        flow = loginv3.LoginV3Flow()
        monkeypatch.setattr(flow, 'login', lambda _params: None)

        flow.handle_account_recovery(params, b'login-token')

        assert derived_iterations == [constants.PBKDF2_LEGACY_MIN_ITERATIONS]
        assert params.data_key == data_key
        assert endpoints == [
            'authentication/master_password_recovery_verification_v2',
            'authentication/account_recovery_verify_code',
            'authentication/get_data_key_backup_v3',
        ]

    @pytest.mark.parametrize('payload', [b'', bytes(99), b'\x02' + bytes(99)])
    def test_login_rejects_malformed_encryption_params(self, payload):
        params = KeeperParams()
        params.iterations = 1_000_000
        response = APIRequest_pb2.LoginResponse()
        response.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
        response.encryptedDataKey = payload

        expected_message = 'Unsupported encryption params version' if payload[:1] == b'\x02' else 'bad params length'
        with pytest.raises(ValueError, match=expected_message):
            loginv3.LoginV3Flow.get_data_key(params, response)

    def test_login_accepts_independent_auth_and_encryption_iterations(self):
        params = KeeperParams()
        params.password = 'test-password'
        params.iterations = 1_000_000
        data_key = bytes(range(32))
        response = APIRequest_pb2.LoginResponse()
        response.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
        response.encryptedDataKey = utils.create_encryption_params(
            params.password, b'0123456789abcdef', constants.PBKDF2_LEGACY_MIN_ITERATIONS, data_key)

        loginv3.LoginV3Flow.get_data_key(params, response)
        assert params.data_key == data_key

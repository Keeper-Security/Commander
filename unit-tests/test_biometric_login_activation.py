import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip('fido2')

from keepercommander import crypto, utils
from keepercommander.biometric import check_biometric_previously_used, sync_biometric_passkey_status
from keepercommander.biometric.client import BiometricClient
from keepercommander.biometric.commands.unregister import BiometricUnregisterCommand
from keepercommander.biometric.platforms.macos.handler import MacOSStorageHandler
from keepercommander.biometric.platforms.windows import WindowsStorageHandler
from keepercommander.error import KeeperApiError
from keepercommander.loginv3 import LoginV3API, LoginV3Flow
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2


@pytest.fixture(params=['macos', 'windows'])
def storage(request, tmp_path):
    if request.param == 'macos':
        handler = MacOSStorageHandler()
        handler.prefs_path = str(tmp_path / 'biometric.plist')
        yield handler
    else:
        values = {}

        def query(key, name):
            if name not in values:
                raise FileNotFoundError(name)
            return values[name]

        def delete(key, name):
            if name not in values:
                raise FileNotFoundError(name)
            del values[name]

        winreg = SimpleNamespace(
            REG_SZ=1, REG_DWORD=4, QueryValueEx=query, DeleteValue=delete,
            SetValueEx=lambda key, name, reserved, kind, value: values.update({name: (value, kind)}))

        @contextmanager
        def registry_key():
            yield 'key'

        handler = WindowsStorageHandler()
        with patch.dict(sys.modules, winreg=winreg), patch.object(handler, 'registry_key', registry_key):
            yield handler


@pytest.fixture
def params():
    params = KeeperParams()
    params.user = 'user@example.com'
    params.session_token = 'session'
    params.device_token = utils.base64_url_encode(b'device-token')
    params.device_private_key = utils.base64_url_encode(crypto.unload_ec_private_key(crypto.generate_ec_key()[0]))
    params.data_key = b'k' * 32
    return params


@pytest.fixture
def client(storage):
    handler = SimpleNamespace(storage_handler=storage, get_biometric_flag=storage.get_biometric_flag)
    with patch('keepercommander.biometric.client.BiometricDetector') as detector:
        detector.return_value.get_platform_handler.return_value = handler
        yield BiometricClient()


def test_account_flag_is_not_a_credential_id(storage, params):
    assert not storage.get_biometric_flag(params.user)
    assert storage.store_biometric_flag(params.user)
    assert storage.get_biometric_flag(params.user)
    assert storage.get_credential_id(params.user) is None
    assert not storage.get_biometric_flag('other@example.com')
    assert storage.delete_biometric_flag(params.user)
    assert not storage.get_biometric_flag(params.user)


def test_macos_flag_survives_new_storage_instance(tmp_path, params):
    storage = MacOSStorageHandler()
    storage.prefs_path = str(tmp_path / 'biometric.plist')
    assert storage.store_biometric_flag(params.user)
    reloaded = MacOSStorageHandler()
    reloaded.prefs_path = storage.prefs_path
    assert reloaded.get_biometric_flag(params.user)
    assert reloaded.get_credential_id(params.user) is None


def test_account_flag_does_not_claim_server_credential_for_unregistration(client, storage, params):
    storage.store_biometric_flag(params.user)
    with patch('keepercommander.biometric.commands.base.BiometricClient', return_value=client):
        command = BiometricUnregisterCommand()
    with patch.object(client, 'disable_passkey') as disable:
        command._disable_server_passkeys(params)
    disable.assert_not_called()


def test_account_sync_preserves_legacy_local_credential(storage, params):
    assert storage.store_credential_id(params.user, 'local-credential-id')
    assert storage.get_biometric_flag(params.user)
    assert storage.store_biometric_flag(params.user)
    assert storage.get_credential_id(params.user) == 'local-credential-id'
    assert storage.delete_biometric_flag(params.user)
    assert not storage.get_biometric_flag(params.user)


def test_registration_can_replace_account_flag(storage, params):
    assert storage.store_biometric_flag(params.user)
    assert storage.store_credential_id(params.user, 'new-credential')
    assert storage.get_credential_id(params.user) == 'new-credential'


def test_sync_existing_passkey_registers_encrypted_device_data_key(client, storage, params):
    response = APIRequest_pb2.PasskeyListResponse()
    response.passkeyInfo.add(credentialId=b'existing-security-key')

    def communicate(params, request, endpoint, **kwargs):
        if endpoint == 'authentication/passkey/get_available_keys':
            return response
        assert endpoint == 'authentication/register_encrypted_data_key_for_device'
        assert request.encryptedDeviceToken == b'device-token'
        private_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
        assert crypto.decrypt_ec(request.encryptedDeviceDataKey, private_key) == params.data_key
        # Only cache the flag after registering the data key.
        assert not storage.get_biometric_flag(params.user)

    with patch('keepercommander.biometric.BiometricClient', return_value=client), \
            patch('keepercommander.api.communicate_rest', side_effect=communicate) as api:
        sync_biometric_passkey_status(params)
    assert api.call_count == 2
    assert storage.get_biometric_flag(params.user)
    assert storage.get_credential_id(params.user) is None


@pytest.mark.parametrize('legacy', [False, True])
def test_sync_accepts_device_data_key_already_registered(client, storage, params, legacy):
    if legacy:
        storage.store_credential_id(params.user, 'local-credential')
    response = APIRequest_pb2.PasskeyListResponse()
    response.passkeyInfo.add(credentialId=b'existing-key')
    with patch('keepercommander.biometric.BiometricClient', return_value=client), \
            patch('keepercommander.api.communicate_rest', side_effect=[
                response, KeeperApiError('device_data_key_exists', 'Already registered')]):
        sync_biometric_passkey_status(params)
    assert storage.get_biometric_flag(params.user)
    assert storage.get_credential_id(params.user) == ('local-credential' if legacy else None)


@pytest.mark.parametrize('legacy', [False, True])
def test_sync_clears_cached_state_when_no_active_passkeys(client, storage, params, legacy):
    if legacy:
        storage.store_credential_id(params.user, 'old-credential')
    else:
        storage.store_biometric_flag(params.user)
    with patch('keepercommander.biometric.BiometricClient', return_value=client), \
            patch.object(client, 'get_available_credentials', return_value=[]), \
            patch.object(LoginV3API, 'register_encrypted_data_key_for_device') as register:
        sync_biometric_passkey_status(params)
    assert not storage.get_biometric_flag(params.user)
    assert storage.get_credential_id(params.user) is None
    register.assert_not_called()


@pytest.mark.parametrize('cached', [False, True])
@pytest.mark.parametrize('failure', ['list', 'device-key'])
def test_sync_failure_preserves_cache_and_retries(client, storage, params, cached, failure):
    if cached:
        storage.store_biometric_flag(params.user)
    with patch('keepercommander.biometric.BiometricClient', return_value=client), \
            patch.object(client, 'get_available_credentials', return_value=[{'credential_id': b'key'}]) as available, \
            patch.object(LoginV3API, 'register_encrypted_data_key_for_device') as register:
        failing_call = available if failure == 'list' else register
        failing_call.side_effect = KeeperApiError('server_error', 'Unavailable')
        sync_biometric_passkey_status(params)
        assert storage.get_biometric_flag(params.user) == cached
        failing_call.side_effect = None
        sync_biometric_passkey_status(params)
    assert storage.get_biometric_flag(params.user)


def test_unsupported_platform_skips_sync(params):
    with patch('keepercommander.biometric.BiometricClient') as client:
        client.return_value.platform_handler = None
        sync_biometric_passkey_status(params)
    client.return_value.get_available_credentials.assert_not_called()


@pytest.mark.parametrize('sso', [False, True])
def test_successful_login_syncs_after_account_summary(params, sso):
    params.sso_login_info = {'is_cloud': True} if sso else None
    response = APIRequest_pb2.LoginResponse(
        primaryUsername=params.user, encryptedSessionToken=b'session', sessionTokenType=APIRequest_pb2.NO_RESTRICTION)

    def sync(actual_params):
        summary.assert_called_once_with(params)
        assert actual_params.session_token
        assert actual_params.data_key
        assert actual_params.password is None

    with patch.object(LoginV3Flow, 'get_data_key', return_value='SSO Login' if sso else 'Master Password'), \
            patch.object(LoginV3Flow, 'populateAccountSummary') as summary, \
            patch('keepercommander.loginv3.loader.store_config_properties'), \
            patch('keepercommander.biometric.sync_biometric_passkey_status', side_effect=sync) as synchronize:
        assert LoginV3Flow.post_login_processing(params, response)
    synchronize.assert_called_once_with(params)


def test_restricted_login_does_not_activate_passkeys(params):
    response = APIRequest_pb2.LoginResponse(
        primaryUsername=params.user, encryptedSessionToken=b'session', sessionTokenType=APIRequest_pb2.RESTRICT)
    with patch.object(LoginV3Flow, 'get_data_key', return_value='Master Password'), \
            patch.object(LoginV3Flow, 'populateAccountSummary'), \
            patch('keepercommander.loginv3.loader.store_config_properties'), \
            patch('keepercommander.biometric.sync_biometric_passkey_status') as synchronize:
        with pytest.raises(Exception, match='expired'):
            LoginV3Flow.post_login_processing(params, response)
    synchronize.assert_not_called()


def test_next_login_uses_existing_passkey_without_registration(client, storage, params):
    with patch('keepercommander.biometric.BiometricClient', return_value=client), \
            patch.object(client, 'get_available_credentials', return_value=[{'credential_id': b'key'}]), \
            patch.object(LoginV3API, 'register_encrypted_data_key_for_device'):
        sync_biometric_passkey_status(params)

    params.session_token = None
    with patch('keepercommander.biometric.BiometricDetector') as detector, \
            patch.object(LoginV3API, 'get_device_id', return_value=b'device-token'), \
            patch.object(LoginV3API, 'startLoginMessage', return_value=APIRequest_pb2.LoginResponse(
                loginState=APIRequest_pb2.REQUIRES_AUTH_HASH)), \
            patch.object(LoginV3API, 'resume_login', return_value=APIRequest_pb2.LoginResponse(
                loginState=APIRequest_pb2.LOGGED_IN)) as resume, \
            patch.object(LoginV3Flow, 'post_login_processing'), \
            patch('keepercommander.biometric.commands.verify.BiometricVerifyCommand.biometric_authenticate',
                  return_value={'is_valid': True, 'login_token': b'passkey-login'}) as authenticate, \
            patch.object(BiometricClient, 'generate_registration_options') as register:
        detector.return_value.get_platform_handler.return_value = client.platform_handler
        assert check_biometric_previously_used(params.user)
        LoginV3Flow().login(params)
    authenticate.assert_called_once_with(params, username=params.user)
    resume.assert_called_once_with(params, b'passkey-login', b'device-token', loginType='PASSKEY_BIO')
    register.assert_not_called()


@pytest.mark.parametrize('failure', [None, Exception('Key unavailable'), KeyboardInterrupt()])
def test_automatically_enabled_login_retains_default_fallback(client, storage, params, failure):
    storage.store_biometric_flag(params.user)
    params.session_token = None
    with patch('keepercommander.biometric.BiometricDetector') as detector, \
            patch.object(LoginV3API, 'get_device_id', return_value=b'device-token'), \
            patch.object(LoginV3API, 'startLoginMessage', side_effect=[
                APIRequest_pb2.LoginResponse(loginState=APIRequest_pb2.REQUIRES_AUTH_HASH),
                APIRequest_pb2.LoginResponse(loginState=APIRequest_pb2.LOGGED_IN)]) as start, \
            patch.object(LoginV3Flow, 'post_login_processing') as post_login, \
            patch('keepercommander.biometric.commands.verify.BiometricVerifyCommand.biometric_authenticate',
                  side_effect=failure, return_value={'is_valid': False}):
        detector.return_value.get_platform_handler.return_value = client.platform_handler
        LoginV3Flow().login(params)
    assert start.call_count == 2
    post_login.assert_called_once()
    assert storage.get_biometric_flag(params.user)

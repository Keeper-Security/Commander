import json
import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
)

from keepercommander import rest_api, utils
from keepercommander.params import KeeperParams
from keepercommander.error import CommandError
from keepercommander.proto import APIRequest_pb2
from keepercommander.biometric.client import BiometricClient
from keepercommander.biometric.commands.register import BiometricRegisterCommand
from keepercommander.biometric.platforms.macos.handler import MacOSHandler
from keepercommander.biometric.platforms.macos.passkey import MacOSPasskeyWebAuthnClient
from keepercommander.biometric.platforms.windows import WindowsHandler
from keepercommander.biometric.platforms.security_key import (
    SecurityKeyInteraction, create_security_key_client, get_security_key_devices,
)
from keepercommander.biometric.utils.error_handler import BiometricErrorHandler


@pytest.fixture
def params():
    params = KeeperParams()
    params.user = 'user@example.com'
    params.device_token = utils.base64_url_encode(b'device-token')
    return params


@pytest.fixture
def client():
    with patch('keepercommander.biometric.client.BiometricDetector'):
        return BiometricClient()


def test_registration_requests_all_authenticator_types(client, params):
    response = APIRequest_pb2.PasskeyRegistrationResponse(
        challengeToken=b'challenge', pkCreationOptions=json.dumps({'challenge': 'abc'}))
    with patch('keepercommander.biometric.client.api.communicate_rest', return_value=response) as communicate:
        options = client.generate_registration_options(params)
    request = communicate.call_args.args[1]
    assert request.authenticatorAttachment == APIRequest_pb2.AuthenticatorAttachment.ALL_SUPPORTED
    assert communicate.call_args.args[2] == 'authentication/passkey/generate_registration'
    assert options == {'challenge_token': b'challenge', 'creation_options': {'challenge': 'abc'}}


@pytest.mark.parametrize('purpose, expected', [
    ('login', APIRequest_pb2.PasskeyPurpose.PK_LOGIN),
    ('vault', APIRequest_pb2.PasskeyPurpose.PK_REAUTH),
])
def test_authentication_requests_all_authenticator_types(client, params, purpose, expected):
    response = APIRequest_pb2.PasskeyAuthenticationResponse(
        challengeToken=b'challenge', pkRequestOptions='{}', encryptedLoginToken=b'login')
    with patch('keepercommander.biometric.client.api.communicate_rest', return_value=response) as communicate:
        options = client.generate_authentication_options(params, purpose)
    request = communicate.call_args.args[1]
    assert request.authenticatorAttachment == APIRequest_pb2.AuthenticatorAttachment.ALL_SUPPORTED
    assert request.username == params.user
    assert request.clientVersion == rest_api.CLIENT_VERSION
    assert request.encryptedDeviceToken == b'device-token'
    assert request.passkeyPurpose == expected
    assert options['login_token'] == b'login'


def creation_options(attachment=None):
    options = {
        'rp': {'id': 'keepersecurity.com', 'name': 'Keeper'},
        'user': {'id': utils.base64_url_encode(b'user'), 'name': 'user', 'displayName': 'User'},
        'challenge': b'challenge',
        'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}],
    }
    if attachment:
        options['authenticatorSelection'] = {'authenticatorAttachment': attachment}
    return options


@pytest.mark.parametrize('attachment', [None, 'platform', 'cross-platform'])
def test_creation_preserves_server_attachment_and_requires_verification(attachment):
    options = MacOSHandler().handle_credential_creation(creation_options(attachment))
    assert options['authenticatorSelection'].get('authenticatorAttachment') == attachment
    assert options['authenticatorSelection']['userVerification'] == 'required'
    assert options['authenticatorSelection']['residentKey'] == 'required'
    assert options['user']['id'] == b'user'
    parsed = PublicKeyCredentialCreationOptions.from_dict(options)
    assert parsed.authenticator_selection.authenticator_attachment == attachment


@pytest.fixture
def mac_client():
    return MacOSPasskeyWebAuthnClient(
        MagicMock(), MagicMock(), lambda: MacOSHandler().detect_touch_id_capabilities())


def parsed_creation(attachment=None):
    return PublicKeyCredentialCreationOptions.from_dict(
        MacOSHandler().handle_credential_creation(creation_options(attachment)))


def parsed_request(transports=None):
    credential = {'id': b'credential', 'type': 'public-key'}
    if transports is not None:
        credential['transports'] = transports
    return PublicKeyCredentialRequestOptions.from_dict({
        'challenge': b'challenge', 'rpId': 'keepersecurity.com',
        'allowCredentials': [credential], 'userVerification': 'required',
    })


@contextmanager
def attached_devices():
    yield [MagicMock()]


def test_mac_cross_platform_registration_does_not_use_touch_id(mac_client):
    options = parsed_creation('cross-platform')
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create, \
            patch.object(mac_client.touch_id_client, 'make_credential') as touch_id:
        result = mac_client.make_credential(options)
    create.return_value.make_credential.assert_called_once_with(options)
    assert result == create.return_value.make_credential.return_value
    touch_id.assert_not_called()


def test_mac_platform_only_registration_does_not_enumerate_security_keys(mac_client):
    options = parsed_creation('platform')
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices') as devices, \
            patch.object(mac_client.touch_id_client, 'make_credential') as touch_id:
        mac_client.make_credential(options)
    devices.assert_not_called()
    touch_id.assert_called_once_with(options)


def test_mac_unrestricted_registration_without_touch_id_uses_security_key(mac_client):
    options = parsed_creation()
    with patch.object(MacOSHandler, 'detect_touch_id_capabilities', return_value=(False, 'No Touch ID')), \
            patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create:
        mac_client.make_credential(options)
    create.return_value.make_credential.assert_called_once_with(options)


@pytest.mark.parametrize('choice, security_key', [('s', True), ('S', True), ('t', False)])
def test_mac_registration_offers_both_authenticators(mac_client, choice, security_key):
    options = parsed_creation()
    with patch.object(MacOSHandler, 'detect_touch_id_capabilities', return_value=(True, 'Touch ID')), \
            patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.commands.base.user_choice', return_value=choice), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create, \
            patch.object(mac_client.touch_id_client, 'make_credential') as touch_id:
        mac_client.make_credential(options)
    if security_key:
        create.return_value.make_credential.assert_called_once_with(options)
        touch_id.assert_not_called()
    else:
        touch_id.assert_called_once_with(options)
        create.assert_not_called()


@pytest.mark.parametrize('transports', [None, ['usb'], ['nfc', 'usb']])
def test_mac_external_authentication_without_local_credential(mac_client, transports):
    options = parsed_request(transports)
    mac_client.keychain_manager.credential_exists.return_value = False
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create:
        mac_client.get_assertion(options)
    create.return_value.get_assertion.assert_called_once_with(options)


def test_mac_existing_touch_id_authentication_is_preserved(mac_client):
    options = parsed_request(['internal'])
    mac_client.keychain_manager.credential_exists.return_value = True
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices') as devices, \
            patch.object(mac_client.touch_id_client, 'get_assertion') as touch_id:
        mac_client.get_assertion(options)
    devices.assert_not_called()
    touch_id.assert_called_once_with(options)


def test_mac_platform_only_authentication_does_not_try_usb_key(mac_client):
    mac_client.keychain_manager.credential_exists.return_value = False
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices') as devices:
        with pytest.raises(Exception, match='No supported passkey authenticator'):
            mac_client.get_assertion(parsed_request(['internal']))
    devices.assert_not_called()


def test_mac_cross_platform_authentication_does_not_offer_excluded_local_key(mac_client):
    mac_client.keychain_manager.credential_exists.return_value = False
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create, \
            patch('keepercommander.commands.base.user_choice') as choice:
        mac_client.get_assertion(parsed_request(['usb']))
    choice.assert_not_called()
    create.return_value.get_assertion.assert_called_once()


def test_mac_discoverable_authentication_uses_security_key(mac_client):
    options = PublicKeyCredentialRequestOptions.from_dict({
        'challenge': b'challenge', 'rpId': 'keepersecurity.com', 'userVerification': 'required',
    })
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create:
        mac_client.get_assertion(options)
    create.return_value.get_assertion.assert_called_once_with(options)
    mac_client.keychain_manager.credential_exists.assert_not_called()


def test_mac_no_fallback_after_security_key_error(mac_client):
    mac_client.keychain_manager.credential_exists.return_value = True
    def wait_for_cancellation(options, event, on_verified):
        assert event.wait(2)
        raise Exception('Touch ID authentication cancelled')

    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices', attached_devices), \
            patch('keepercommander.commands.base.user_choice') as choice, \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client') as create, \
            patch.object(mac_client.touch_id_client, 'get_assertion', side_effect=wait_for_cancellation) as touch_id:
        create.return_value.get_assertion.side_effect = Exception('PIN invalid')
        create.return_value.info.versions = ['FIDO_2_1']
        with pytest.raises(Exception, match='PIN invalid'):
            mac_client.get_assertion(parsed_request())
    choice.assert_not_called()
    # Touch ID was listening concurrently, but cancelled before verification.
    touch_id.assert_called_once()


def test_no_security_key_has_actionable_error():
    with pytest.raises(Exception, match='Connect your key'):
        create_security_key_client(MagicMock(), [])


def test_security_key_client_retains_origin_validation():
    collector, device = MagicMock(), MagicMock()
    with patch('keepercommander.biometric.platforms.security_key.Fido2Client') as client:
        create_security_key_client(collector, [device])
    assert client.call_args.args == (device,)
    assert client.call_args.kwargs['client_data_collector'] is collector
    assert isinstance(client.call_args.kwargs['user_interaction'], SecurityKeyInteraction)


def test_multiple_security_keys_can_be_selected():
    devices = [MagicMock(), MagicMock()]
    with patch('builtins.input', return_value='2'), \
            patch('keepercommander.biometric.platforms.security_key.Fido2Client') as client:
        create_security_key_client(MagicMock(), devices)
    assert client.call_args.args[0] is devices[1]


@pytest.mark.parametrize('selection', ['0', '3', 'x', ''])
def test_invalid_security_key_selection_is_rejected(selection):
    with patch('builtins.input', return_value=selection), \
            patch('keepercommander.biometric.platforms.security_key.Fido2Client') as client:
        with pytest.raises(Exception, match='Invalid security key selection'):
            create_security_key_client(MagicMock(), [MagicMock(), MagicMock()])
    client.assert_not_called()


def test_security_key_pin_is_not_echoed():
    with patch('keepercommander.biometric.platforms.security_key.getpass.getpass', return_value='secret') as prompt:
        assert SecurityKeyInteraction().request_pin(None, 'keepersecurity.com') == 'secret'
    prompt.assert_called_once_with('Enter Security Key PIN: ')


def test_security_key_handles_close_on_failure():
    device = MagicMock()
    with patch('keepercommander.biometric.platforms.security_key.CtapHidDevice.list_devices', return_value=[device]):
        with pytest.raises(ValueError):
            with get_security_key_devices() as devices:
                assert devices == [device]
                raise ValueError('cancelled')
    device.close.assert_called_once()


def test_mac_capability_check_accepts_security_key_without_touch_id():
    with patch('keepercommander.biometric.platforms.macos.handler.get_security_key_devices', attached_devices), \
            patch.object(MacOSHandler, 'detect_touch_id_capabilities') as touch_id, \
            patch('keepercommander.biometric.platforms.macos.handler.platform.system', return_value='Darwin'):
        assert MacOSHandler().detect_capabilities()[0]
    touch_id.assert_not_called()


@pytest.mark.parametrize('available', [True, False])
def test_windows_capability_check_uses_webauthn_not_biometrics(available):
    native = MagicMock()
    native.WindowsClient.is_available.return_value = available
    with patch.dict(sys.modules, {'fido2.client.windows': native}), \
            patch('keepercommander.biometric.platforms.windows.os', SimpleNamespace(name='nt')), \
            patch.object(WindowsHandler, '_check_biometrics') as biometrics:
        assert WindowsHandler().detect_capabilities()[0] == available
    biometrics.assert_not_called()


def test_registration_allows_adding_key_when_already_enabled(params):
    with patch('keepercommander.biometric.commands.base.BiometricClient'), \
            patch('keepercommander.biometric.commands.base.BiometricDetector'):
        command = BiometricRegisterCommand()
    command.client.platform_handler.storage_handler.get_credential_id.return_value = 'existing'
    with patch.object(command, '_check_platform_support'):
        command._validate_prerequisites(params, {})


def test_mac_existing_local_credential_does_not_block_other_authenticators():
    handler = MacOSHandler()
    handler.keychain_manager = MagicMock()
    options = creation_options()
    options['excludeCredentials'] = [{'id': 'existing', 'type': 'public-key'}]
    prepared = handler.handle_credential_creation(options)
    assert prepared['excludeCredentials'] == options['excludeCredentials']
    handler.keychain_manager.credential_exists.assert_not_called()


@pytest.mark.parametrize('error', [
    CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED),
    ClientError(ClientError.ERR.DEVICE_INELIGIBLE, CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED)),
    Exception("(<ERR.DEVICE_INELIGIBLE: 4>, CtapError('CTAP error: 0x19 - CREDENTIAL_EXCLUDED'))"),
])
def test_excluded_security_key_has_readable_registration_error(error):
    result = BiometricErrorHandler.handle_credential_creation_error(error, 'Passkey')
    assert str(result) == (
        'This security key already has a passkey registered for this Keeper account. '
        'Use "biometric verify" to test it, or register a different security key.')
    assert 'CTAP' not in str(result)
    assert 'ERR.' not in str(result)


def test_device_ineligible_without_excluded_credential_is_not_a_duplicate():
    error = ClientError(ClientError.ERR.DEVICE_INELIGIBLE, CtapError(CtapError.ERR.NO_CREDENTIALS))
    result = BiometricErrorHandler.handle_credential_creation_error(error, 'Passkey')
    assert 'already has a passkey' not in str(result)


def test_excluded_key_does_not_store_placeholder_or_report_registration_success(client, params):
    command = object.__new__(BiometricRegisterCommand)
    command.client = client
    handler = MacOSHandler()
    handler.storage_handler = MagicMock()
    client.platform_handler = handler
    webauthn_client = MagicMock()
    webauthn_client.make_credential.side_effect = ClientError(
        ClientError.ERR.DEVICE_INELIGIBLE, CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED))
    with patch.object(command, '_check_platform_support'), \
            patch.object(client, 'generate_registration_options', return_value={
                'challenge_token': b'token', 'creation_options': creation_options('cross-platform'),
            }), \
            patch.object(handler, 'create_webauthn_client', return_value=webauthn_client), \
            patch.object(client, 'verify_registration') as verify_registration, \
            patch.object(command, '_finalize_registration') as finalize:
        with pytest.raises(CommandError, match='This security key already has a passkey registered'):
            command.execute(params, name='My key')
    verify_registration.assert_not_called()
    handler.storage_handler.store_credential_id.assert_not_called()
    finalize.assert_not_called()

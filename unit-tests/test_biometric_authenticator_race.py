import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fido2.webauthn import PublicKeyCredentialRequestOptions

from keepercommander.biometric.platforms.macos.keychain import MacOSKeychainManager
from keepercommander.biometric.platforms.macos.passkey import MacOSPasskeyWebAuthnClient
from keepercommander.biometric.platforms.macos.webauthn import MacOSTouchIDWebAuthnClient


@pytest.fixture
def options():
    return PublicKeyCredentialRequestOptions.from_dict({
        'challenge': b'challenge', 'rpId': 'keepersecurity.com',
        'allowCredentials': [{'id': b'credential', 'type': 'public-key'}],
        'userVerification': 'required', 'timeout': 2000,
    })


@pytest.fixture
def client():
    keychain = MagicMock()
    keychain.credential_exists.return_value = True
    return MacOSPasskeyWebAuthnClient(MagicMock(), keychain, lambda: (True, 'Touch ID'))


@contextmanager
def devices_attached(devices):
    yield devices


def cancelled_wait(event):
    assert event.wait(2), 'Losing authenticator was not cancelled'
    raise Exception('Authentication cancelled')


def key_client():
    key = MagicMock()
    key.info.versions = ['FIDO_2_1']
    return key


def test_touch_id_wins_without_selection_or_pin_prompt(client, options):
    device, key = MagicMock(), key_client()
    key_started = threading.Event()
    workers = []
    response = object()

    def key_selection(event):
        workers.append(threading.current_thread())
        key_started.set()
        cancelled_wait(event)

    def touch_id(options, event, on_verified):
        workers.append(threading.current_thread())
        assert key_started.wait(2)
        on_verified()
        return response

    key.selection.side_effect = key_selection
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([device])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=touch_id), \
            patch('keepercommander.commands.base.user_choice') as choice:
        assert client.get_assertion(options) is response
    choice.assert_not_called()
    key.get_assertion.assert_not_called()
    assert len(workers) == 2
    assert all(not worker.is_alive() for worker in workers)


def test_security_key_touch_wins_and_pin_runs_in_main_thread_after_cleanup(client, options):
    device, key = MagicMock(), key_client()
    platform_started = threading.Event()
    workers = []
    response = object()

    def touch_id(options, event, on_verified):
        workers.append(threading.current_thread())
        platform_started.set()
        cancelled_wait(event)

    def key_selection(event):
        workers.append(threading.current_thread())
        assert platform_started.wait(2)

    def assertion(request):
        assert threading.current_thread() is threading.main_thread()
        assert all(not worker.is_alive() for worker in workers)
        assert request.challenge == options.challenge
        assert request.rp_id == options.rp_id
        assert request.allow_credentials == options.allow_credentials
        assert request.user_verification == 'required'
        assert 0 < request.timeout <= options.timeout
        return response

    key.selection.side_effect = key_selection
    key.get_assertion.side_effect = assertion
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([device])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=touch_id), \
            patch('keepercommander.commands.base.user_choice') as choice:
        assert client.get_assertion(options) is response
    choice.assert_not_called()
    assert len(workers) == 2


def test_multiple_security_keys_listen_concurrently_without_number_prompt(client, options):
    devices = [MagicMock(), MagicMock()]
    keys = [key_client(), key_client()]
    first_started = threading.Event()
    workers = []
    client.keychain_manager.credential_exists.return_value = False

    def first_selection(event):
        workers.append(threading.current_thread())
        first_started.set()
        cancelled_wait(event)

    def second_selection(event):
        workers.append(threading.current_thread())
        assert first_started.wait(2)

    keys[0].selection.side_effect = first_selection
    keys[1].selection.side_effect = second_selection
    def create(collector, selected_devices):
        return keys[devices.index(selected_devices[0])]

    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached(devices)), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', side_effect=create), \
            patch('builtins.input') as prompt:
        assert client.get_assertion(options) is keys[1].get_assertion.return_value
    prompt.assert_not_called()
    keys[0].get_assertion.assert_not_called()
    keys[1].get_assertion.assert_called_once()
    assert all(not worker.is_alive() for worker in workers)


def test_touch_id_failure_does_not_block_security_key_selection(client, options):
    key = key_client()
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([MagicMock()])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=Exception('Touch ID unavailable')):
        assert client.get_assertion(options) is key.get_assertion.return_value


def test_chosen_platform_signing_error_is_not_hidden_by_key_cancellation(client, options):
    key = key_client()
    key_started = threading.Event()
    def key_selection(event):
        key_started.set()
        assert event.wait(2)
        raise Exception('CTAP KEEPALIVE_CANCEL')

    def touch_id(options, event, on_verified):
        assert key_started.wait(2)
        on_verified()
        raise Exception('Keychain read failed')

    key.selection.side_effect = key_selection
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([MagicMock()])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=touch_id):
        with pytest.raises(Exception, match='Keychain read failed'):
            client.get_assertion(options)
    key.get_assertion.assert_not_called()


@pytest.mark.parametrize('interrupted', [False, True])
def test_timeout_or_ctrl_c_cancels_and_joins_all_workers(client, options, interrupted):
    key = key_client()
    workers = []
    def touch_id(options, event, on_verified):
        workers.append(threading.current_thread())
        cancelled_wait(event)

    def key_selection(event):
        workers.append(threading.current_thread())
        cancelled_wait(event)

    key.selection.side_effect = key_selection
    short_options = PublicKeyCredentialRequestOptions.from_dict(dict(options, timeout=20))
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([MagicMock()])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=touch_id):
        if interrupted:
            with patch('keepercommander.biometric.platforms.macos.passkey.queue.Queue.get', side_effect=KeyboardInterrupt):
                with pytest.raises(KeyboardInterrupt):
                    client.get_assertion(short_options)
        else:
            with pytest.raises(TimeoutError, match='timed out'):
                client.get_assertion(short_options)
    key.get_assertion.assert_not_called()
    assert all(not worker.is_alive() for worker in workers)


@pytest.mark.parametrize('outcome', ['success', 'cancelled', 'timeout'])
def test_native_touch_id_context_is_invalidated(outcome):
    native = SimpleNamespace(LAPolicyDeviceOwnerAuthenticationWithBiometrics=1)
    context = MagicMock()
    cancellation = threading.Event()
    def evaluate(policy, reason, callback):
        if outcome == 'success':
            callback(True, None)
        elif outcome == 'cancelled':
            cancellation.set()

    context.evaluatePolicy_localizedReason_reply_.side_effect = evaluate
    touch = MacOSTouchIDWebAuthnClient(MagicMock(), MagicMock())
    with patch.dict(sys.modules, {'LocalAuthentication': native}):
        if outcome == 'success':
            assert touch._authenticate_with_touchid(context, 'Authenticate', 0.1, cancellation)
        else:
            with pytest.raises(Exception, match=outcome if outcome == 'cancelled' else 'timed out'):
                touch._authenticate_with_touchid(context, 'Authenticate', 0.01, cancellation)
    context.invalidate.assert_called_once()


def test_losing_touch_id_attempt_never_reads_private_key(options):
    keychain = MagicMock()
    touch = MacOSTouchIDWebAuthnClient(MagicMock(), keychain)
    def rejected_selection():
        raise Exception('Another authenticator was selected')

    with patch.object(touch, '_validate_dependencies'), \
            patch.object(touch, '_create_auth_context'), \
            patch.object(touch, '_check_biometric_availability'), \
            patch.object(touch, '_authenticate_with_touchid', return_value=True):
        with pytest.raises(Exception, match='Another authenticator was selected'):
            touch.get_assertion(options, on_verified=rejected_selection)
    keychain.load_credential.assert_not_called()


def test_keychain_eligibility_checks_metadata_not_private_key():
    keychain = MacOSKeychainManager()
    with patch('keepercommander.biometric.platforms.macos.keychain.subprocess.run',
               return_value=SimpleNamespace(returncode=0)) as run:
        assert keychain.credential_exists('credential', 'keepersecurity.com')
    assert '-w' not in run.call_args.args[0]


def test_u2f_only_device_never_runs_dummy_registration_selection(client, options):
    key = key_client()
    key.info.versions = ['U2F_V2']
    with patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key):
        with pytest.raises(Exception, match='not a U2F-only key'):
            client._authenticate_with_either(options, False, [MagicMock()])
    key.selection.assert_not_called()
    key.get_assertion.assert_not_called()


@pytest.mark.parametrize('attempt', range(5))
def test_nearly_simultaneous_touches_only_allow_one_authenticator_to_sign(client, options, attempt):
    key = key_client()
    ready = threading.Barrier(2)
    signed = []
    def touch_id(options, event, on_verified):
        ready.wait(timeout=2)
        on_verified()
        signed.append('touch_id')
        return 'touch_id'

    def key_selection(event):
        ready.wait(timeout=2)

    def key_assertion(options):
        signed.append('security_key')
        return 'security_key'

    key.selection.side_effect = key_selection
    key.get_assertion.side_effect = key_assertion
    with patch('keepercommander.biometric.platforms.macos.passkey.get_security_key_devices',
               return_value=devices_attached([MagicMock()])), \
            patch('keepercommander.biometric.platforms.macos.passkey.create_security_key_client', return_value=key), \
            patch.object(client.touch_id_client, 'get_assertion', side_effect=touch_id):
        result = client.get_assertion(options)
    assert signed == [result]


def test_touch_id_winner_reads_keychain_only_after_verification_and_claim(options):
    keychain = MagicMock()
    verified = []
    def claim():
        verified.append(True)

    def load(credential_id, rp_id, timeout):
        assert verified == [True]
        assert rp_id == options.rp_id
        assert timeout > 0
        return 'private-key'

    keychain.load_credential.side_effect = load
    touch = MacOSTouchIDWebAuthnClient(MagicMock(), keychain)
    with patch.object(touch, '_validate_dependencies'), \
            patch.object(touch, '_create_auth_context'), \
            patch.object(touch, '_check_biometric_availability'), \
            patch.object(touch, '_authenticate_with_touchid', return_value=True), \
            patch.object(touch, '_create_assertion_response', return_value='assertion') as sign:
        assert touch.get_assertion(options, on_verified=claim) == 'assertion'
    assert sign.call_args.args[0] == options.challenge
    assert sign.call_args.args[1] == options.rp_id
    assert sign.call_args.args[-1] == 'private-key'

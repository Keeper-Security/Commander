# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import importlib
import hashlib
import logging
import os
import uuid
from urllib.parse import urlparse

from .. import __version__, crypto, rest_api, utils
from ..params import KeeperParams


DEFAULT_BRIDGE_TIMEOUT_MS = None
BRIDGE_LOGIN_TIMEOUT_ENV = 'KDBC_LOGIN_TIMEOUT_MS'
DEV_BRIDGE_VERIFICATION_POLICY = 'log_only'
_ALLOWED_VERIFICATION_POLICIES = {'enforce', DEV_BRIDGE_VERIFICATION_POLICY}
_PRODUCTION_KEEPER_HOST_SUFFIXES = (
    'keepersecurity.com',
    'keepersecurity.eu',
    'keepersecurity.com.au',
    'keepersecurity.jp',
    'keepersecurity.ca',
    'govcloud.keepersecurity.us',
)
KDBC_CLIENT_NOT_ENROLLED = 'KDBC_CLIENT_NOT_ENROLLED'
KDBC_KA_LOGIN_FAILED = 'KDBC_KA_LOGIN_FAILED'
KDBC_PROTOCOL_ERROR = 'KDBC_PROTOCOL_ERROR'
KDBC_INTERNAL_ERROR = 'KDBC_INTERNAL_ERROR'
_STORE_UNAVAILABLE = object()


class DesktopBridgeLoginError(Exception):
    def __init__(self, message, code=KDBC_INTERNAL_ERROR, kind='internal_error', retryable=False,
                 actor='commander', request_id=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.kind = kind
        self.retryable = retryable
        self.actor = actor
        self.request_id = request_id

    def __str__(self):
        parts = [
            'Desktop bridge login failed:',
            f'code={self.code}',
            f'kind={self.kind}',
            f'actor={self.actor}',
            f'retryable={self.retryable}',
        ]
        if self.request_id:
            parts.append(f'request_id={self.request_id}')
        parts.append(f'message={self.message}')
        return ' '.join(parts)


def login_via_desktop(params, bridge_module=None, bridge_socket=None, timeout_ms=DEFAULT_BRIDGE_TIMEOUT_MS,
                      verification_policy=None):
    # type: (KeeperParams, object, str, int) -> None
    module = bridge_module or _load_bridge_module()
    timeout_ms = _resolve_login_timeout_ms(timeout_ms)
    logging.info(
        'Requesting Keeper Desktop bridge login approval%s.',
        f' (timeout {timeout_ms // 1000}s)' if timeout_ms else ' (press Ctrl-C to cancel)',
    )
    env_host = params.server
    client_identity = _build_client_identity(module)
    request = _build_bootstrap_request_for_device(
        module, params, _placeholder_device_credentials(module), bridge_socket, timeout_ms,
        verification_policy, client_identity)
    login_context = _prepare_via_desktop_login_context(module, params, env_host, request, client_identity)
    vault_result = login_context.vault_bootstrap
    device_credentials = login_context.device
    bootstrap_device_token = bytes(device_credentials.encrypted_device_token)
    bootstrap_device_private_key = bytes(device_credentials.device_private_key)

    vault_account_binding = getattr(vault_result, 'vault_account_binding', None)
    binding_account_uid = _adopt_vault_account_binding(params, vault_account_binding)
    _adopt_vault_ka_server(
        params,
        getattr(vault_result, 'ka_server', None) or getattr(vault_result, 'server', None),
    )
    _clear_via_desktop_transient_auth_state(params)

    vault_session_token = _decode_vault_session_token(vault_result.vault_session_token)
    message_session_uid = utils.base64_url_decode(utils.generate_uid())

    encrypted_session_token, encrypted_data_key, primary_username, account_uid = \
        _ka_login_from_existing_session_token(
            params, bootstrap_device_token, message_session_uid, vault_session_token,
        )

    _apply_ka_credentials(
        params, bootstrap_device_private_key, encrypted_session_token, encrypted_data_key,
        primary_username, account_uid,
    )
    _verify_ka_account_binding(params, binding_account_uid)
    _apply_vault_account_binding(params, vault_account_binding)
    try:
        _start_vault_lifecycle_monitor(params, module, request.config)
    except Exception:
        _clear_desktop_lifecycle_state(params)
        raise
    logging.info('Authenticated through Keeper Desktop bridge.')


def _ka_login_from_existing_session_token(params, encrypted_device_token, message_session_uid, vault_session_token):
    # type: (KeeperParams, bytes, bytes, bytes) -> tuple
    """
    Calls KA authentication/login_from_existing_session_token (protocol contract step 6).

    Header context: vault session token in ApiRequestPayload.encryptedSessionToken.
    Body: StartLoginRequest with encryptedDeviceToken, clientVersion, messageSessionUid.

    Returns (encrypted_session_token, encrypted_data_key, primary_username, account_uid).
    Raises DesktopBridgeLoginError on any failure.
    """
    from ..proto import APIRequest_pb2
    from .. import rest_api as _rest_api

    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = _rest_api.CLIENT_VERSION
    rq.encryptedDeviceToken = bytes(encrypted_device_token)
    rq.messageSessionUid = bytes(message_session_uid)
    logging.info(
        'via-desktop: KA request context server=%s user=%s account_uid=%s '
        'device_token=%s device_private_key_present=%s clone_code_present=%s '
        'message_session_uid=%s endpoint=%s',
        getattr(params, 'server', None),
        getattr(params, 'user', None) or '<unset>',
        _uid_fingerprint(getattr(params, 'account_uid_bytes', None)),
        _bytes_fingerprint(bytes(encrypted_device_token)),
        bool(getattr(params, 'device_private_key', None)),
        bool(getattr(params, 'clone_code', None)),
        _bytes_fingerprint(bytes(message_session_uid)),
        'authentication/login_from_existing_session_token',
    )

    payload = APIRequest_pb2.ApiRequestPayload()
    payload.payload = rq.SerializeToString()
    payload.encryptedSessionToken = bytes(vault_session_token)
    logging.info(
        'via-desktop: KA wrapper session token fingerprint session_token_len=%s session_token_sha12=%s',
        len(bytes(vault_session_token)),
        hashlib.sha256(bytes(vault_session_token)).hexdigest()[:12],
    )

    login_resp = _execute_login_from_existing_session_token(params, bytes(encrypted_device_token), payload)

    if login_resp.loginState != APIRequest_pb2.LoginState.Value('LOGGED_IN'):
        raise DesktopBridgeLoginError(
            f'KA login_from_existing_session_token returned unexpected login state: {login_resp.loginState}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_login_failed',
            actor='ka',
        )

    if not login_resp.encryptedSessionToken or not login_resp.encryptedDataKey:
        raise DesktopBridgeLoginError(
            'KA login_from_existing_session_token response missing required credential fields',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_login_failed',
            actor='ka',
        )

    return (
        login_resp.encryptedSessionToken,
        login_resp.encryptedDataKey,
        login_resp.primaryUsername or None,
        login_resp.accountUid or None,
    )


def _execute_login_from_existing_session_token(params, encrypted_device_token, payload):
    from ..proto import APIRequest_pb2

    try:
        rs = _execute_desktop_session_transfer(params, bytes(encrypted_device_token), payload)
    except DesktopBridgeLoginError:
        raise
    except Exception as exc:
        raise DesktopBridgeLoginError(
            f'KA login_from_existing_session_token request failed: {exc}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_login_failed',
            actor='ka',
        ) from exc

    if isinstance(rs, dict):
        raise DesktopBridgeLoginError(
            f"KA login_from_existing_session_token error: {rs.get('message') or rs.get('error') or 'unknown'}",
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_login_failed',
            actor='ka',
        )

    if not isinstance(rs, bytes):
        raise DesktopBridgeLoginError(
            'KA login_from_existing_session_token returned unexpected response type',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_login_failed',
            actor='ka',
        )

    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.ParseFromString(rs)
    return login_resp


def _execute_desktop_session_transfer(params, encrypted_device_token, payload):
    from .. import rest_api as _rest_api

    return _rest_api.execute_rest(
        params.rest_context,
        'authentication/login_from_existing_session_token',
        payload,
    )


def _device_credential_store(module):
    store_cls = getattr(module, 'DeviceCredentialStore', None)
    if not store_cls:
        return None
    try:
        return store_cls()
    except Exception as exc:
        if _is_store_unavailable_error(module, exc):
            logging.info('via-desktop: device credential store unavailable; using ephemeral device only.')
            return _STORE_UNAVAILABLE
        if _is_store_auth_failed_error(module, exc):
            raise _store_auth_failed_login_error(exc) from exc
        raise


def _prepare_via_desktop_device_credentials(module, params, env_host, client_identity):
    store = _device_credential_store(module)
    prepare = getattr(store, 'prepare_via_desktop_device_credentials', None)
    if store in (None, _STORE_UNAVAILABLE) or not prepare:
        return _register_ephemeral_device(params)

    def registrar(register_env_host, device_public_key, registrar_client_identity=None):
        return _register_device_for_public_key(
            params,
            register_env_host or env_host,
            device_public_key,
            registrar_client_identity or client_identity,
        )

    try:
        creds = prepare(env_host, registrar, client_identity=client_identity)
    except DesktopBridgeLoginError:
        raise
    except Exception as exc:
        if _is_store_unavailable_error(module, exc):
            raise _store_unavailable_login_error(exc) from exc
        if _is_store_auth_failed_error(module, exc):
            raise _store_auth_failed_login_error(exc) from exc
        if _is_ka_registration_failed_error(module, exc):
            raise _ka_registration_failed_login_error(exc) from exc
        if _is_bootstrap_device_not_for_this_account_error(module, exc):
            raise _translate_bridge_error(exc) from exc
        raise

    if not creds:
        raise DesktopBridgeLoginError(
            'Keeper Desktop bridge did not return device credentials.',
            code=KDBC_PROTOCOL_ERROR,
            kind='device_credentials_missing',
            actor='bridge',
            retryable=False,
        )

    device_token = bytes(creds.encrypted_device_token)
    device_private_key = bytes(creds.device_private_key)
    logging.info(
        'via-desktop: using KDBC-prepared Commander device for Vault KA server device_token=%s',
        _bytes_fingerprint(device_token),
    )
    return device_token, device_private_key


def _prepare_via_desktop_login_context(module, params, env_host, request, client_identity):
    store = _device_credential_store(module)
    prepare = getattr(store, 'prepare_via_desktop_login_context', None)
    logging.info(
        'via-desktop: preparing KDBC login context request_id=%s env_host=%s coordinator_available=%s',
        getattr(request, 'request_id', None),
        env_host,
        bool(prepare) and store not in (None, _STORE_UNAVAILABLE),
    )
    if store in (None, _STORE_UNAVAILABLE) or not prepare:
        device_token, device_private_key = _register_ephemeral_device(params)
        fallback_request = _build_bootstrap_request_for_device(
            module,
            params,
            module.DeviceCredentials(
                encrypted_device_token=device_token,
                device_private_key=device_private_key,
                device_public_key=crypto.unload_ec_public_key(
                    crypto.load_ec_private_key(device_private_key).public_key()
                ),
            ),
            request.config.socket_override if request.config else None,
            request.config.timeout_millis if request.config else DEFAULT_BRIDGE_TIMEOUT_MS,
            request.config.verification_policy if request.config else None,
            client_identity,
        )
        try:
            vault_result = module.BridgeClient().exchange_vault_token(fallback_request)
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

        class _FallbackLoginContext:
            pass

        context = _FallbackLoginContext()
        context.env_host = env_host
        context.device = fallback_request.device
        context.vault_bootstrap = vault_result
        context.used_cached_device = False
        context.attempted_env_hosts = []
        return context

    def registrar(register_env_host, device_public_key, registrar_client_identity=None):
        logging.info(
            'via-desktop: KDBC requested device registration env_host=%s public_key=%s',
            register_env_host or env_host,
            _bytes_fingerprint(bytes(device_public_key)),
        )
        return _register_device_for_public_key(
            params,
            register_env_host or env_host,
            device_public_key,
            registrar_client_identity or client_identity,
        )

    try:
        context = prepare(request, registrar)
        logging.info(
            'via-desktop: KDBC login context prepared request_id=%s env_host=%s used_cached_device=%s '
            'attempted_env_hosts=%s device_token=%s',
            getattr(request, 'request_id', None),
            getattr(context, 'env_host', None),
            getattr(context, 'used_cached_device', None),
            getattr(context, 'attempted_env_hosts', None),
            _bytes_fingerprint(bytes(context.device.encrypted_device_token)),
        )
        return context
    except DesktopBridgeLoginError:
        raise
    except Exception as exc:
        if _is_store_unavailable_error(module, exc):
            raise _store_unavailable_login_error(exc) from exc
        if _is_store_auth_failed_error(module, exc):
            raise _store_auth_failed_login_error(exc) from exc
        if _is_ka_registration_failed_error(module, exc):
            raise _ka_registration_failed_login_error(exc) from exc
        if _is_bootstrap_device_not_for_this_account_error(module, exc):
            raise _translate_bridge_error(exc) from exc
        raise _translate_bridge_error(exc) from exc


def _is_store_unavailable_error(module, exc):
    error_cls = getattr(module, 'DeviceCredentialStoreUnavailableError', None)
    if error_cls and isinstance(exc, error_cls):
        return True
    return getattr(exc, 'kind', None) == 'device_credential_store_unavailable'


def _is_store_auth_failed_error(module, exc):
    error_cls = getattr(module, 'DeviceCredentialStoreAuthFailedError', None)
    if error_cls and isinstance(exc, error_cls):
        return True
    return (
        getattr(exc, 'kind', None) == 'device_credential_store_auth_failed'
        or getattr(exc, 'code', None) == 'KDBC_DEVICE_CREDENTIAL_STORE_AUTH_FAILED'
    )


def _is_ka_registration_failed_error(module, exc):
    error_cls = getattr(module, 'KARegistrationFailedError', None)
    if error_cls and isinstance(exc, error_cls):
        return True
    return (
        getattr(exc, 'kind', None) == 'ka_registration_failed'
        or getattr(exc, 'code', None) == 'KDBC_KA_REGISTRATION_FAILED'
    )


def _ka_registration_failed_login_error(exc):
    return DesktopBridgeLoginError(
        getattr(exc, 'message', None) or str(exc) or 'KA device registration failed.',
        code=getattr(exc, 'code', None) or 'KDBC_KA_REGISTRATION_FAILED',
        kind=getattr(exc, 'kind', None) or 'ka_registration_failed',
        actor=getattr(exc, 'actor', None) or 'ka',
        retryable=bool(getattr(exc, 'retryable', False)),
    )


def _is_bootstrap_device_not_for_this_account_error(module, exc):
    error_cls = getattr(module, 'BootstrapDeviceNotForThisAccountError', None)
    if error_cls and isinstance(exc, error_cls):
        return True
    return (
        getattr(exc, 'kind', None) == 'bootstrap_device_not_for_this_account'
        or getattr(exc, 'code', None) in {
            'KDBC_BOOTSTRAP_DEVICE_NOT_FOR_THIS_ACCOUNT',
            'KDBC_BOOTSTRAP_DEVICE_NOT_FOR_ACCOUNT',
        }
    )


def _store_auth_failed_login_error(exc):
    return DesktopBridgeLoginError(
        'Device credential store authentication was denied.',
        code=getattr(exc, 'code', None) or 'KDBC_DEVICE_CREDENTIAL_STORE_AUTH_FAILED',
        kind=getattr(exc, 'kind', None) or 'device_credential_store_auth_failed',
        actor=getattr(exc, 'actor', None) or 'commander',
        retryable=False,
    )


def _store_unavailable_login_error(exc):
    return DesktopBridgeLoginError(
        getattr(exc, 'message', None) or str(exc) or 'Device credential store is unavailable.',
        code=getattr(exc, 'code', None) or 'KDBC_DEVICE_CREDENTIAL_STORE_UNAVAILABLE',
        kind=getattr(exc, 'kind', None) or 'device_credential_store_unavailable',
        actor=getattr(exc, 'actor', None) or 'leaf',
        retryable=bool(getattr(exc, 'retryable', False)),
    )


def _load_cached_device_credentials(module, store, env_host):
    if store in (None, _STORE_UNAVAILABLE):
        return store
    try:
        creds = store.load(env_host)
    except Exception as exc:
        if _is_store_unavailable_error(module, exc):
            logging.info('via-desktop: device credential store unavailable; using ephemeral device only.')
            return _STORE_UNAVAILABLE
        if _is_store_auth_failed_error(module, exc):
            raise _store_auth_failed_login_error(exc) from exc
        raise DesktopBridgeLoginError(
            f'Device credential store load failed: {_safe_exception_message(exc)}',
            code=KDBC_INTERNAL_ERROR,
            kind='device_credential_store_error',
            actor='commander',
        ) from exc
    if not creds:
        return None
    device_token = bytes(creds.encrypted_device_token)
    device_private_key = bytes(creds.device_private_key)
    logging.info(
        'via-desktop: using cached Commander device for Vault KA server device_token=%s',
        _bytes_fingerprint(device_token),
    )
    return device_token, device_private_key


def _save_cached_device_credentials(module, store, env_host, device_token, device_private_key):
    if store in (None, _STORE_UNAVAILABLE):
        return
    try:
        creds = module.DeviceCredentials(
            encrypted_device_token=bytes(device_token),
            device_private_key=bytes(device_private_key),
            device_public_key=crypto.unload_ec_public_key(
                crypto.load_ec_private_key(bytes(device_private_key)).public_key()
            ),
        )
        store.save(env_host, creds)
        logging.info('via-desktop: cached Commander device for Vault KA server %s.', env_host)
    except Exception as exc:
        if _is_store_auth_failed_error(module, exc):
            raise _store_auth_failed_login_error(exc) from exc
        if _is_store_unavailable_error(module, exc):
            logging.info(
                'via-desktop: device credential store unavailable during save; continuing with in-memory session.'
            )
            return
        logging.info(
            'via-desktop: device credential store save failed; continuing with in-memory session: %s',
            _safe_exception_message(exc),
        )


def _delete_cached_device_credentials(store, env_host):
    if store in (None, _STORE_UNAVAILABLE):
        return
    try:
        store.delete(env_host)
        logging.info('via-desktop: deleted rejected cached Commander device for Vault KA server %s.', env_host)
    except Exception as exc:
        logging.info(
            'via-desktop: device credential store delete failed: %s',
            _safe_exception_message(exc),
        )


def _is_cached_credential_rejection(exc):
    message = str(exc).lower()
    kind = str(getattr(exc, 'kind', '')).lower()
    return (
        'login state: 17' in message
    ) or (
        'device' in message and (
            'not registered' in message
            or 'not known' in message
            or 'invalid device' in message
            or 'data key' in message
        )
    ) or kind in {
        'ka_device_registration_failed',
        'ka_device_data_key_required',
    }


def _safe_exception_message(exc):
    message = str(exc).strip()
    if message:
        return message
    result_code = getattr(exc, 'result_code', None)
    if result_code:
        return str(result_code)
    return exc.__class__.__name__


def _decode_vault_session_token(value):
    if value is None:
        return b''
    if isinstance(value, str):
        text = value.strip()
    else:
        raw = bytes(value)
        try:
            text = raw.decode('ascii').strip()
        except UnicodeDecodeError:
            return raw
    if not text:
        return b''
    import base64
    padding = '=' * (-len(text) % 4)
    try:
        return base64.b64decode(text + padding, validate=True)
    except Exception:
        return utils.base64_url_decode(text)


def _load_bridge_module():
    try:
        return importlib.import_module('keeper_desktop_bridge_client')
    except ImportError as exc:
        raise DesktopBridgeLoginError(
            'Python package keeper_desktop_bridge_client is not available.',
            code=KDBC_INTERNAL_ERROR,
            kind='dependency_missing',
            actor='commander'
        ) from exc


def _resolve_login_timeout_ms(timeout_ms):
    env_value = os.environ.get(BRIDGE_LOGIN_TIMEOUT_ENV)
    if env_value:
        try:
            timeout_ms = int(env_value)
        except ValueError:
            logging.warning('Ignoring invalid %s value: %s', BRIDGE_LOGIN_TIMEOUT_ENV, env_value)
    if timeout_ms is not None and timeout_ms <= 0:
        return None
    return timeout_ms


def _get_device_credentials(params):
    if not params.device_token or not params.device_private_key:
        logging.info('No device credentials found — registering new device with KA.')
        try:
            from .. import loginv3
            loginv3.LoginV3API.get_device_id(params)
        except Exception as exc:
            raise DesktopBridgeLoginError(
                f'Device registration failed: {exc}',
                code=KDBC_CLIENT_NOT_ENROLLED,
                kind='not_enrolled',
                actor='commander',
            ) from exc

    try:
        device_token = utils.base64_url_decode(params.device_token)
        device_private_key = utils.base64_url_decode(params.device_private_key)
        crypto.load_ec_private_key(device_private_key)
    except Exception as exc:
        raise DesktopBridgeLoginError(
            'Stored Commander device credentials are invalid.',
            code=KDBC_CLIENT_NOT_ENROLLED,
            kind='not_enrolled',
            actor='commander'
        ) from exc

    return device_token, device_private_key


def _register_device_for_public_key(params, env_host, device_public_key, client_identity=None):
    from ..proto import APIRequest_pb2
    from .. import rest_api as _rest_api
    from ..loginv3 import CommonHelperMethods

    rq = APIRequest_pb2.DeviceRegistrationRequest()
    rq.clientVersion = _rest_api.CLIENT_VERSION
    rq.deviceName = CommonHelperMethods.get_device_name()
    rq.devicePublicKey = bytes(device_public_key)

    payload = APIRequest_pb2.ApiRequestPayload()
    payload.payload = rq.SerializeToString()

    original_server_base = params.rest_context.server_base
    try:
        if env_host:
            params.rest_context.server_base = env_host
        rs = _rest_api.execute_rest(params.rest_context, 'authentication/register_device', payload)
    except Exception as exc:
        raise DesktopBridgeLoginError(
            f'KA register_device failed: {_safe_exception_message(exc)}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        ) from exc
    finally:
        params.rest_context.server_base = original_server_base

    if not isinstance(rs, bytes):
        if isinstance(rs, dict):
            message = rs.get('message') or rs.get('error') or 'unknown'
        else:
            message = 'unexpected response type'
        raise DesktopBridgeLoginError(
            f'KA register_device failed: {message}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        )

    device = APIRequest_pb2.Device()
    device.ParseFromString(rs)
    if not device.encryptedDeviceToken:
        raise DesktopBridgeLoginError(
            'KA register_device response missing encrypted device token',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        )

    logging.info(
        'via-desktop: registered KDBC-prepared Commander device for Vault KA server device_token=%s',
        _bytes_fingerprint(device.encryptedDeviceToken),
    )
    return device.encryptedDeviceToken


def _register_ephemeral_device(params):
    from ..proto import APIRequest_pb2
    from .. import rest_api as _rest_api
    from ..loginv3 import CommonHelperMethods

    private_key, public_key = crypto.generate_ec_key()

    rq = APIRequest_pb2.DeviceRegistrationRequest()
    rq.clientVersion = _rest_api.CLIENT_VERSION
    rq.deviceName = CommonHelperMethods.get_device_name()
    rq.devicePublicKey = crypto.unload_ec_public_key(public_key)

    payload = APIRequest_pb2.ApiRequestPayload()
    payload.payload = rq.SerializeToString()

    try:
        rs = _rest_api.execute_rest(params.rest_context, 'authentication/register_device', payload)
    except Exception as exc:
        raise DesktopBridgeLoginError(
            f'KA register_device failed: {_safe_exception_message(exc)}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        ) from exc

    if not isinstance(rs, bytes):
        if isinstance(rs, dict):
            message = rs.get('message') or rs.get('error') or 'unknown'
        else:
            message = 'unexpected response type'
        raise DesktopBridgeLoginError(
            f'KA register_device failed: {message}',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        )

    device = APIRequest_pb2.Device()
    device.ParseFromString(rs)
    if not device.encryptedDeviceToken:
        raise DesktopBridgeLoginError(
            'KA register_device response missing encrypted device token',
            code=KDBC_KA_LOGIN_FAILED,
            kind='ka_device_registration_failed',
            actor='ka',
        )

    device_private_key = crypto.unload_ec_private_key(private_key)
    logging.info(
        'via-desktop: registered ephemeral Commander device for Vault KA server device_token=%s',
        _bytes_fingerprint(device.encryptedDeviceToken),
    )
    return device.encryptedDeviceToken, device_private_key


def _build_client_identity(module):
    return module.ClientIdentity(
        name='Keeper Commander',
        version=__version__,
        kind='commander',
        ka_client_version=rest_api.CLIENT_VERSION,
    )


def _placeholder_device_credentials(module):
    private_key, public_key = crypto.generate_ec_key()
    return module.DeviceCredentials(
        encrypted_device_token=b'',
        device_private_key=crypto.unload_ec_private_key(private_key),
        device_public_key=crypto.unload_ec_public_key(public_key),
    )


def _build_bootstrap_request_for_device(module, params, device, bridge_socket, timeout_ms,
                                        verification_policy, client=None):
    client = client or _build_client_identity(module)

    config = _build_bridge_config(module, params, bridge_socket, timeout_ms, verification_policy)

    return module.BootstrapRequest(
        client=client,
        device=device,
        flow='already_enrolled',
        request_id=str(uuid.uuid4()),
        message_session_uid=utils.generate_uid(),
        config=config,
    )


def _build_bootstrap_request(module, params, device_token, device_private_key, bridge_socket, timeout_ms,
                             verification_policy, client=None):
    private_key = crypto.load_ec_private_key(device_private_key)
    device = module.DeviceCredentials(
        encrypted_device_token=device_token,
        device_private_key=device_private_key,
        device_public_key=crypto.unload_ec_public_key(private_key.public_key()),
    )
    return _build_bootstrap_request_for_device(
        module, params, device, bridge_socket, timeout_ms, verification_policy, client,
    )


def _build_bridge_config(module, params, bridge_socket, timeout_ms, verification_policy):
    if not hasattr(module, 'BridgeClientConfig'):
        return None

    verification_policy = _resolve_verification_policy(params, verification_policy)
    kwargs = {
        'server': params.server,
        'socket_override': bridge_socket,
        'timeout_millis': timeout_ms,
    }
    if verification_policy:
        kwargs['verification_policy'] = verification_policy

    try:
        return module.BridgeClientConfig(**kwargs)
    except TypeError:
        # Older KDBC wheels do not expose verification_policy.
        kwargs.pop('verification_policy', None)
        return module.BridgeClientConfig(**kwargs)


def _start_vault_lifecycle_monitor(params, module, config):
    bridge_client = getattr(module, 'BridgeClient', None)
    if bridge_client is None:
        raise DesktopBridgeLoginError(
            'KDBC lifecycle monitor API is unavailable',
            code=KDBC_KA_LOGIN_FAILED,
            kind='kdbc_lifecycle_monitor_unavailable',
            actor='bridge',
        )

    client = bridge_client()
    start_monitor = getattr(client, 'start_vault_lifecycle_monitor', None)
    if not callable(start_monitor):
        raise DesktopBridgeLoginError(
            'KDBC lifecycle monitor API is unavailable',
            code=KDBC_KA_LOGIN_FAILED,
            kind='kdbc_lifecycle_monitor_unavailable',
            actor='bridge',
        )

    _stop_vault_lifecycle_monitor(params)
    monitor = start_monitor(config, lambda notice: _handle_vault_lifecycle_notice(params, notice))
    params.desktop_lifecycle_monitor = monitor
    return monitor


def _stop_vault_lifecycle_monitor(params):
    monitor = getattr(params, 'desktop_lifecycle_monitor', None)
    params.desktop_lifecycle_monitor = None
    if monitor is None:
        return
    try:
        monitor.stop()
    except Exception as err:
        logging.debug('Unable to stop Vault lifecycle monitor: %s', err)


def _close_desktop_lifecycle_tunnels(params):
    from ..commands.tunnel.tunnel_lifecycle import close_pam_tunnels_on_logout
    close_pam_tunnels_on_logout(params)


def _suspend_desktop_pam_state(params):
    from ..commands.tunnel import pam_state_bridge
    pam_state_bridge.suspend_desktop_bridge_state(params, clear_binding=True)


def _clear_desktop_lifecycle_state(params):
    try:
        _suspend_desktop_pam_state(params)
    except Exception as err:
        logging.debug('Unable to suspend Desktop PAM state sync: %s', err)
    params.clear_session()


def _handle_vault_lifecycle_notice(params, notice):
    reason = getattr(notice, 'reason', None) or 'vault_desktop_disconnected'
    # The monitor invokes this callback from its own reader, so detach it before
    # clearing the session to avoid stopping or joining that reader recursively.
    params.desktop_lifecycle_monitor = None
    try:
        _close_desktop_lifecycle_tunnels(params)
    except Exception as err:
        logging.warning('Unable to close PAM tunnels after Vault lifecycle terminal: %s', err)
    _clear_desktop_lifecycle_state(params)
    params.via_desktop_session_terminated = True
    logging.warning('Vault Desktop lifecycle terminal; cleared Keeper session: %s', reason)


def _resolve_verification_policy(params, verification_policy):
    server = getattr(params, 'server', '')
    if verification_policy:
        return _normalize_verification_policy(server, verification_policy)

    env_policy = os.environ.get('KDBC_VERIFICATION_POLICY')
    if env_policy:
        return _normalize_verification_policy(server, env_policy)

    if _is_keeper_dev_host(server):
        return DEV_BRIDGE_VERIFICATION_POLICY

    return None


def _server_hostname(server):
    if not server:
        return ''

    server = str(server).strip().lower()
    if not server:
        return ''

    parsed = urlparse(server if '://' in server else f'https://{server}')
    return parsed.hostname or ''


def _is_keeper_dev_host(server):
    host = _server_hostname(server)
    return host == 'dev.keepersecurity.com' or host.endswith('.dev.keepersecurity.com')


def _is_keeper_production_host(server):
    host = _server_hostname(server)
    if not host or _is_keeper_dev_host(host):
        return False
    return any(
        host == suffix or host.endswith(f'.{suffix}')
        for suffix in _PRODUCTION_KEEPER_HOST_SUFFIXES
    )


def _normalize_verification_policy(server, policy):
    policy = str(policy or '').strip().lower()
    if not policy:
        return None
    if policy not in _ALLOWED_VERIFICATION_POLICIES:
        logging.warning("Ignoring unsupported KDBC verification policy: %s", policy)
        return None
    if policy == DEV_BRIDGE_VERIFICATION_POLICY and _is_keeper_production_host(server):
        logging.warning(
            "Ignoring KDBC_VERIFICATION_POLICY=log_only for production Keeper host %s",
            _server_hostname(server) or server,
        )
        return None
    return policy


def _translate_bridge_error(exc):
    code = getattr(exc, 'code', None) or KDBC_INTERNAL_ERROR
    kind = getattr(exc, 'kind', None) or 'bridge_error'
    retryable = bool(getattr(exc, 'retryable', False))
    actor = getattr(exc, 'actor', None) or 'bridge'
    request_id = getattr(exc, 'request_id', None)
    message = getattr(exc, 'message', None) or str(exc) or 'Unknown bridge error'
    return DesktopBridgeLoginError(
        message,
        code=code,
        kind=kind,
        retryable=retryable,
        actor=actor,
        request_id=request_id,
    )


def _apply_ka_credentials(params, device_private_key, encrypted_session_token, encrypted_data_key,
                           primary_username, account_uid):
    params.session_token_bytes = bytes(encrypted_session_token)
    params.session_token = utils.base64_url_encode(params.session_token_bytes)
    private_key = crypto.load_ec_private_key(device_private_key)
    params.data_key = crypto.decrypt_ec(bytes(encrypted_data_key), private_key)
    params.password = None
    params.clone_code = None

    if primary_username:
        params.user = primary_username

    if account_uid:
        if isinstance(account_uid, bytes):
            params.account_uid_bytes = account_uid
        else:
            try:
                params.account_uid_bytes = utils.base64_url_decode(account_uid)
            except Exception:
                logging.debug('KA login returned an account UID with an unexpected encoding.')

    from .. import loginv3
    loginv3.LoginV3Flow.populateAccountSummary(params)


def _binding_value(binding, name):
    if binding is None:
        return None
    if isinstance(binding, dict):
        return binding.get(name)
    return getattr(binding, name, None)


def _normalize_account_uid(value):
    if value is None:
        return None, None
    if isinstance(value, bytes):
        return value, utils.base64_url_encode(value)
    value = str(value).strip()
    if not value:
        return None, None
    decoded = utils.base64_url_decode(value)
    return decoded, utils.base64_url_encode(decoded)


def _uid_fingerprint(value):
    _decoded, normalized = _normalize_account_uid(value)
    if not normalized:
        return 'none'
    digest = hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:12]
    return f'len={len(normalized)} sha12={digest}'


def _bytes_fingerprint(value):
    if not value:
        return 'none'
    return f'len={len(value)} sha12={hashlib.sha256(value).hexdigest()[:12]}'


def _adopt_vault_account_binding(params, binding):
    try:
        account_uid_bytes, account_uid = _normalize_account_uid(_binding_value(binding, 'vault_account_uid'))
    except Exception as exc:
        raise DesktopBridgeLoginError(
            'Keeper Desktop bridge returned an invalid Vault account binding.',
            code=KDBC_PROTOCOL_ERROR,
            kind='account_binding_invalid',
            actor='vault',
            retryable=False,
        ) from exc

    if not account_uid_bytes or not account_uid:
        raise DesktopBridgeLoginError(
            'Keeper Desktop bridge did not return a Vault account binding.',
            code=KDBC_PROTOCOL_ERROR,
            kind='account_binding_missing',
            actor='vault',
            retryable=False,
        )

    username = _binding_value(binding, 'username')
    email = _binding_value(binding, 'email')
    display_user = str(email or username or '').strip()

    params.account_uid_bytes = account_uid_bytes
    if display_user:
        params.user = display_user

    logging.info(
        'via-desktop: adopting Vault user %s (uid %s)',
        display_user or '<unknown>',
        _uid_fingerprint(account_uid),
    )
    return account_uid


def _adopt_vault_ka_server(params, server):
    server = str(server or '').strip()
    if not server:
        raise DesktopBridgeLoginError(
            'Keeper Desktop bridge did not return a Vault KA server.',
            code=KDBC_PROTOCOL_ERROR,
            kind='ka_server_binding_missing',
            actor='vault',
            retryable=False,
        )
    if getattr(params, 'server', None) != server:
        logging.info('via-desktop: adopting Vault KA server %s', server)
    params.server = server


def _clear_via_desktop_transient_auth_state(params):
    params.password = ''
    params.auth_verifier = None
    params.clone_code = None


def _verify_ka_account_binding(params, binding_account_uid):
    try:
        _decoded, active_account_uid = _normalize_account_uid(getattr(params, 'account_uid_bytes', None))
    except Exception:
        active_account_uid = None
    if binding_account_uid and active_account_uid and binding_account_uid != active_account_uid:
        raise DesktopBridgeLoginError(
            'Desktop account does not match Vault account',
            code=KDBC_PROTOCOL_ERROR,
            kind='account_mismatch',
            actor='commander',
            retryable=False,
        )


def _apply_vault_account_binding(params, binding):
    try:
        from ..commands.tunnel import pam_state_bridge
    except Exception:
        return
    if binding is None:
        pam_state_bridge.suspend_desktop_bridge_state(params, clear_binding=True)
        logging.debug('Keeper Desktop bridge did not return a Vault account binding.')
        return
    ok, message = pam_state_bridge.set_desktop_account_binding(params, binding)
    if not ok and message == pam_state_bridge.DESKTOP_ACCOUNT_MISMATCH_MESSAGE:
        raise DesktopBridgeLoginError(
            pam_state_bridge.desktop_account_binding_mismatch_diagnostic(params),
            code=KDBC_PROTOCOL_ERROR,
            kind='account_mismatch',
            actor='commander',
            retryable=False,
        )
    if ok and getattr(params, 'desktop_user', None):
        params.user = params.desktop_user

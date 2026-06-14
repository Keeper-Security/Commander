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
import logging
import os
import uuid
from urllib.parse import urlparse

from .. import __version__, crypto, rest_api, utils
from ..params import KeeperParams


DEFAULT_BRIDGE_TIMEOUT_MS = 160000
DEV_BRIDGE_VERIFICATION_POLICY = 'log_only'
KDBC_CLIENT_NOT_ENROLLED = 'KDBC_CLIENT_NOT_ENROLLED'
KDBC_KA_LOGIN_FAILED = 'KDBC_KA_LOGIN_FAILED'
KDBC_PROTOCOL_ERROR = 'KDBC_PROTOCOL_ERROR'
KDBC_INTERNAL_ERROR = 'KDBC_INTERNAL_ERROR'


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
    device_token, device_private_key = _get_device_credentials(params)
    request = _build_bootstrap_request(
        module, params, device_token, device_private_key, bridge_socket, timeout_ms, verification_policy)

    try:
        vault_result = module.BridgeClient().exchange_vault_token(request)
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc

    vault_session_token = bytes(vault_result.vault_session_token)
    uid = request.message_session_uid
    if isinstance(uid, str):
        message_session_uid = utils.base64_url_decode(uid)
    elif uid:
        message_session_uid = bytes(uid)
    else:
        message_session_uid = b''

    encrypted_session_token, encrypted_data_key, primary_username, account_uid = \
        _ka_login_from_existing_session_token(
            params, device_token, message_session_uid, vault_session_token,
        )

    _apply_ka_credentials(
        params, device_private_key, encrypted_session_token, encrypted_data_key,
        primary_username, account_uid,
    )
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

    payload = APIRequest_pb2.ApiRequestPayload()
    payload.payload = rq.SerializeToString()
    payload.encryptedSessionToken = bytes(vault_session_token)

    try:
        rs = _rest_api.execute_rest(
            params.rest_context,
            'authentication/login_from_existing_session_token',
            payload,
        )
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


def _build_bootstrap_request(module, params, device_token, device_private_key, bridge_socket, timeout_ms,
                             verification_policy):
    private_key = crypto.load_ec_private_key(device_private_key)
    device_public_key = crypto.unload_ec_public_key(private_key.public_key())
    client = module.ClientIdentity(
        name='Keeper Commander',
        version=__version__,
        kind='commander',
        ka_client_version=rest_api.CLIENT_VERSION,
    )
    device = module.DeviceCredentials(
        encrypted_device_token=device_token,
        device_private_key=device_private_key,
        device_public_key=device_public_key,
    )

    config = _build_bridge_config(module, params, bridge_socket, timeout_ms, verification_policy)

    return module.BootstrapRequest(
        client=client,
        device=device,
        flow='already_enrolled',
        request_id=str(uuid.uuid4()),
        message_session_uid=utils.generate_uid(),
        config=config,
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


def _resolve_verification_policy(params, verification_policy):
    if verification_policy:
        return verification_policy

    env_policy = os.environ.get('KDBC_VERIFICATION_POLICY')
    if env_policy:
        return env_policy

    if _is_keeper_dev_host(getattr(params, 'server', '')):
        return DEV_BRIDGE_VERIFICATION_POLICY

    return None


def _is_keeper_dev_host(server):
    if not server:
        return False

    server = str(server).strip().lower()
    if not server:
        return False

    parsed = urlparse(server if '://' in server else f'https://{server}')
    host = parsed.hostname or ''
    return host.startswith('dev.keepersecurity.') or host.startswith('govcloud.dev.keepersecurity.')


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

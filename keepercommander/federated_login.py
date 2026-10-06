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

"""Login with a federated (OAuth) KSM client config and a workload JWT.

The KSM config is produced by `secrets-manager client add --federated`. The JWT (e.g. a
Kubernetes projected service account token) is exchanged at
`sm/v1/get_session_token_for_app_client` for a vault session token of the app owner.
Available in Service Mode only.
"""

import base64
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional

import requests
from keeper_secrets_manager_core.keeper_globals import keeper_secrets_manager_sdk_client_id as KSM_CLIENT_VERSION

from . import crypto, rest_api, utils
from .error import KeeperApiError, Error
from .params import KeeperParams

EXCHANGE_ENDPOINT = 'get_session_token_for_app_client'
CONFIG_WAIT_INTERVAL = 5
CONFIG_WAIT_LOG_EVERY = 60


# DEMO ONLY: step by step logging of the federated login, including tokens. Remove before release:
# delete this function and every demo_log(...) call (grep -rn demo_log keepercommander)
def demo_log(message, *args):
    print(f'[DEMO {datetime.now():%H:%M:%S}] ' + (message % args if args else message), flush=True)


def demo_token_claims(token):   # type: (str) -> dict
    """DEMO ONLY: the unverified JWT claims, for logging"""
    try:
        payload = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    except Exception:
        return {}


class FederatedLogin:
    def __init__(self, ksm_config, token_file):   # type: (str, str) -> None
        self.ksm_config = ksm_config
        self.token_file = token_file
        self.expires_on = 0

    def config_path(self):   # type: () -> Optional[str]
        """The config file path, or None when KEEPER_KSM_CONFIG holds the config itself"""
        value = self.ksm_config.strip()
        if value.startswith(('/', '~', '.')) or os.path.isfile(value):
            return os.path.expanduser(value)
        return None

    def wait_for_config(self):   # type: () -> None
        """Waits for the config file to appear, so the service can start before its Secret is created"""
        path = self.config_path()
        waited = 0
        while path and not (os.path.isfile(path) and os.path.getsize(path) > 0):
            if waited % CONFIG_WAIT_LOG_EVERY == 0:
                logging.warning('Waiting for the KSM config at %s', path)
            time.sleep(CONFIG_WAIT_INTERVAL)
            waited += CONFIG_WAIT_INTERVAL

    def load_config(self):   # type: () -> dict
        """Accepts a path to a JSON config file, a JSON string, or a base64-encoded JSON string."""
        value = self.ksm_config.strip()
        path = self.config_path()
        if path:
            with open(path, 'r') as f:
                value = f.read().strip()
        if not value.startswith('{'):
            value = base64.b64decode(value).decode()
        config = json.loads(value)
        if config.get('authType') != 'oauth':
            raise Error('KSM config is not a federated (OAuth) client config')
        for key in ('hostname', 'clientId'):
            if not config.get(key):
                raise Error(f'KSM config is missing "{key}"')
        demo_log('Read KSM config from %s: hostname=%s, clientId=%s, dataKey %s', path or 'KEEPER_KSM_CONFIG',
                 config['hostname'], config['clientId'], 'present' if config.get('dataKey') else 'MISSING')
        return config

    def read_token(self):   # type: () -> str
        path = os.path.expanduser(self.token_file)
        # projected tokens are rotated in place by the kubelet, so re-read the file on every exchange
        with open(path, 'r') as f:
            token = f.read().strip()
        if not token:
            raise Error(f'OIDC token file "{path}" is empty')
        claims = demo_token_claims(token)
        demo_log('Read K8s service account token from %s: iss=%s, sub=%s, aud=%s, expires %s\n  token: %s',
                 path, claims.get('iss'), claims.get('sub'), claims.get('aud'),
                 datetime.fromtimestamp(claims['exp']) if claims.get('exp') else '?', token)
        return token

    def exchange(self, params, config):   # type: (KeeperParams, dict) -> str
        """Exchanges the JWT for a vault session token. Returns the URL-safe base64 session token.

        sm/v1 endpoints use the KSM wire format, not the ApiRequest envelope of rest_api.execute_rest,
        and the KSM SDK only sends signed requests, so the request is built here. The server public key
        negotiation is shared with Commander's REST context.
        """
        context = params.rest_context
        if not context.server_key_id:
            context.server_key_id = 7
        url = f'https://{config["hostname"]}/api/rest/sm/v1/{EXCHANGE_ENDPOINT}'
        payload = json.dumps({
            'clientVersion': KSM_CLIENT_VERSION,
            'clientId': config['clientId'],
        }).encode()

        for _ in range(3):
            demo_log('Exchanging the K8s token at %s (server key id %s)', url, context.server_key_id)
            transmission_key = utils.generate_aes_key()
            encrypted_transmission_key = rest_api.encrypt_with_keeper_key(context, transmission_key)
            rs = requests.post(url, data=crypto.encrypt_aes_v2(payload, transmission_key), headers={
                'Content-Type': 'application/octet-stream',
                'PublicKeyId': str(context.server_key_id),
                'TransmissionKey': base64.b64encode(encrypted_transmission_key).decode(),
                'Authorization': f'Bearer {self.read_token()}',
            }, proxies=context.proxies, verify=context.certificate_check,
                timeout=rest_api.DEFAULT_TIMEOUT)

            if rs.status_code == 200:
                response = json.loads(crypto.decrypt_aes_v2(rs.content, transmission_key))
                self.expires_on = response.get('expiresOn') or 0
                demo_log('KA returned a session token, expires %s\n  session token: %s',
                         datetime.fromtimestamp(self.expires_on / 1000) if self.expires_on else '?',
                         response['sessionToken'])
                return response['sessionToken']

            try:
                failure = rs.json()
            except ValueError:
                raise KeeperApiError(str(rs.status_code), rs.text or rs.reason)
            error = failure.get('result_code') or failure.get('error')
            if error == 'key' and failure.get('key_id'):
                logging.debug('Server requested public key %s', failure['key_id'])
                demo_log('KA asked for server key id %s, retrying', failure['key_id'])
                context.server_key_id = int(failure['key_id'])
                continue
            demo_log('KA rejected the exchange: %s %s', error, failure.get('message') or '')
            raise KeeperApiError(error, failure.get('message') or failure.get('additional_info') or '')
        raise Error('Unable to negotiate the server public key')

    def login(self, params):   # type: (KeeperParams) -> None
        from .loginv3 import LoginV3Flow

        demo_log('Federated login started: KEEPER_KSM_CONFIG=%s, KEEPER_OIDC_TOKEN_FILE=%s',
                 self.ksm_config, self.token_file)
        self.wait_for_config()
        config = self.load_config()
        data_key = config.get('dataKey')
        if not data_key:
            raise Error('KSM config has no "dataKey". Re-create the client with --include-data-key '
                        'to use it for Commander login')

        params.server = config['hostname']
        params.session_token = self.exchange(params, config)
        params.data_key = base64.b64decode(data_key)
        params.password = None
        demo_log('Data key loaded from the KSM config (%d bytes)', len(params.data_key))

        LoginV3Flow.populateAccountSummary(params)
        if params.license:
            params.user = params.license.get('email') or params.user
            account_uid = params.license.get('account_uid')
            if account_uid:
                params.account_uid_bytes = base64.b64decode(account_uid)
        demo_log('Account summary loaded: logged in as %s', params.user)

        expires_in = max(0, int(self.expires_on / 1000 - time.time()))
        logging.info('Federated login as %s (session expires in %d min)', params.user, expires_in // 60)

    def refresh(self, params):   # type: (KeeperParams) -> bool
        """Re-exchanges a fresh JWT after the vault session token expired."""
        demo_log('Session token expired, exchanging a fresh K8s token')
        try:
            params.session_token = self.exchange(params, self.load_config())
            demo_log('Session refreshed')
            return True
        except Exception as e:
            logging.warning('Federated session refresh failed: %s', e)
            params.session_token = None
            return False


def from_environment():   # type: () -> Optional[FederatedLogin]
    """Federated login is only enabled for Service Mode, see service.core.globals"""
    ksm_config = os.environ.get('KEEPER_KSM_CONFIG')
    token_file = os.environ.get('KEEPER_OIDC_TOKEN_FILE')
    if not ksm_config and not token_file:
        return None
    if not ksm_config or not token_file:
        raise Error('Federated login requires both KEEPER_KSM_CONFIG and KEEPER_OIDC_TOKEN_FILE')
    return FederatedLogin(ksm_config, token_file)

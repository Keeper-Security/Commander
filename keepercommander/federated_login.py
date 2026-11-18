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

"""Login with a federated client config and a workload JWT.

The federated config (federated-config.json) is produced by
`secrets-manager client add --federated --access-type vault-session --include-data-key`. The JWT
(e.g. a Kubernetes projected service account token) is exchanged at `sm/v1/exchange_token` for a
vault session token of the user who added the client.
Available in Service Mode only.
"""

import base64
import json
import logging
import os
import time
from typing import Optional

import requests

from . import crypto, rest_api, utils
from .error import KeeperApiError, Error
from .params import KeeperParams

EXCHANGE_ENDPOINT = 'exchange_token'
FILE_WAIT_INTERVAL = 5
FILE_WAIT_LOG_EVERY = 60


def encrypted_bearer(token, transmission_key):   # type: (str, bytes) -> str
    encrypted = crypto.encrypt_aes_v2(token.encode(), transmission_key)
    return 'EncryptedBearer ' + base64.b64encode(encrypted).decode()


class FederatedLogin:
    def __init__(self, federated_config, token_file):   # type: (str, str) -> None
        self.federated_config = federated_config
        self.token_file = token_file
        self.expires_on = 0

    def config_path(self):   # type: () -> Optional[str]
        """The config file path, or None when KEEPER_FEDERATED_CONFIG holds the config itself"""
        value = self.federated_config.strip()
        if value.startswith(('/', '~', '.')) or os.path.isfile(value):
            return os.path.expanduser(value)
        return None

    def wait_for_files(self):   # type: () -> None
        """Waits until the federated config file and the token file exist and are not empty.

        In Docker or Kubernetes the service can start before its config Secret or token is mounted.
        """
        waiting = [(name, path) for name, path in (('federated config', self.config_path()),
                                                   ('OIDC token', os.path.expanduser(self.token_file))) if path]
        waited = 0
        while True:
            missing = [(name, path) for name, path in waiting if not (os.path.isfile(path) and os.path.getsize(path) > 0)]
            if not missing:
                return
            if waited % FILE_WAIT_LOG_EVERY == 0:
                for name, path in missing:
                    logging.warning('Waiting for the %s at %s', name, path)
            time.sleep(FILE_WAIT_INTERVAL)
            waited += FILE_WAIT_INTERVAL

    def load_config(self):   # type: () -> dict
        """Accepts a path to a JSON config file, a JSON string, or a base64-encoded JSON string."""
        value = self.federated_config.strip()
        path = self.config_path()
        if path:
            with open(path, 'r') as f:
                value = f.read().strip()
        if not value.startswith('{'):
            value = base64.b64decode(value).decode()
        config = json.loads(value)
        if config.get('authType') != 'oauth':
            raise Error('Federated config is not a federated (OAuth) client config')
        for key in ('hostname', 'clientId'):
            if not config.get(key):
                raise Error(f'Federated config is missing "{key}"')
        return config

    def read_token(self):   # type: () -> str
        path = os.path.expanduser(self.token_file)
        with open(path, 'r') as f:
            token = f.read().strip()
        if not token:
            raise Error(f'OIDC token file "{path}" is empty')
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
            'clientVersion': rest_api.CLIENT_VERSION,
            'clientId': config['clientId'],
        }).encode()

        for _ in range(3):
            transmission_key = utils.generate_aes_key()
            encrypted_transmission_key = rest_api.encrypt_with_keeper_key(context, transmission_key)
            rs = requests.post(url, data=crypto.encrypt_aes_v2(payload, transmission_key), headers={
                'Content-Type': 'application/octet-stream',
                'PublicKeyId': str(context.server_key_id),
                'TransmissionKey': base64.b64encode(encrypted_transmission_key).decode(),
                'Authorization': encrypted_bearer(self.read_token(), transmission_key),
            }, proxies=context.proxies, verify=context.certificate_check,
                timeout=rest_api.DEFAULT_TIMEOUT)

            if rs.status_code == 200:
                response = json.loads(crypto.decrypt_aes_v2(rs.content, transmission_key))
                self.expires_on = response.get('expiresOn') or 0
                return response['sessionToken']

            try:
                failure = rs.json()
            except ValueError:
                raise KeeperApiError(str(rs.status_code), rs.text or rs.reason)
            error = failure.get('result_code') or failure.get('error')
            if error == 'key' and failure.get('key_id'):
                logging.debug('Server requested public key %s', failure['key_id'])
                context.server_key_id = int(failure['key_id'])
                continue
            raise KeeperApiError(error, failure.get('message') or failure.get('additional_info') or '')
        raise Error('Unable to negotiate the server public key')

    def login(self, params):   # type: (KeeperParams) -> None
        from .loginv3 import LoginV3Flow

        self.wait_for_files()
        config = self.load_config()
        data_key = config.get('dataKey')
        if not data_key:
            raise Error('Federated config has no "dataKey". Re-create the client with --include-data-key '
                        'to use it for Commander login')

        params.server = config['hostname']
        params.session_token = self.exchange(params, config)
        params.data_key = base64.b64decode(data_key)
        params.password = None

        summary = LoginV3Flow.populateAccountSummary(params)
        usernames = list(summary.usernames) if summary else []
        params.user = (params.license or {}).get('email') or (usernames[0] if usernames else params.user)
        if params.license:
            account_uid = params.license.get('account_uid')
            if account_uid:
                params.account_uid_bytes = base64.b64decode(account_uid)

        expires_in = max(0, int(self.expires_on / 1000 - time.time()))
        logging.info('Federated login as %s (session expires in %d min)', params.user, expires_in // 60)

    def refresh(self, params):   # type: (KeeperParams) -> bool
        logging.debug('Federated session token expired, exchanging a fresh OIDC token')
        try:
            params.session_token = self.exchange(params, self.load_config())
            return True
        except Exception as e:
            logging.warning('Federated session refresh failed: %s', e)
            params.session_token = None
            return False


def from_environment():   # type: () -> Optional[FederatedLogin]
    """Federated login is only enabled for Service Mode, see service.core.globals"""
    federated_config = os.environ.get('KEEPER_FEDERATED_CONFIG')
    token_file = os.environ.get('KEEPER_OIDC_TOKEN_FILE')
    if not federated_config and not token_file:
        return None
    if not federated_config or not token_file:
        raise Error('Federated login requires both KEEPER_FEDERATED_CONFIG and KEEPER_OIDC_TOKEN_FILE')
    return FederatedLogin(federated_config, token_file)

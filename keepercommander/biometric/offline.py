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

"""`login --offline`: unlock the vault with the biometric passkey stored in the local Keychain.

No setup step and no extra secret: when an account has biometric login and its passkey is
in this Mac's Keychain, every online sync also writes an encrypted copy of the vault next
to the Commander config. The encryption key is derived (HKDF-SHA256) from that passkey's
private key. ``login --offline`` then:

1. requires Touch ID,
2. loads the passkey private key from the Keychain,
3. derives the key and decrypts the copy. Decryption only succeeds with the same passkey
   that created the copy, so it doubles as the passkey validation.

The session is read-only: every request to the Keeper server is refused.

Limits: only passkeys whose private key lives in the macOS Keychain (Touch ID passkeys
created by Commander) can be used. Windows Hello and USB security-key passkeys keep their
private key in hardware and cannot be used for offline unlock. The copy holds decrypted
vault key material, so the OS user account is the trust boundary.
"""

import base64
import hashlib
import json
import logging
import os
import platform
import tempfile
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import crypto, utils

SNAPSHOT_VERSION = 2
AUTH_TIMEOUT_SECONDS = 60
_KDF_INFO = b'keeper-commander-offline-vault-v1'

# KeeperParams attributes that make up the vault.
_CACHE_ATTRS = (
    'revision', 'sync_down_token', 'account_uid_bytes',
    'record_cache', 'meta_data_cache', 'non_shared_data_cache', 'shared_folder_cache',
    'team_cache', 'share_object_cache', 'record_link_cache', 'record_rotation_cache',
    'subfolder_cache', 'subfolder_record_cache', 'user_cache', 'record_type_cache',
    'settings', 'enforcements', 'license', 'disallowed_features', 'is_enterprise_admin',
    'data_key', 'client_key',
)


# Private keys are stored as "<kind>:<base64>". Older sessions may hold a Cryptodome RSA key.
def _dump_rsa(key):
    if hasattr(key, 'export_key'):
        return 'pycrypto:' + base64.b64encode(key.export_key('DER')).decode('ascii')
    return 'rsa:' + base64.b64encode(crypto.unload_rsa_private_key(key)).decode('ascii')


def _load_rsa(value):
    kind, _, data = value.partition(':')
    der = base64.b64decode(data)
    if kind == 'pycrypto':
        from Cryptodome.PublicKey import RSA
        return RSA.import_key(der)
    return crypto.load_rsa_private_key(der)


def _dump_ec(key):
    return 'ec:' + base64.b64encode(crypto.unload_ec_private_key(key)).decode('ascii')


def _load_ec(value):
    return crypto.load_ec_private_key(base64.b64decode(value.partition(':')[2]))


_KEY_ATTRS = {
    'rsa_key': (_load_rsa, _dump_rsa),
    'rsa_key2': (_load_rsa, _dump_rsa),
    'ecc_key': (_load_ec, _dump_ec),
}


class OfflineError(Exception):
    """User-facing offline mode failure."""


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #

def _encode(value):   # type: (Any) -> Any
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return {'__b': base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, (set, frozenset)):
        return {'__s': [_encode(v) for v in value]}
    if isinstance(value, tuple):
        return {'__t': [_encode(v) for v in value]}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        if all(isinstance(k, str) and not k.startswith('__') for k in value):
            return {k: _encode(v) for k, v in value.items()}
        return {'__d': [[_encode(k), _encode(v)] for k, v in value.items()]}
    raise TypeError('Cannot serialize {0}'.format(type(value).__name__))


def _decode(value):   # type: (Any) -> Any
    if isinstance(value, list):
        return [_decode(v) for v in value]
    if isinstance(value, dict):
        if len(value) == 1:
            if '__b' in value:
                return base64.b64decode(value['__b'])
            if '__s' in value:
                return set(_hashable(_decode(v)) for v in value['__s'])
            if '__t' in value:
                return tuple(_decode(v) for v in value['__t'])
            if '__d' in value:
                return {_hashable(_decode(k)): _decode(v) for k, v in value['__d']}
        return {k: _decode(v) for k, v in value.items()}
    return value


def _hashable(value):
    return tuple(_hashable(v) for v in value) if isinstance(value, list) else value


# --------------------------------------------------------------------------- #
# Passkey in the local Keychain
# --------------------------------------------------------------------------- #

def snapshot_path(params, user=None):   # type: (Any, Optional[str]) -> str
    user = (user or params.user or '').lower()
    if params.config_filename:
        folder = os.path.dirname(os.path.abspath(params.config_filename))
    else:
        folder = os.path.join(os.path.expanduser('~'), '.keeper')
    digest = hashlib.sha256(user.encode('utf-8')).hexdigest()[:16]
    return os.path.join(folder, 'offline_vault_{0}.json'.format(digest))


def _keychain_manager():
    if platform.system() != 'Darwin':
        raise OfflineError('Offline login uses the passkey stored in the macOS Keychain, so it is only '
                           'available on macOS. Windows Hello and security-key passkeys cannot be read '
                           'for offline use.')
    from .platforms.macos.keychain import MacOSKeychainManager
    return MacOSKeychainManager()


def _load_passkey_key(credential_id, rp_id):   # type: (str, str) -> bytes
    """Derive the vault-copy key from the Keychain passkey's private key."""
    private_key = _keychain_manager().load_credential(credential_id, rp_id, AUTH_TIMEOUT_SECONDS)
    if private_key is None:
        raise OfflineError('The biometric passkey was not found in the local Keychain. '
                           'Offline login needs the passkey registered on this Mac.')
    secret = crypto.unload_ec_private_key(private_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_KDF_INFO).derive(secret)


def _find_local_passkey(params):   # type: (Any) -> Optional[Dict[str, str]]
    """Ask Keeper which passkeys the account allows and pick the one held in this Keychain."""
    from .client import BiometricClient
    options = BiometricClient().generate_authentication_options(params, 'login')
    request_options = options['request_options']
    pk_options = request_options.get('publicKeyCredentialRequestOptions', request_options)
    rp_id = pk_options.get('rpId')
    if not rp_id:
        return None
    manager = _keychain_manager()
    for credential in pk_options.get('allowCredentials') or []:
        credential_id = credential.get('id')
        if isinstance(credential_id, (bytes, bytearray)):
            credential_id = utils.base64_url_encode(bytes(credential_id))
        if credential_id and manager.credential_exists(credential_id, rp_id):
            return {'rp_id': rp_id, 'credential_id': credential_id}
    return None


def verify_touch_id(reason):   # type: (str) -> None
    try:
        from .platforms.macos.webauthn import MacOSTouchIDWebAuthnClient
        client = MacOSTouchIDWebAuthnClient(None, None)
        client._validate_dependencies(['LocalAuthentication'])
        context = client._create_auth_context()
        client._check_biometric_availability(context)
        print('Touch ID: {0}'.format(reason))
        ok = client._authenticate_with_touchid(context, reason, AUTH_TIMEOUT_SECONDS)
    except Exception as e:
        raise OfflineError('Touch ID authentication failed: {0}'.format(e))
    if not ok:
        raise OfflineError('Touch ID authentication failed.')


def _biometric_is_set(user):   # type: (str) -> bool
    from . import check_biometric_previously_used
    return bool(check_biometric_previously_used(user))


# --------------------------------------------------------------------------- #
# Snapshot file
# --------------------------------------------------------------------------- #

def _write_private_file(path, data):   # type: (str, bytes) -> None
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=folder, prefix='.offline_vault_')
    try:
        with os.fdopen(fd, 'wb') as f:      # mkstemp creates the file with mode 0600
            f.write(data)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _read_snapshot_file(path):   # type: (str) -> Dict[str, Any]
    try:
        with open(path, 'r', encoding='utf-8') as f:
            doc = json.load(f)
        if doc.get('version') != SNAPSHOT_VERSION:
            raise ValueError('version')
        return doc
    except Exception:
        raise OfflineError('The offline vault is unreadable or from an incompatible version. '
                           'Log in online once to recreate it.')


def _build_payload(params):   # type: (Any) -> bytes
    state = {}    # type: Dict[str, Any]
    for attr in _CACHE_ATTRS:
        try:
            state[attr] = _encode(getattr(params, attr, None))
        except TypeError as e:
            logging.debug('Offline snapshot: skipping %s: %s', attr, e)
    keys = {}
    for attr, (_, dump) in _KEY_ATTRS.items():
        key = getattr(params, attr, None)
        if key is not None:
            keys[attr] = dump(key)
    payload = {
        'user': params.user.lower(),
        'server': params.server,
        'saved_at': int(time.time()),
        'state': state,
        'keys': keys,
    }
    return json.dumps(payload, separators=(',', ':')).encode('utf-8')


def snapshot_age(params):   # type: (Any) -> Optional[int]
    path = snapshot_path(params)
    return int(os.path.getmtime(path)) if os.path.isfile(path) else None


def refresh_snapshot(params):   # type: (Any) -> None
    """After an online sync, update the offline copy. Silent no-op unless the account has biometric
    login with its passkey in this Mac's Keychain. Never raises."""
    try:
        if getattr(params, 'offline', False) or not params.user or not params.data_key:
            return
        if platform.system() != 'Darwin' or not _biometric_is_set(params.user):
            return
        path = snapshot_path(params)
        location = None
        if os.path.isfile(path):
            try:
                doc = _read_snapshot_file(path)
                location = {'rp_id': doc['rp_id'], 'credential_id': doc['credential_id']}
            except Exception:
                location = None
        if location is None:
            location = _find_local_passkey(params)
        if location is None:
            logging.debug('Offline vault: no biometric passkey for this account in the local Keychain')
            return
        key = _load_passkey_key(location['credential_id'], location['rp_id'])
        doc = {
            'version': SNAPSHOT_VERSION,
            'user': params.user.lower(),
            'rp_id': location['rp_id'],
            'credential_id': location['credential_id'],
            'data': base64.b64encode(crypto.encrypt_aes_v2(_build_payload(params), key)).decode('ascii'),
        }
        _write_private_file(path, json.dumps(doc).encode('utf-8'))
        logging.debug('Offline vault updated')
    except Exception as e:
        logging.debug('Could not update the offline vault: %s', e)


def delete_snapshot(params, user=None):   # type: (Any, Optional[str]) -> None
    path = snapshot_path(params, user)
    if os.path.isfile(path):
        os.remove(path)


def load_offline_session(params, user):   # type: (Any, str) -> None
    """Validate the Keychain passkey and load the vault copy into ``params``. No network access."""
    from ..sync_down import prepare_folder_tree

    user = user.lower()
    path = snapshot_path(params, user)
    if not os.path.isfile(path):
        raise OfflineError('No offline vault found for {0}. Log in online once (with biometric login set up) '
                           'to create it.'.format(user))
    if not _biometric_is_set(user):
        raise OfflineError('Biometric login is not set for {0}.'.format(user))
    doc = _read_snapshot_file(path)
    if doc.get('user') != user:
        raise OfflineError('The offline vault belongs to a different account.')

    _keychain_manager()      # fail early on unsupported platforms
    verify_touch_id('unlock the Keeper vault offline')
    key = _load_passkey_key(doc['credential_id'], doc['rp_id'])
    try:
        payload = json.loads(crypto.decrypt_aes_v2(base64.b64decode(doc['data']), key).decode('utf-8'))
    except Exception:
        raise OfflineError('Passkey validation failed: the Keychain passkey does not match the one that '
                           'protects the offline vault, or the vault is corrupted.')
    if payload.get('user') != user:
        raise OfflineError('The offline vault belongs to a different account.')

    commands = list(params.commands)
    params.clear_session()
    params.commands.extend(commands)
    for attr, value in payload['state'].items():
        decoded = _decode(value)
        target = getattr(params, attr, None)
        if isinstance(target, dict) and isinstance(decoded, dict):
            target.clear()
            target.update(decoded)
        else:
            setattr(params, attr, decoded)
    for attr, value in payload['keys'].items():
        if attr in _KEY_ATTRS:
            setattr(params, attr, _KEY_ATTRS[attr][0](value))

    params.user = user
    prepare_folder_tree(params)
    params.current_folder = None
    params.offline = True
    params.rest_context.offline = True
    params.session_token = 'offline'     # lets commands that require a session run; the network is blocked
    params.sync_data = False
    params._sync_record_count = sum(1 for r in params.record_cache.values() if r.get('version', 0) in (2, 3))
    params._sync_breachwatch_count = 0
    params._offline_saved_at = payload.get('saved_at')

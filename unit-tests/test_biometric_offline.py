import json
import os
from unittest import mock

import pytest

pytest.importorskip('fido2')

from data_vault import get_synced_params
from keepercommander import api, crypto, vault
from keepercommander.biometric import offline
from keepercommander.commands.utils import LoginCommand, login_parser
from keepercommander.error import CommandError, KeeperApiError
from keepercommander.params import KeeperParams

LOCATION = {'rp_id': 'keepersecurity.com', 'credential_id': 'cred-1'}


class FakeKeychain:
    """Stands in for MacOSKeychainManager: holds passkey private keys by credential id."""

    def __init__(self):
        self.keys = {'cred-1': crypto.generate_ec_key()[0]}

    def load_credential(self, credential_id, rp_id=None, timeout_seconds=None):
        return self.keys.get(credential_id)

    def credential_exists(self, credential_id, rp_id=None, timeout_seconds=None):
        return credential_id in self.keys


@pytest.fixture
def env(tmp_path):
    keychain = FakeKeychain()
    touch_id = []
    with mock.patch.object(offline.platform, 'system', return_value='Darwin'), \
            mock.patch.object(offline, '_keychain_manager', return_value=keychain), \
            mock.patch.object(offline, '_biometric_is_set', return_value=True), \
            mock.patch.object(offline, '_find_local_passkey', return_value=dict(LOCATION)), \
            mock.patch.object(offline, 'verify_touch_id', side_effect=lambda reason: touch_id.append(reason)):
        params = get_synced_params()
        params.config_filename = str(tmp_path / 'config.json')
        yield params, keychain, touch_id


def _offline_params(online):
    p = KeeperParams(server=online.server)
    p.config_filename = online.config_filename
    return p


def _create(online):
    offline.refresh_snapshot(online)
    assert os.path.isfile(offline.snapshot_path(online))


def test_codec_round_trip():
    value = {'a': b'\x00\x01', 'b': {1, 2}, 'c': (1, b'x'), 3: [None, True, 1.5, 'x'], '__b': 'user data'}
    assert offline._decode(json.loads(json.dumps(offline._encode(value)))) == value


def test_codec_rejects_unknown_types():
    with pytest.raises(TypeError):
        offline._encode({'x': object()})


def test_sync_creates_snapshot_without_any_setup(env):
    online, _, touch_id = env
    assert not os.path.exists(offline.snapshot_path(online))
    _create(online)
    assert not touch_id          # online refresh needs no extra prompt


def test_snapshot_is_encrypted_private_and_names_the_passkey(env):
    online, _, _ = env
    _create(online)
    path = offline.snapshot_path(online)
    assert os.name == 'nt' or os.stat(path).st_mode & 0o077 == 0
    raw = open(path, 'rb').read()
    for uid in online.record_cache:
        assert uid.encode() not in raw
    doc = json.loads(raw)
    assert doc['credential_id'] == 'cred-1' and doc['rp_id'] == 'keepersecurity.com'


def test_no_snapshot_without_biometric(env):
    online, _, _ = env
    with mock.patch.object(offline, '_biometric_is_set', return_value=False):
        offline.refresh_snapshot(online)
    assert not os.path.exists(offline.snapshot_path(online))


def test_no_snapshot_without_local_passkey(env):
    online, _, _ = env
    with mock.patch.object(offline, '_find_local_passkey', return_value=None):
        offline.refresh_snapshot(online)
    assert not os.path.exists(offline.snapshot_path(online))


def test_no_snapshot_on_non_mac(env):
    online, _, _ = env
    with mock.patch.object(offline.platform, 'system', return_value='Windows'):
        offline.refresh_snapshot(online)
    assert not os.path.exists(offline.snapshot_path(online))


def test_refresh_reuses_known_passkey_location(env):
    online, _, _ = env
    _create(online)
    with mock.patch.object(offline, '_find_local_passkey', side_effect=AssertionError('no server lookup')):
        offline.refresh_snapshot(online)
    assert os.path.isfile(offline.snapshot_path(online))


def test_refresh_never_raises(env):
    online, keychain, _ = env
    _create(online)
    keychain.keys.clear()
    offline.refresh_snapshot(online)


def test_offline_login_restores_vault(env):
    online, _, touch_id = env
    _create(online)
    p = _offline_params(online)
    offline.load_offline_session(p, online.user)

    assert touch_id, 'offline login must require Touch ID'
    assert p.offline and p.rest_context.offline
    assert p.data_key == online.data_key
    assert p.record_cache.keys() == online.record_cache.keys()
    assert p.folder_cache.keys() == online.folder_cache.keys()
    for uid in online.record_cache:
        assert vault.KeeperRecord.load(p, uid).title == vault.KeeperRecord.load(online, uid).title
    assert crypto.unload_rsa_private_key(p.rsa_key2) == crypto.unload_rsa_private_key(online.rsa_key2)


def test_different_passkey_cannot_open_vault(env):
    online, keychain, _ = env
    _create(online)
    keychain.keys['cred-1'] = crypto.generate_ec_key()[0]       # another key under the same id
    p = _offline_params(online)
    with pytest.raises(offline.OfflineError, match='Passkey validation failed'):
        offline.load_offline_session(p, online.user)
    assert not p.offline and not p.record_cache


def test_missing_passkey_in_keychain(env):
    online, keychain, _ = env
    _create(online)
    keychain.keys.clear()
    with pytest.raises(offline.OfflineError, match='not found in the local Keychain'):
        offline.load_offline_session(_offline_params(online), online.user)


def test_touch_id_failure_stops_login(env):
    online, _, _ = env
    _create(online)
    p = _offline_params(online)
    with mock.patch.object(offline, 'verify_touch_id', side_effect=offline.OfflineError('denied')):
        with pytest.raises(offline.OfflineError, match='denied'):
            offline.load_offline_session(p, online.user)
    assert not p.offline and not p.record_cache


def test_requires_biometric_flag(env):
    online, _, _ = env
    _create(online)
    with mock.patch.object(offline, '_biometric_is_set', return_value=False):
        with pytest.raises(offline.OfflineError, match='Biometric login is not set'):
            offline.load_offline_session(_offline_params(online), online.user)


def test_no_snapshot_message(env):
    online, _, _ = env
    with pytest.raises(offline.OfflineError, match='No offline vault'):
        offline.load_offline_session(_offline_params(online), online.user)


def test_tampered_snapshot_is_rejected(env):
    online, _, _ = env
    _create(online)
    path = offline.snapshot_path(online)
    doc = json.load(open(path))
    raw = bytearray(__import__('base64').b64decode(doc['data']))
    raw[20] ^= 0xFF
    doc['data'] = __import__('base64').b64encode(bytes(raw)).decode()
    json.dump(doc, open(path, 'w'))
    with pytest.raises(offline.OfflineError, match='Passkey validation failed'):
        offline.load_offline_session(_offline_params(online), online.user)


def test_other_users_snapshot_is_rejected(env):
    online, _, _ = env
    _create(online)
    with pytest.raises(offline.OfflineError):
        offline.load_offline_session(_offline_params(online), 'someone.else@example.com')


def test_macos_only(env):
    online, _, _ = env
    _create(online)
    with mock.patch.object(offline, '_keychain_manager', side_effect=offline.OfflineError('macOS')):
        with pytest.raises(offline.OfflineError, match='macOS'):
            offline.load_offline_session(_offline_params(online), online.user)


def test_offline_session_blocks_network(env):
    online, _, _ = env
    _create(online)
    p = _offline_params(online)
    offline.load_offline_session(p, online.user)
    with mock.patch('keepercommander.rest_api.requests.post') as post:
        with pytest.raises(KeeperApiError):
            api.communicate_rest(p, None, 'vault/sync_down')
        post.assert_not_called()


def test_clear_session_leaves_offline_mode(env):
    online, _, _ = env
    _create(online)
    p = _offline_params(online)
    offline.load_offline_session(p, online.user)
    p.clear_session()
    assert not p.offline and not p.rest_context.offline


def test_delete_snapshot(env):
    online, _, _ = env
    _create(online)
    offline.delete_snapshot(online)
    assert not os.path.exists(offline.snapshot_path(online))


def test_login_offline_flag_and_command(env):
    online, _, _ = env
    assert login_parser.parse_args(['--offline', 'a@b.com']).offline is True
    _create(online)
    p = _offline_params(online)
    p.batch_mode = True
    LoginCommand().execute(p, email=online.user, offline=True)
    assert p.offline and p.session_token

    q = _offline_params(online)
    q.session_token = 'real'
    with pytest.raises(CommandError, match='Already logged in'):
        LoginCommand().execute(q, email=online.user, offline=True)

"""Unit tests for NSF folder key / name decrypt (shared + team paths)."""

import json
from unittest import TestCase
from unittest.mock import Mock

from keepercommander import crypto, utils
from keepercommander.nested_share_folder import sync as nsf_sync
from keepercommander.proto import folder_pb2


def _make_params(**overrides):
    p = Mock()
    p.data_key = utils.generate_aes_key()
    p.rsa_key2 = None
    p.ecc_key = None
    p.team_cache = {}
    p.nested_share_folders = {}
    p.nested_share_folder_keys = {}
    p.nested_share_folder_accesses = {}
    p.nested_share_records = {}
    p.nested_share_record_data = {}
    p.nested_share_record_keys = {}
    p.nested_share_folder_records = {}
    p.nested_share_record_links = {}
    for k, v in overrides.items():
        setattr(p, k, v)
    return p


def _encrypted_folder(name, folder_key):
    """Return (folder_uid, folder_obj, folder_key) with AES-GCM encrypted data."""
    folder_uid = utils.generate_uid()
    data = crypto.encrypt_aes_v2(json.dumps({'name': name}).encode('utf-8'), folder_key)
    folder_obj = {
        'folder_uid': folder_uid,
        'parent_uid': None,
        'data': data,
    }
    return folder_uid, folder_obj, folder_key


class TestNsfFolderKeyDecrypt(TestCase):

    def test_user_key_owner_path_decrypts_name(self):
        params = _make_params()
        folder_key = utils.generate_aes_key()
        folder_uid, folder_obj, _ = _encrypted_folder('Owner Folder', folder_key)
        params.nested_share_folders[folder_uid] = folder_obj
        params.nested_share_folder_keys[folder_uid] = [{
            'folder_uid': folder_uid,
            'parent_uid': None,
            'encrypted_key': crypto.encrypt_aes_v2(folder_key, params.data_key),
            'key_type': folder_pb2.ENCRYPTED_BY_USER_KEY,
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertEqual(folder_obj['name'], 'Owner Folder')
        self.assertEqual(folder_obj['folder_key_unencrypted'], folder_key)

    def test_team_key_via_folder_access_decrypts_name(self):
        """ENCRYPTED_BY_TEAM_KEY + AT_TEAM access wrapped with team AES key."""
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        params = _make_params(team_cache={
            team_uid: {
                'team_uid': team_uid,
                'team_key_unencrypted': team_aes,
            },
        })
        folder_uid, folder_obj, _ = _encrypted_folder('Team Shared NSF', folder_key)
        params.nested_share_folders[folder_uid] = folder_obj
        params.nested_share_folder_keys[folder_uid] = [{
            'folder_uid': folder_uid,
            'parent_uid': None,
            'encrypted_key': b'',  # unused for TEAM_KEY
            'key_type': folder_pb2.ENCRYPTED_BY_TEAM_KEY,
        }]
        params.nested_share_folder_accesses[folder_uid] = [{
            'folder_uid': folder_uid,
            'access_type_uid': team_uid,
            'access_type': folder_pb2.AT_TEAM,
            'folder_key': {
                'encrypted_key': crypto.encrypt_aes_v2(folder_key, team_aes),
                'encrypted_key_type': folder_pb2.encrypted_by_data_key_gcm,
            },
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertEqual(folder_obj['name'], 'Team Shared NSF')
        self.assertEqual(folder_obj['folder_key_unencrypted'], folder_key)

    def test_team_key_fails_without_decrypted_team_key(self):
        """Ordering dependency: encrypted-only team_cache entry cannot unwrap."""
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        params = _make_params(team_cache={
            team_uid: {
                'team_uid': team_uid,
                # team_key present but not yet decrypted
                'team_key': utils.base64_url_encode(
                    crypto.encrypt_aes_v2(team_aes, utils.generate_aes_key())
                ),
                'team_key_type': 1,
            },
        })
        folder_uid, folder_obj, _ = _encrypted_folder('Hidden Name', folder_key)
        params.nested_share_folders[folder_uid] = folder_obj
        params.nested_share_folder_keys[folder_uid] = [{
            'folder_uid': folder_uid,
            'parent_uid': None,
            'encrypted_key': b'',
            'key_type': folder_pb2.ENCRYPTED_BY_TEAM_KEY,
        }]
        params.nested_share_folder_accesses[folder_uid] = [{
            'folder_uid': folder_uid,
            'access_type_uid': team_uid,
            'access_type': folder_pb2.AT_TEAM,
            'folder_key': {
                'encrypted_key': crypto.encrypt_aes_v2(folder_key, team_aes),
                'encrypted_key_type': folder_pb2.encrypted_by_data_key_gcm,
            },
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertNotIn('folder_key_unencrypted', folder_obj)
        self.assertNotIn('name', folder_obj)

    def test_parent_key_without_parent_falls_back_to_team_access(self):
        """Sharee gets PARENT_KEY metadata but no parent folder; key is in accesses."""
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        parent_uid = utils.generate_uid()
        params = _make_params(team_cache={
            team_uid: {
                'team_uid': team_uid,
                'team_key_unencrypted': team_aes,
            },
        })
        folder_uid, folder_obj, _ = _encrypted_folder('Child Shared', folder_key)
        folder_obj['parent_uid'] = parent_uid
        params.nested_share_folders[folder_uid] = folder_obj
        # Parent not in nested_share_folders (outside sharee hierarchy)
        params.nested_share_folder_keys[folder_uid] = [{
            'folder_uid': folder_uid,
            'parent_uid': parent_uid,
            'encrypted_key': crypto.encrypt_aes_v2(folder_key, utils.generate_aes_key()),
            'key_type': folder_pb2.ENCRYPTED_BY_PARENT_KEY,
        }]
        params.nested_share_folder_accesses[folder_uid] = [{
            'folder_uid': folder_uid,
            'access_type_uid': team_uid,
            'access_type': folder_pb2.AT_TEAM,
            'folder_key': {
                'encrypted_key': crypto.encrypt_aes_v2(folder_key, team_aes),
                'encrypted_key_type': folder_pb2.encrypted_by_data_key_gcm,
            },
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertEqual(folder_obj['name'], 'Child Shared')

    def test_parent_key_with_parent_unwraps_chain(self):
        params = _make_params()
        parent_key = utils.generate_aes_key()
        child_key = utils.generate_aes_key()
        parent_uid, parent_obj, _ = _encrypted_folder('Parent', parent_key)
        child_uid, child_obj, _ = _encrypted_folder('Child', child_key)
        child_obj['parent_uid'] = parent_uid
        params.nested_share_folders[parent_uid] = parent_obj
        params.nested_share_folders[child_uid] = child_obj
        params.nested_share_folder_keys[parent_uid] = [{
            'folder_uid': parent_uid,
            'parent_uid': None,
            'encrypted_key': crypto.encrypt_aes_v2(parent_key, params.data_key),
            'key_type': folder_pb2.ENCRYPTED_BY_USER_KEY,
        }]
        params.nested_share_folder_keys[child_uid] = [{
            'folder_uid': child_uid,
            'parent_uid': parent_uid,
            'encrypted_key': crypto.encrypt_aes_v2(child_key, parent_key),
            'key_type': folder_pb2.ENCRYPTED_BY_PARENT_KEY,
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertEqual(parent_obj['name'], 'Parent')
        self.assertEqual(child_obj['name'], 'Child')

    def test_user_access_fallback_when_user_key_fails(self):
        """USER_KEY wrap fails; folderAccesses has user-wrapped key."""
        params = _make_params()
        folder_key = utils.generate_aes_key()
        folder_uid, folder_obj, _ = _encrypted_folder('Access Shared', folder_key)
        params.nested_share_folders[folder_uid] = folder_obj
        params.nested_share_folder_keys[folder_uid] = [{
            'folder_uid': folder_uid,
            'parent_uid': None,
            # Wrapped with a key the user does not have
            'encrypted_key': crypto.encrypt_aes_v2(folder_key, utils.generate_aes_key()),
            'key_type': folder_pb2.ENCRYPTED_BY_USER_KEY,
        }]
        params.nested_share_folder_accesses[folder_uid] = [{
            'folder_uid': folder_uid,
            'access_type_uid': utils.generate_uid(),
            'access_type': folder_pb2.AT_USER,
            'folder_key': {
                'encrypted_key': crypto.encrypt_aes_v2(folder_key, params.data_key),
                'encrypted_key_type': folder_pb2.encrypted_by_data_key_gcm,
            },
        }]

        nsf_sync._decrypt_nested_share_folder_keys(params)

        self.assertEqual(folder_obj['name'], 'Access Shared')

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

import unittest
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander import vault
from keepercommander.commands.pam_import import nsf_helpers


class TestPAMExtendNSFHelpers(unittest.TestCase):

    def setUp(self):
        self.params = MagicMock()
        self.params.record_cache = {}
        self.params.nested_share_records = {}
        self.params.nested_share_record_data = {}
        self.params.nested_share_folders = {}
        self.params.nested_share_folder_records = {}
        self.params.subfolder_cache = {}
        self.params.subfolder_record_cache = {}
        self.params.shared_folder_cache = {}

    def test_find_pam_configuration_from_nsf_record_data(self):
        self.params.nested_share_records['cfg-nsf-1'] = {'version': 6}
        self.params.nested_share_record_data['cfg-nsf-1'] = {
            'data_json': {
                'title': 'Gateway NSF Config',
                'type': 'pamNetworkConfiguration',
                'fields': [{
                    'type': 'pamResources',
                    'value': [{
                        'controllerUid': 'gw-1',
                        'folderUid': 'nsf-root',
                        'resourceRef': [],
                    }],
                }],
            },
        }

        found = nsf_helpers.find_pam_configuration(self.params, 'Gateway NSF Config')
        self.assertIsNotNone(found)
        self.assertEqual(found.record_uid, 'cfg-nsf-1')

    def test_is_nsf_folder_uid(self):
        self.params.nested_share_folders['nsf-root'] = {'name': 'pamFolder', 'parent_uid': ''}
        self.assertTrue(nsf_helpers.is_nsf_folder_uid(self.params, 'nsf-root'))
        self.assertFalse(nsf_helpers.is_nsf_folder_uid(self.params, 'classic-sf'))

    def test_build_nsf_folder_tree(self):
        self.params.nested_share_folders = {
            'nsf-root': {'name': 'pamFolder', 'parent_uid': ''},
            'nsf-res': {'name': 'pamFolder - Resources', 'parent_uid': 'nsf-root'},
            'nsf-users': {'name': 'pamFolder - Users', 'parent_uid': 'nsf-root'},
        }
        tree = nsf_helpers.build_folder_tree(self.params, 'nsf-root')
        self.assertIn('pamFolder - Resources', tree)
        self.assertEqual(tree['pamFolder - Resources']['uid'], 'nsf-res')

    def test_get_folder_record_uids_merges_caches(self):
        self.params.subfolder_record_cache['fld-1'] = ['rec-a']
        self.params.nested_share_folder_records['fld-1'] = ['rec-b']
        uids = nsf_helpers.get_folder_record_uids(self.params, 'fld-1')
        self.assertEqual(uids, {'rec-a', 'rec-b'})

    @patch('keepercommander.commands.ksm.KSMCommand.get_app_info')
    def test_get_ksm_app_folders_includes_nsf(self, mock_get_app_info):
        from keepercommander.proto import APIRequest_pb2

        share = MagicMock()
        share.shareType = APIRequest_pb2.SHARE_TYPE_FOLDER  # pylint: disable=no-member
        share.secretUid = b'\x01\x02\x03'
        share.editable = True
        app_info = MagicMock()
        app_info.shares = [share]
        mock_get_app_info.return_value = [app_info]

        self.params.nested_share_folders['encoded-uid'] = {'name': 'NSF PAM'}
        with patch('keepercommander.utils.base64_url_encode', return_value='encoded-uid'):
            folders = nsf_helpers.get_ksm_app_folders(self.params, 'ksm-app-1')

        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0]['source'], 'nested')
        self.assertEqual(folders[0]['name'], 'NSF PAM')

    def test_get_records_in_folder_uses_load_pam_record(self):
        user = vault.TypedRecord(version=3)
        user.type_name = 'pamUser'
        user.title = 'Admin'
        user.record_uid = 'usr-1'
        user.fields.append(vault.TypedField.new_field('login', ['root']))
        self.params.nested_share_folder_records['fld-1'] = ['usr-1']

        with patch('keepercommander.commands.pam_import.nsf_helpers.load_pam_record', return_value=user):
            rows = nsf_helpers.get_records_in_folder(self.params, 'fld-1')

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'usr-1')
        self.assertEqual(rows[0][2], 'pamUser')
        self.assertEqual(rows[0][3], 'root')


if __name__ == '__main__':
    unittest.main()

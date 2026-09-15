"""Tests for batched NSF folder creation used by PAM CyberArk import."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from keepercommander.commands.pam_import.nsf_helpers import create_nsf_folders_batch
from keepercommander.error import CommandError


class TestCreateNsfFoldersBatch(unittest.TestCase):

    def _params(self):
        params = MagicMock()
        params.nested_share_folders = {}
        params.subfolder_cache = {}
        params.folder_cache = {}
        params.environment_variables = {}
        return params

    @patch('keepercommander.commands.pam_import.nsf_helpers.sync_down_preserving_nsf_keys')
    @patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3')
    def test_batches_and_seeds_cache(self, mock_batch, mock_sync):
        params = self._params()
        mock_batch.return_value = [
            {
                'folder_uid': 'uid-a',
                'folder_key_unencrypted': b'key-a',
                'name': 'SafeA',
                'success': True,
                'message': '',
            },
            {
                'folder_uid': 'uid-b',
                'folder_key_unencrypted': b'key-b',
                'name': 'SafeB',
                'success': True,
                'message': '',
            },
        ]

        specs = [
            {'name': 'SafeA', 'parent_uid': 'proj'},
            {'name': 'SafeB', 'parent_uid': 'proj'},
        ]
        results = create_nsf_folders_batch(params, specs, sync=True, command='pam')

        self.assertEqual(len(results), 2)
        mock_batch.assert_called_once_with(params, specs)
        mock_sync.assert_called_once_with(params)
        self.assertEqual(params.nested_share_folders['uid-a']['name'], 'SafeA')
        self.assertEqual(params.nested_share_folders['uid-b']['parent_uid'], 'proj')

    @patch('keepercommander.commands.pam_import.nsf_helpers.sync_down_preserving_nsf_keys')
    @patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3')
    def test_skips_sync_when_requested(self, mock_batch, mock_sync):
        params = self._params()
        mock_batch.return_value = [{
            'folder_uid': 'uid-a',
            'folder_key_unencrypted': b'k',
            'name': 'Config',
            'success': True,
            'message': '',
        }]

        create_nsf_folders_batch(
            params, [{'name': 'Config', 'parent_uid': 'proj'}],
            sync=False, command='pam',
        )
        mock_sync.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3')
    def test_raises_on_failed_folder(self, mock_batch):
        params = self._params()
        mock_batch.return_value = [{
            'folder_uid': 'uid-a',
            'success': False,
            'message': 'denied',
            'name': 'Bad',
        }]

        with self.assertRaises(CommandError):
            create_nsf_folders_batch(
                params, [{'name': 'Bad', 'parent_uid': 'proj'}],
                sync=False, command='pam',
            )

    @patch('keepercommander.commands.pam_import.nsf_helpers.sync_down_preserving_nsf_keys')
    @patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3')
    def test_chunks_over_100(self, mock_batch, mock_sync):
        params = self._params()

        def _side_effect(_params, chunk):
            return [{
                'folder_uid': f'uid-{i}',
                'folder_key_unencrypted': b'k',
                'name': s['name'],
                'success': True,
                'message': '',
            } for i, s in enumerate(chunk)]

        mock_batch.side_effect = _side_effect
        specs = [{'name': f'F{i}', 'parent_uid': 'proj'} for i in range(105)]
        results = create_nsf_folders_batch(params, specs, sync=True, command='pam')

        self.assertEqual(len(results), 105)
        self.assertEqual(mock_batch.call_count, 2)
        self.assertEqual(len(mock_batch.call_args_list[0][0][1]), 100)
        self.assertEqual(len(mock_batch.call_args_list[1][0][1]), 5)


class TestCreateSafeFoldersNsfBatch(unittest.TestCase):

    @patch('keepercommander.commands.pam_import.edit.PAMProjectImportCommand.add_folder_permissions')
    @patch('keepercommander.commands.pam_import.nsf_helpers.create_nsf_folders_batch')
    def test_two_layer_batch_layout(self, mock_batch, _mock_perms):
        from keepercommander.commands.pam_import.edit import PAMProjectImportCommand

        cmd = PAMProjectImportCommand()
        params = MagicMock()
        res = {"project_folder": "CyberArk Migration", "safe_folders": []}
        safe_folder_map = {}
        records = [
            {"name": "Win_Local", "safe_name": "Win_Local", "fperm": {}, "uperm": []},
            {"name": "Linux", "safe_name": "Linux", "fperm": {}, "uperm": [{"name": "u@x.com"}]},
        ]

        # Layer1: Config + 2 safes; Layer2: 4 children
        def _batch(_params, specs, sync=True, command='pam'):
            return [{
                'folder_uid': f'uid-{spec["name"]}',
                'name': spec['name'],
                'success': True,
            } for spec in specs]

        mock_batch.side_effect = _batch

        cmd._create_safe_folders_nsf_batch(
            params, 'proj-uid', res, records,
            'CyberArk Migration - Config', safe_folder_map,
        )

        self.assertEqual(mock_batch.call_count, 2)
        layer1_specs = mock_batch.call_args_list[0][0][1]
        layer2_specs = mock_batch.call_args_list[1][0][1]
        self.assertEqual(
            [s['name'] for s in layer1_specs],
            ['CyberArk Migration - Config', 'Win_Local', 'Linux'],
        )
        self.assertEqual(len(layer2_specs), 4)
        self.assertEqual(res['config_folder_uid'], 'uid-CyberArk Migration - Config')
        self.assertEqual(safe_folder_map['Win_Local'], 'uid-Win_Local')
        self.assertIn('Win_Local/Win_Local - Resources', safe_folder_map)
        self.assertIn('Linux/Linux - Users', safe_folder_map)
        self.assertEqual(len(res['safe_folders']), 2)
        _mock_perms.assert_called_once()


if __name__ == '__main__':
    unittest.main()

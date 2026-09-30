"""Tests for Classic-to-Nested-Share conversion request construction."""

from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from keepercommander import crypto, utils
from keepercommander.commands.nested_share_folder import NestedShareConvertCommand
from keepercommander.nested_share_folder.conversion_api import (
    build_convert_records_request,
    convert_records_v3,
)
from keepercommander.error import CommandError
from keepercommander.proto import keeperdrive_convert_pb2


def _uid():
    return utils.generate_uid()


class TestClassicToNsfConversionApi(TestCase):

    def setUp(self):
        self.record_uid = _uid()
        self.record_key = utils.generate_aes_key()
        self.data_key = utils.generate_aes_key()
        self.params = SimpleNamespace(
            data_key=self.data_key,
            record_cache={
                self.record_uid: {'record_key_unencrypted': self.record_key},
            },
            nested_share_folders={},
            subfolder_cache={},
            folder_cache={},
        )

    def test_build_request_uses_empty_uid_and_data_key_for_root(self):
        request = build_convert_records_request(self.params, [self.record_uid])

        self.assertEqual(len(request.records), 1)
        item = request.records[0]
        self.assertEqual(item.record_uid, utils.base64_url_decode(self.record_uid))
        self.assertEqual(item.folder_uid, b'')
        self.assertEqual(len(item.record_key_encrypted_by_folder_key), 60)
        self.assertEqual(len(item.record_key_encrypted_by_owner_key), 60)
        self.assertEqual(
            crypto.decrypt_aes_v2(item.record_key_encrypted_by_folder_key, self.data_key),
            self.record_key)
        self.assertEqual(
            crypto.decrypt_aes_v2(item.record_key_encrypted_by_owner_key, self.data_key),
            self.record_key)

    def test_build_request_uses_target_drive_folder_key(self):
        folder_uid = _uid()
        folder_key = utils.generate_aes_key()
        self.params.nested_share_folders[folder_uid] = {
            'name': 'Destination',
            'folder_key_unencrypted': folder_key,
        }

        request = build_convert_records_request(
            self.params, [self.record_uid], folder_uid=folder_uid)

        item = request.records[0]
        self.assertEqual(item.folder_uid, utils.base64_url_decode(folder_uid))
        self.assertEqual(
            crypto.decrypt_aes_v2(item.record_key_encrypted_by_folder_key, folder_key),
            self.record_key)
        self.assertEqual(
            crypto.decrypt_aes_v2(item.record_key_encrypted_by_owner_key, self.data_key),
            self.record_key)

    def test_build_request_rejects_duplicate_records(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            build_convert_records_request(
                self.params, [self.record_uid, self.record_uid])

    def test_build_request_rejects_oversized_batch(self):
        with self.assertRaisesRegex(ValueError, 'at most 100'):
            build_convert_records_request(self.params, [_uid() for _ in range(101)])

    def test_build_request_rejects_malformed_record_uid(self):
        with self.assertRaisesRegex(ValueError, 'valid Keeper UID'):
            build_convert_records_request(self.params, ['not-a-uid'])

    def test_build_request_rejects_missing_record_key(self):
        self.params.record_cache[self.record_uid].pop('record_key_unencrypted')
        with self.assertRaisesRegex(ValueError, 'Record key not found'):
            build_convert_records_request(self.params, [self.record_uid])

    def test_build_request_rejects_invalid_owner_key_length(self):
        self.params.data_key = b'x' * 16
        with self.assertRaisesRegex(ValueError, 'User data key must be a 32-byte key'):
            build_convert_records_request(self.params, [self.record_uid])

    def test_build_request_rejects_invalid_folder_key_length(self):
        folder_uid = _uid()
        self.params.nested_share_folders[folder_uid] = {
            'folder_key_unencrypted': b'x' * 16,
        }
        with self.assertRaisesRegex(ValueError, 'Destination folder key must be a 32-byte key'):
            build_convert_records_request(
                self.params, [self.record_uid], folder_uid=folder_uid)

    def test_build_request_rejects_non_drive_target(self):
        folder_uid = _uid()
        self.params.subfolder_cache[folder_uid] = {
            'folder_key_unencrypted': utils.generate_aes_key(),
        }
        with self.assertRaisesRegex(ValueError, 'not a Nested Share Folder'):
            build_convert_records_request(
                self.params, [self.record_uid], folder_uid=folder_uid)

    def test_convert_results_are_decoded(self):
        response = keeperdrive_convert_pb2.ConvertRecordResponse()
        result = response.results.add()
        result.record_uid = utils.base64_url_decode(self.record_uid)
        result.status = keeperdrive_convert_pb2.OK

        with patch(
                'keepercommander.nested_share_folder.conversion_api.api.communicate_rest',
                return_value=response) as communicate:
            results = convert_records_v3(self.params, [self.record_uid])

        communicate.assert_called_once()
        self.assertEqual(results, [{
            'record_uid': self.record_uid,
            'status': 'OK',
            'success': True,
        }])


class TestClassicToNsfConversionCommand(TestCase):

    def setUp(self):
        self.record_uid = _uid()
        self.params = SimpleNamespace(
            record_cache={
                self.record_uid: {'data_unencrypted': '{"title":"Legacy"}'},
            },
            nested_share_records={},
            nested_share_folders={},
            sync_data=False,
        )

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    def test_omitted_folder_targets_root_and_refreshes_after_success(self, mock_convert):
        mock_convert.return_value = [{
            'record_uid': self.record_uid, 'status': 'OK', 'success': True,
        }]
        command = NestedShareConvertCommand()

        output = StringIO()
        with redirect_stdout(output):
            results = command.execute(
                self.params, records=['Legacy'], folder_uid=None, force=True)

        mock_convert.assert_called_once_with(
            self.params, record_uids=[self.record_uid], folder_uid=None)
        self.assertTrue(self.params.sync_data)
        self.assertIsNone(results)
        self.assertIn('Warning:', output.getvalue())
        self.assertIn('Classic shared-folder membership', output.getvalue())
        self.assertIn(self.record_uid, output.getvalue())
        self.assertIn('Destination: Vault (root)', output.getvalue())
        self.assertNotIn('server support', output.getvalue())

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    def test_classic_folder_is_not_accepted_as_drive_destination(self, mock_convert):
        folder_uid = _uid()
        self.params.folder_cache = {folder_uid: object()}
        self.params.subfolder_cache = {}

        with self.assertRaisesRegex(CommandError, 'not a Nested Share Folder'):
            NestedShareConvertCommand().execute(
                self.params, records=[self.record_uid],
                folder_uid=folder_uid, force=True)
        mock_convert.assert_not_called()

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3',
           return_value=[])
    def test_empty_response_requests_sync_to_reconcile_state(self, _mock_convert):
        with self.assertLogs(level='WARNING'):
            NestedShareConvertCommand().execute(
                self.params, records=[self.record_uid], folder_uid=None, force=True)

        self.assertTrue(self.params.sync_data)

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    @patch('keepercommander.commands.nested_share_folder.conversion_commands.user_choice',
           return_value='n')
    def test_cancelled_confirmation_does_not_call_endpoint(self, _mock_choice, mock_convert):
        NestedShareConvertCommand().execute(
            self.params, records=[self.record_uid], folder_uid=None, force=False)
        mock_convert.assert_not_called()
        self.assertFalse(self.params.sync_data)

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    def test_command_matches_unordered_results_by_uid(self, mock_convert):
        other_uid = _uid()
        self.params.record_cache[other_uid] = {'data_unencrypted': '{"title":"Other"}'}
        mock_convert.return_value = [
            {'record_uid': other_uid, 'status': 'NOT_RECORD_OWNER', 'success': False},
            {'record_uid': self.record_uid, 'status': 'OK', 'success': True},
        ]

        with self.assertLogs(level='INFO') as captured:
            result = NestedShareConvertCommand().execute(
                self.params,
                records=[self.record_uid, other_uid],
                folder_uid=None,
                force=True,
            )

        self.assertIsNone(result)
        self.assertTrue(self.params.sync_data)
        self.assertIn(
            f'Classic record "{self.record_uid}" converted to a Nested Share Record.',
            '\n'.join(captured.output))
        self.assertIn(f'Classic record "{other_uid}" was not converted:',
                      '\n'.join(captured.output))

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    def test_duplicate_results_are_reported_as_ambiguous_and_refresh(self, mock_convert):
        other_uid = _uid()
        self.params.record_cache[other_uid] = {'data_unencrypted': '{"title":"Other"}'}
        mock_convert.return_value = [
            {'record_uid': self.record_uid, 'status': 'OK', 'success': True},
            {'record_uid': self.record_uid, 'status': 'NOT_RECORD_OWNER', 'success': False},
            {'record_uid': other_uid, 'status': 'NOT_RECORD_OWNER', 'success': False},
        ]

        with self.assertLogs(level='INFO') as captured:
            NestedShareConvertCommand().execute(
                self.params,
                records=[self.record_uid, other_uid],
                folder_uid=None,
                force=True,
            )

        self.assertTrue(self.params.sync_data)
        logs = '\n'.join(captured.output)
        self.assertIn('returned duplicate results', logs)
        self.assertIn('result for Classic record', logs)
        self.assertNotIn(
            f'Classic record "{self.record_uid}" converted to a Nested Share Record.', logs)

    @patch('keepercommander.commands.nested_share_folder.conversion_commands._nsf.convert_records_v3')
    def test_unrequested_results_trigger_reconciliation(self, mock_convert):
        unrequested_uid = _uid()
        mock_convert.return_value = [
            {'record_uid': self.record_uid, 'status': 'NOT_RECORD_OWNER', 'success': False},
            {'record_uid': unrequested_uid, 'status': 'OK', 'success': True},
        ]

        with self.assertLogs(level='WARNING') as captured:
            NestedShareConvertCommand().execute(
                self.params, records=[self.record_uid], folder_uid=None, force=True)

        self.assertTrue(self.params.sync_data)
        self.assertIn('unrequested records', '\n'.join(captured.output))

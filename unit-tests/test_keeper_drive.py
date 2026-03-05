"""
Unit tests for KeeperDrive commands and key helpers.

Follows the same patterns as test_command_folder.py and test_command_record.py:
  - Command execute() happy paths and error cases
  - Key utility/parsing functions
"""

import os
import time
from unittest import TestCase, mock
from unittest.mock import Mock, MagicMock, patch

from keepercommander import utils, crypto
from keepercommander.error import CommandError


_DATA_KEY = utils.generate_aes_key()
_ACCOUNT_UID = utils.generate_uid()


def _make_params(**overrides):
    p = Mock()
    p.data_key = _DATA_KEY
    p.account_uid_bytes = utils.base64_url_decode(_ACCOUNT_UID)
    p.rsa_key2 = None
    p.ecc_key = None
    p.user_cache = {}
    p.record_cache = {}
    p.meta_data_cache = {}
    p.folder_cache = {}
    p.subfolder_cache = {}
    p.subfolder_record_cache = {}
    p.record_owner_cache = {}
    p.keeper_drive_folders = {}
    p.keeper_drive_folder_keys = {}
    p.keeper_drive_folder_accesses = {}
    p.keeper_drive_records = {}
    p.keeper_drive_record_data = {}
    p.keeper_drive_record_keys = {}
    p.keeper_drive_record_accesses = {}
    p.keeper_drive_folder_records = {}
    p.keeper_drive_record_sharing_states = {}
    p.keeper_drive_record_links = {}
    p.keeper_drive_raw_dag_data = []
    p.sync_data = False
    p.enterprise = None
    for k, v in overrides.items():
        setattr(p, k, v)
    return p


def _make_folder(folder_uid=None, name='Test Folder', parent_uid=None):
    fuid = folder_uid or utils.generate_uid()
    key = utils.generate_aes_key()
    return fuid, {
        'folder_uid': fuid, 'name': name,
        'parent_uid': parent_uid, 'folder_key_unencrypted': key,
    }


def _make_record(record_uid=None, title='Test Record'):
    ruid = record_uid or utils.generate_uid()
    key = utils.generate_aes_key()
    return ruid, {
        'record_uid': ruid, 'revision': 1, 'version': 3,
        'shared': False, 'record_key_unencrypted': key, 'title': title,
    }


class TestCommandHelpers(TestCase):

    def test_parse_expiration_none(self):
        from keepercommander.commands.keeper_drive.helpers import parse_expiration
        self.assertIsNone(parse_expiration(None, None, 'test'))

    def test_parse_expiration_never(self):
        from keepercommander.commands.keeper_drive.helpers import parse_expiration
        self.assertEqual(parse_expiration('never', None, 'test'), -1)

    def test_parse_expiration_iso_date(self):
        from keepercommander.commands.keeper_drive.helpers import parse_expiration
        result = parse_expiration('2027-01-01T00:00:00Z', None, 'test')
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_parse_expiration_relative(self):
        from keepercommander.commands.keeper_drive.helpers import parse_expiration
        for unit in ('30d', '24h', '30mi', '6mo', '1y'):
            result = parse_expiration(None, unit, 'test')
            self.assertIsInstance(result, int)
            self.assertGreater(result, int(time.time() * 1000))

    def test_parse_expiration_invalid(self):
        from keepercommander.commands.keeper_drive.helpers import parse_expiration
        with self.assertRaises(CommandError):
            parse_expiration('not-a-date', None, 'test')
        with self.assertRaises(CommandError):
            parse_expiration(None, 'invalid', 'test')

    def test_infer_role(self):
        from keepercommander.commands.keeper_drive.helpers import infer_role
        self.assertEqual(infer_role({'can_change_ownership': True}), 'manager')
        self.assertEqual(infer_role({'can_update_access': True, 'can_approve_access': True}), 'content-share-manager')
        self.assertEqual(infer_role({'can_update_access': True}), 'shared-manager')
        self.assertEqual(infer_role({'can_edit': True}), 'content-manager')
        self.assertEqual(infer_role({'can_view': True, 'can_list_access': True}), 'viewer')
        self.assertEqual(infer_role({'can_view_title': True}), 'requestor')
        self.assertEqual(infer_role({}), 'navigator')

    def test_normalize_parent_uid(self):
        from keepercommander.commands.keeper_drive.helpers import normalize_parent_uid, ROOT_FOLDER_UID
        self.assertEqual(normalize_parent_uid(ROOT_FOLDER_UID), 'root')
        self.assertEqual(normalize_parent_uid('root'), 'root')
        self.assertEqual(normalize_parent_uid(None), '')
        self.assertEqual(normalize_parent_uid('abc123'), 'abc123')

    def test_format_timestamp(self):
        from keepercommander.commands.keeper_drive.helpers import format_timestamp
        self.assertIn('2024', format_timestamp(1704067200000))
        self.assertEqual(format_timestamp(0), '')
        self.assertEqual(format_timestamp(None), '')

    def test_command_error_handler(self):
        from keepercommander.commands.keeper_drive.helpers import command_error_handler
        with command_error_handler('kd-test'):
            pass
        with self.assertRaises(CommandError):
            with command_error_handler('kd-test'):
                raise CommandError('kd-test', 'specific')
        with self.assertRaises(CommandError):
            with command_error_handler('kd-test'):
                raise RuntimeError('generic')

    def test_check_result(self):
        from keepercommander.commands.keeper_drive.helpers import check_result
        check_result({'success': True}, 'kd-test')
        with self.assertRaises(CommandError):
            check_result({'success': False, 'message': 'failed'}, 'kd-test')

    def test_find_folder_location(self):
        from keepercommander.commands.keeper_drive.helpers import find_folder_location, ROOT_FOLDER_UID
        ruid = utils.generate_uid()
        fuid, fobj = _make_folder(name='Docs')
        params = _make_params(
            keeper_drive_folder_records={fuid: {ruid}},
            keeper_drive_folders={fuid: fobj},
        )
        self.assertEqual(find_folder_location(params, ruid), 'Docs')
        params2 = _make_params(keeper_drive_folder_records={ROOT_FOLDER_UID: {ruid}})
        self.assertEqual(find_folder_location(params2, ruid), 'root')
        self.assertEqual(find_folder_location(_make_params(), 'missing'), '')

    def test_load_record_metadata_from_cache(self):
        from keepercommander.commands.keeper_drive.helpers import load_record_metadata
        ruid = utils.generate_uid()
        params = _make_params(
            keeper_drive_record_data={ruid: {
                'data_json': {'title': 'Cached', 'type': 'login', 'fields': [], 'notes': 'n'}
            }},
            keeper_drive_records={ruid: {'revision': 5, 'version': 3}},
        )
        result = load_record_metadata(params, ruid)
        self.assertEqual(result['title'], 'Cached')
        self.assertEqual(result['revision'], 5)


class TestSync(TestCase):

    def test_accumulator_and_has_data(self):
        from keepercommander.keeper_drive.sync import create_accumulator, has_data
        acc = create_accumulator()
        self.assertFalse(has_data(acc))
        acc['folders'].append('x')
        self.assertTrue(has_data(acc))

    def test_clear_caches(self):
        from keepercommander.keeper_drive.sync import clear_caches
        params = _make_params()
        params.keeper_drive_folders['f1'] = {'name': 'x'}
        params.keeper_drive_records['r1'] = {'title': 'y'}
        clear_caches(params)
        self.assertEqual(len(params.keeper_drive_folders), 0)
        self.assertEqual(len(params.keeper_drive_records), 0)

    def test_process_empty(self):
        from keepercommander.keeper_drive.sync import process, create_accumulator
        process(_make_params(), create_accumulator())


class TestKeeperDriveFolderCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.keeper_drive.folder_api.create_folder_v3')
    def test_mkdir(self, mock_create):
        from keepercommander.commands.keeper_drive import KeeperDriveMkdirCommand
        mock_create.return_value = {
            'folder_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        cmd = KeeperDriveMkdirCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(), folder='NewFolder')
        mock_create.assert_called_once()

    @patch('keepercommander.keeper_drive.folder_api.update_folder_v3')
    def test_update_folder(self, mock_update):
        from keepercommander.commands.keeper_drive import KeeperDriveUpdateFolderCommand
        mock_update.return_value = {
            'folder_uid': 'fuid', 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        fuid, fobj = _make_folder(name='OldName')
        cmd = KeeperDriveUpdateFolderCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_folders={fuid: fobj}),
                        folder=fuid, folder_name='NewName')
        mock_update.assert_called_once()

    def test_list_empty(self):
        from keepercommander.commands.keeper_drive import KeeperDriveListCommand
        cmd = KeeperDriveListCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params())

    def test_list_with_data(self):
        from keepercommander.commands.keeper_drive import KeeperDriveListCommand
        fuid, fobj = _make_folder(name='Documents')
        ruid, robj = _make_record(title='Note')
        params = _make_params(
            keeper_drive_folders={fuid: fobj},
            keeper_drive_records={ruid: robj},
            keeper_drive_record_data={ruid: {'data_json': {'title': 'Note', 'type': 'general'}}},
        )
        cmd = KeeperDriveListCommand()
        with mock.patch('builtins.print'):
            cmd.execute(params, folders=True)
            cmd.execute(params, records=True)


class TestKeeperDriveRecordCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.keeper_drive.record_api.create_record_v3')
    def test_add_record(self, mock_create):
        from keepercommander.commands.keeper_drive import KeeperDriveAddRecordCommand
        mock_create.return_value = {
            'record_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True, 'revision': 1,
        }
        fuid, fobj = _make_folder()
        cmd = KeeperDriveAddRecordCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_folders={fuid: fobj}, record_type_cache={}),
                        title='New Record', folder_uid=fuid, force=True,
                        record_type='general', fields=[])

    @patch('keepercommander.keeper_drive.folder_record_api.add_record_to_folder_v3')
    def test_add_record_to_folder(self, mock_add):
        from keepercommander.commands.keeper_drive import KeeperDriveAddRecordToFolderCommand
        mock_add.return_value = {
            'folder_uid': 'f', 'record_uid': 'r',
            'status': 'SUCCESS', 'message': '', 'success': True,
        }
        fuid, fobj = _make_folder()
        ruid, robj = _make_record()
        cmd = KeeperDriveAddRecordToFolderCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_folders={fuid: fobj},
                                     keeper_drive_records={ruid: robj}),
                        folder=fuid, record=ruid)

    @patch('keepercommander.keeper_drive.folder_record_api.remove_record_from_folder_v3')
    def test_remove_record_from_folder(self, mock_remove):
        from keepercommander.commands.keeper_drive import KeeperDriveRemoveRecordFromFolderCommand
        mock_remove.return_value = {
            'folder_uid': 'f', 'record_uid': 'r',
            'status': 'SUCCESS', 'message': '', 'success': True,
        }
        fuid, fobj = _make_folder()
        ruid, robj = _make_record()
        cmd = KeeperDriveRemoveRecordFromFolderCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_folders={fuid: fobj},
                                     keeper_drive_records={ruid: robj}),
                        folder=fuid, record=ruid)


class TestKeeperDriveSharingCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.keeper_drive.record_api.share_record_v3')
    def test_share_record(self, mock_share):
        from keepercommander.commands.keeper_drive import KeeperDriveShareRecordCommand
        ruid, robj = _make_record()
        mock_share.return_value = {
            'success': True, 'message': '',
            'results': [{'record_uid': ruid, 'success': True, 'message': '', 'pending': False}],
        }
        cmd = KeeperDriveShareRecordCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_records={ruid: robj}),
                        record=ruid, email='user@example.com',
                        action='grant', role='viewer')

    @patch('keepercommander.keeper_drive.record_api.unshare_record_v3')
    def test_share_record_revoke(self, mock_unshare):
        from keepercommander.commands.keeper_drive import KeeperDriveShareRecordCommand
        ruid, robj = _make_record()
        mock_unshare.return_value = {
            'success': True, 'message': '',
            'results': [{'record_uid': ruid, 'success': True, 'message': ''}],
        }
        cmd = KeeperDriveShareRecordCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(keeper_drive_records={ruid: robj}),
                        record=ruid, email='user@example.com',
                        action='revoke')


class TestKeeperDriveDisplayCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.keeper_drive.record_api.get_record_details_v3')
    def test_get_record_details(self, mock_details):
        from keepercommander.commands.keeper_drive import KeeperDriveGetRecordDetailsCommand
        mock_details.return_value = {'data': [], 'errors': []}
        cmd = KeeperDriveGetRecordDetailsCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(), record_uids=[utils.generate_uid()])

    @patch('keepercommander.keeper_drive.record_api.get_record_accesses_v3')
    def test_get_record_access(self, mock_accesses):
        from keepercommander.commands.keeper_drive import KeeperDriveGetRecordAccessCommand
        mock_accesses.return_value = {'record_accesses': [], 'forbidden_records': []}
        cmd = KeeperDriveGetRecordAccessCommand()
        with mock.patch('builtins.print'), \
             mock.patch.dict('sys.modules', {'keepercommander.display': MagicMock()}):
            cmd.execute(_make_params(), record_uids=[utils.generate_uid()])


class TestCommandRegistration(TestCase):

    def test_all_commands_registered(self):
        from keepercommander.commands.keeper_drive import register_commands
        commands = {}
        register_commands(commands)
        expected = [
            'kd-mkdir', 'kd-record-add', 'kd-record-update', 'kd-rndir',
            'kd-list', 'kd-share-folder', 'kd-record-details', 'kd-record-access',
            'kd-share-record', 'kd-record-permission', 'kd-transfer-record',
            'kd-add-record-to-folder', 'kd-remove-record-from-folder', 'kd-ln',
            'kd-folder-access', 'kd-rm', 'kd-rmdir', 'kd-shortcut', 'kd-get',
        ]
        for name in expected:
            self.assertIn(name, commands)
        removed = ['kd-grant-access', 'kd-update-access', 'kd-revoke-access',
                    'kd-update-record-share', 'kd-unshare-record']
        for name in removed:
            self.assertNotIn(name, commands)

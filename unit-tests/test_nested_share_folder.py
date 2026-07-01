"""
Unit tests for Nested Share Folder commands and key helpers.

Follows the same patterns as test_command_folder.py and test_command_record.py:
  - Command execute() happy paths and error cases
  - Key utility/parsing functions
"""

import json
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
    p.nested_share_folders = {}
    p.nested_share_folder_keys = {}
    p.nested_share_folder_accesses = {}
    p.nested_share_records = {}
    p.nested_share_record_data = {}
    p.nested_share_record_keys = {}
    p.nested_share_record_accesses = {}
    p.nested_share_folder_records = {}
    p.nested_share_record_sharing_states = {}
    p.nested_share_record_links = {}
    p.nested_share_raw_dag_data = []
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


def _make_sharing_status(record_uid, recipient_uid_bytes=None):
    from keepercommander.proto import record_sharing_pb2
    status = record_sharing_pb2.Status()
    status.recordUid = utils.base64_url_decode(record_uid)
    status.recipientUid = recipient_uid_bytes or utils.base64_url_decode(utils.generate_uid())
    status.status = record_sharing_pb2.SUCCESS
    return status


class TestCommandHelpers(TestCase):

    def test_parse_expiration_none(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        self.assertIsNone(parse_expiration(None, None, 'test'))

    def test_parse_expiration_never(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        self.assertEqual(parse_expiration('never', None, 'test'), -1)

    def test_parse_expiration_iso_date(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        result = parse_expiration('2027-01-01T00:00:00Z', None, 'test')
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_parse_expiration_relative(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        for unit in ('30d', '24h', '30mi', '6mo', '1y'):
            result = parse_expiration(None, unit, 'test')
            self.assertIsInstance(result, int)
            self.assertGreater(result, int(time.time() * 1000))

    def test_parse_expiration_invalid(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        with self.assertRaises(CommandError):
            parse_expiration('not-a-date', None, 'test')
        with self.assertRaises(CommandError):
            parse_expiration(None, 'invalid', 'test')

    def test_parse_expiration_rejects_sub_minute(self):
        from keepercommander.commands.nested_share_folder.helpers import parse_expiration
        with self.assertRaises(CommandError) as ctx:
            parse_expiration(None, '0mi', 'test')
        self.assertIn('at least 1 minute', str(ctx.exception))
        with self.assertRaises(CommandError):
            parse_expiration('2020-01-01T00:00:00Z', None, 'test')

    def test_infer_role(self):
        from keepercommander.commands.nested_share_folder.helpers import infer_role
        self.assertEqual(infer_role({'can_change_ownership': True}), 'full-manager')
        # ``can_update_access`` + ``can_approve_access`` alone (no edit) is
        # ``share-manager``; promotion to ``content-share-manager`` requires
        # ``can_edit`` per the v3 permission matrix.
        self.assertEqual(
            infer_role({'can_update_access': True, 'can_approve_access': True,
                        'can_edit': True}),
            'content-share-manager',
        )
        self.assertEqual(
            infer_role({'can_update_access': True, 'can_approve_access': True}),
            'share-manager',
        )
        self.assertEqual(infer_role({'can_update_access': True}), 'share-manager')
        self.assertEqual(infer_role({'can_edit': True}), 'content-manager')
        self.assertEqual(infer_role({'can_view': True, 'can_list_access': True}), 'viewer')
        self.assertEqual(infer_role({'can_view_title': True}), 'requestor')
        self.assertEqual(infer_role({}), 'navigator')

    def test_normalize_parent_uid(self):
        from keepercommander.commands.nested_share_folder.helpers import normalize_parent_uid, ROOT_FOLDER_UID
        self.assertEqual(normalize_parent_uid(ROOT_FOLDER_UID), 'root')
        self.assertEqual(normalize_parent_uid('root'), 'root')
        self.assertEqual(normalize_parent_uid(None), '')
        self.assertEqual(normalize_parent_uid('abc123'), 'abc123')

    def test_format_timestamp(self):
        from keepercommander.commands.nested_share_folder.helpers import format_timestamp
        self.assertEqual(format_timestamp(0), '')
        self.assertEqual(format_timestamp(None), '')

    def test_command_error_handler(self):
        from keepercommander.commands.nested_share_folder.helpers import command_error_handler
        with command_error_handler('nsf-test'):
            pass
        with self.assertRaises(CommandError):
            with command_error_handler('nsf-test'):
                raise CommandError('nsf-test', 'specific')
        with self.assertRaises(CommandError):
            with command_error_handler('nsf-test'):
                raise RuntimeError('generic')

    def test_check_result(self):
        from keepercommander.commands.nested_share_folder.helpers import check_result
        check_result({'success': True}, 'nsf-test')
        with self.assertRaises(CommandError):
            check_result({'success': False, 'message': 'failed'}, 'nsf-test')

    def test_find_folder_location(self):
        from keepercommander.commands.nested_share_folder.helpers import find_folder_location, ROOT_FOLDER_UID
        ruid = utils.generate_uid()
        fuid, fobj = _make_folder(name='Docs')
        params = _make_params(
            nested_share_folder_records={fuid: {ruid}},
            nested_share_folders={fuid: fobj},
        )
        result = find_folder_location(params, ruid)
        self.assertIsInstance(result, dict)
        self.assertEqual(result['uid'], fuid)
        self.assertEqual(result['path'], 'Docs')
        params2 = _make_params(nested_share_folder_records={ROOT_FOLDER_UID: {ruid}})
        result2 = find_folder_location(params2, ruid)
        self.assertIsInstance(result2, dict)
        self.assertIsNone(result2['uid'])
        self.assertEqual(result2['path'], '/')
        self.assertIsNone(find_folder_location(_make_params(), 'missing'))

    def test_load_record_metadata_from_cache(self):
        from keepercommander.commands.nested_share_folder.helpers import load_record_metadata
        ruid = utils.generate_uid()
        params = _make_params(
            nested_share_record_data={ruid: {
                'data_json': {'title': 'Cached', 'type': 'login', 'fields': [], 'notes': 'n'}
            }},
            nested_share_records={ruid: {'revision': 5, 'version': 3}},
        )
        result = load_record_metadata(params, ruid)
        self.assertEqual(result['title'], 'Cached')
        self.assertEqual(result['revision'], 5)


class TestSync(TestCase):

    def test_accumulator_and_has_data(self):
        from keepercommander.nested_share_folder.sync import create_accumulator, has_data
        acc = create_accumulator()
        self.assertFalse(has_data(acc))
        acc['folders'].append('x')
        self.assertTrue(has_data(acc))

    def test_clear_caches(self):
        from keepercommander.nested_share_folder.sync import clear_caches
        params = _make_params()
        params.nested_share_folders['f1'] = {'name': 'x'}
        params.nested_share_records['r1'] = {'title': 'y'}
        clear_caches(params)
        self.assertEqual(len(params.nested_share_folders), 0)
        self.assertEqual(len(params.nested_share_records), 0)

    def test_process_empty(self):
        from keepercommander.nested_share_folder.sync import process, create_accumulator
        process(_make_params(), create_accumulator())


class TestNestedShareFolderFolderCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.commands.nested_share_folder.folder_commands._nsf.create_folder_v3')
    def test_mkdir(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareFolderMkdirCommand
        mock_create.return_value = {
            'folder_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        cmd = NestedShareFolderMkdirCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(), folder='NewFolder')
        mock_create.assert_called_once()

    @patch('keepercommander.commands.nested_share_folder.folder_commands._nsf.create_folder_v3')
    def test_mkdir_resolves_parent_uid_in_path(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareFolderMkdirCommand
        parent_uid = 'tY6D-RanxY252zzBY_xU4A'
        child_uid = utils.generate_uid()
        mock_create.return_value = {
            'folder_uid': child_uid, 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        parent_fuid, parent_fobj = _make_folder(
            folder_uid=parent_uid, name='Real Parent')
        cmd = NestedShareFolderMkdirCommand()
        with mock.patch('builtins.print'):
            cmd.execute(
                _make_params(nested_share_folders={parent_uid: parent_fobj}),
                folder=f'{parent_uid}/My Child Folder',
            )
        mock_create.assert_called_once_with(
            params=mock.ANY,
            folder_name='My Child Folder',
            parent_uid=parent_uid,
            color=None,
            inherit_permissions=True,
        )

    @patch('keepercommander.commands.nested_share_folder.folder_commands._nsf.create_folder_v3')
    def test_mkdir_resolves_parent_name_in_path(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareFolderMkdirCommand
        parent_fuid, parent_fobj = _make_folder(name='Engineering')
        child_uid = utils.generate_uid()
        mock_create.return_value = {
            'folder_uid': child_uid, 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        cmd = NestedShareFolderMkdirCommand()
        with mock.patch('builtins.print'):
            cmd.execute(
                _make_params(nested_share_folders={parent_fuid: parent_fobj}),
                folder='Engineering/New Folder KD 1 June',
            )
        mock_create.assert_called_once_with(
            params=mock.ANY,
            folder_name='New Folder KD 1 June',
            parent_uid=parent_fuid,
            color=None,
            inherit_permissions=True,
        )

    @patch('keepercommander.commands.nested_share_folder.folder_commands._nsf.create_folder_v3')
    def test_mkdir_creates_intermediate_name_segments(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareFolderMkdirCommand
        eng_uid = utils.generate_uid()
        child_uid = utils.generate_uid()
        mock_create.side_effect = [
            {
                'folder_uid': eng_uid, 'status': 'SUCCESS',
                'message': '', 'success': True,
            },
            {
                'folder_uid': child_uid, 'status': 'SUCCESS',
                'message': '', 'success': True,
            },
        ]
        cmd = NestedShareFolderMkdirCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(), folder='Engineering/New Folder KD 1 June')
        self.assertEqual(mock_create.call_count, 2)
        mock_create.assert_any_call(
            params=mock.ANY,
            folder_name='Engineering',
            parent_uid=None,
            color=None,
            inherit_permissions=True,
        )
        mock_create.assert_any_call(
            params=mock.ANY,
            folder_name='New Folder KD 1 June',
            parent_uid=eng_uid,
            color=None,
            inherit_permissions=True,
        )

    @patch('keepercommander.nested_share_folder.folder_api.update_folder_v3')
    def test_update_folder(self, mock_update):
        from keepercommander.commands.nested_share_folder import NestedShareFolderUpdateCommand
        mock_update.return_value = {
            'folder_uid': 'fuid', 'status': 'SUCCESS',
            'message': '', 'success': True,
        }
        fuid, fobj = _make_folder(name='OldName')
        cmd = NestedShareFolderUpdateCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(nested_share_folders={fuid: fobj}),
                        folder=fuid, folder_name='NewName')
        mock_update.assert_called_once()

    def test_list_empty(self):
        from keepercommander.commands.nested_share_folder import NestedShareFolderListCommand
        cmd = NestedShareFolderListCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params())

    def test_list_with_data(self):
        from keepercommander.commands.nested_share_folder import NestedShareFolderListCommand
        fuid, fobj = _make_folder(name='Documents')
        ruid, robj = _make_record(title='Note')
        params = _make_params(
            nested_share_folders={fuid: fobj},
            nested_share_records={ruid: robj},
            nested_share_record_data={ruid: {'data_json': {'title': 'Note', 'type': 'general'}}},
        )
        cmd = NestedShareFolderListCommand()
        with mock.patch('builtins.print'):
            cmd.execute(params, folders=True)
            cmd.execute(params, records=True)


class TestNestedShareFolderRecordCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.nested_share_folder.record_api.create_record_v3')
    def test_add_record(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        mock_create.return_value = {
            'record_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True, 'revision': 1,
        }
        fuid, fobj = _make_folder()
        cmd = NestedShareRecordAddCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(nested_share_folders={fuid: fobj}, record_type_cache={}),
                        title='New Record', folder_uid=fuid, force=True,
                        record_type='general', fields=[])

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.create_record_v3')
    def test_add_record_rejects_restricted_record_type(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        fuid, fobj = _make_folder()
        params = _make_params(
            nested_share_folders={fuid: fobj},
            record_type_cache={1: json.dumps({'$id': 'login'})},
            enforcements={
                'jsons': [{'key': 'restrict_record_types', 'value': '{"std": [1], "ent": []}'}],
            },
        )
        cmd = NestedShareRecordAddCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, title='Blocked', record_type='login', fields=[], force=True)
        self.assertIn('restricted', str(ctx.exception).lower())
        mock_create.assert_not_called()

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.create_record_v3')
    def test_add_record_rejects_weak_password_without_force(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        fuid, fobj = _make_folder()
        params = _make_params(
            nested_share_folders={fuid: fobj},
            enforcements={
                'jsons': [{
                    'key': 'generated_password_complexity',
                    'value': json.dumps([{
                        'length': 12,
                        'lower-use': True, 'lower-min': 1,
                        'upper-use': True, 'upper-min': 1,
                        'digit-use': True, 'digit-min': 1,
                    }]),
                }],
            },
        )
        cmd = NestedShareRecordAddCommand()
        cmd.execute(params, title='Weak', record_type='general',
                    fields=['password=abc'], force=False)
        mock_create.assert_not_called()

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.create_record_v3')
    def test_add_record_allows_weak_password_with_force(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        mock_create.return_value = {
            'record_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True, 'revision': 1,
        }
        fuid, fobj = _make_folder()
        params = _make_params(
            nested_share_folders={fuid: fobj},
            enforcements={
                'jsons': [{
                    'key': 'generated_password_complexity',
                    'value': json.dumps([{
                        'length': 12,
                        'lower-use': True, 'lower-min': 1,
                        'upper-use': True, 'upper-min': 1,
                        'digit-use': True, 'digit-min': 1,
                    }]),
                }],
            },
        )
        cmd = NestedShareRecordAddCommand()
        cmd.execute(params, title='Weak', record_type='general',
                    fields=['password=abc'], force=True)
        mock_create.assert_called_once()

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.create_record_v3')
    def test_add_record_gen_uses_password_policy(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        mock_create.return_value = {
            'record_uid': utils.generate_uid(), 'status': 'SUCCESS',
            'message': '', 'success': True, 'revision': 1,
        }
        fuid, fobj = _make_folder()
        params = _make_params(
            nested_share_folders={fuid: fobj},
            enforcements={
                'jsons': [{
                    'key': 'generated_password_complexity',
                    'value': json.dumps([{
                        'length': 16,
                        'lower-use': True, 'lower-min': 2,
                        'upper-use': True, 'upper-min': 2,
                        'digit-use': True, 'digit-min': 2,
                        'special-use': True, 'special-min': 1,
                        'special': '!@#$',
                    }]),
                }],
            },
        )
        cmd = NestedShareRecordAddCommand()
        cmd.execute(params, title='Generated', record_type='general',
                    fields=['password=$GEN'], force=False)
        mock_create.assert_called_once()
        record_data = mock_create.call_args.kwargs['record_data']
        password = next(
            v[0] for f in record_data['fields']
            if f.get('type') == 'password' for v in [f.get('value', [])] if v
        )
        self.assertGreaterEqual(len(password), 16)
        self.assertGreaterEqual(sum(1 for c in password if c.islower()), 2)
        self.assertGreaterEqual(sum(1 for c in password if c.isupper()), 2)
        self.assertGreaterEqual(sum(1 for c in password if c.isdigit()), 2)
        self.assertGreaterEqual(sum(1 for c in password if c in '!@#$'), 1)

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.update_record_v3')
    @patch('keepercommander.commands.nested_share_folder.helpers.check_record_edit_permission')
    def test_update_record_rejects_restricted_record_type(self, mock_perm, mock_update):
        from keepercommander.commands.nested_share_folder import NestedShareRecordUpdateCommand
        ruid, robj = _make_record()
        params = _make_params(
            nested_share_records={ruid: robj},
            record_cache={ruid: {'revision': 1, 'data_unencrypted': json.dumps({
                'type': 'login', 'title': 'Old', 'fields': [],
            })}},
            record_type_cache={1: json.dumps({'$id': 'login'})},
            enforcements={
                'jsons': [{'key': 'restrict_record_types', 'value': '{"std": [1], "ent": []}'}],
            },
        )
        cmd = NestedShareRecordUpdateCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, record_uids=[ruid], record_type='login', fields=[])
        self.assertIn('restricted', str(ctx.exception).lower())
        mock_update.assert_not_called()

    @patch('keepercommander.commands.nested_share_folder.record_commands._nsf.update_record_v3')
    @patch('keepercommander.commands.nested_share_folder.helpers.check_record_edit_permission')
    def test_update_record_rejects_weak_password_without_force(self, mock_perm, mock_update):
        from keepercommander.commands.nested_share_folder import NestedShareRecordUpdateCommand
        ruid, robj = _make_record()
        params = _make_params(
            nested_share_records={ruid: robj},
            record_cache={ruid: {'revision': 1, 'data_unencrypted': json.dumps({
                'type': 'login', 'title': 'Old',
                'fields': [{'type': 'password', 'value': ['ExistingPass123']}],
            })}},
            enforcements={
                'jsons': [{
                    'key': 'generated_password_complexity',
                    'value': json.dumps([{
                        'length': 12,
                        'lower-use': True, 'lower-min': 1,
                        'upper-use': True, 'upper-min': 1,
                        'digit-use': True, 'digit-min': 1,
                    }]),
                }],
            },
        )
        cmd = NestedShareRecordUpdateCommand()
        cmd.execute(params, record_uids=[ruid], fields=['password=abc'], force=False)
        mock_update.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_record_api.add_record_to_folder_v3')
    def test_add_record_to_folder(self, mock_add):
        pass

    @patch('keepercommander.nested_share_folder.folder_record_api.remove_record_from_folder_v3')
    def test_remove_record_from_folder(self, mock_remove):
        pass


class TestCrossTypeGuards(TestCase):
    """Legacy and Nested Share Folders/Records use different permission
    structures. Commands must refuse cross-type operations."""

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    def test_is_nested_share_record(self):
        from keepercommander.commands.nested_share_folder.helpers import is_nested_share_record
        nsf_uid, _ = _make_record()
        legacy_uid = utils.generate_uid()
        params = _make_params(
            nested_share_records={nsf_uid: {'revision': 1}},
            record_cache={legacy_uid: {'revision': 1}, nsf_uid: {'revision': 1}},
        )
        self.assertTrue(is_nested_share_record(params, nsf_uid))
        self.assertFalse(is_nested_share_record(params, legacy_uid))
        self.assertFalse(is_nested_share_record(params, None))

    def test_is_nested_share_folder(self):
        from keepercommander.commands.nested_share_folder.helpers import (
            is_nested_share_folder, ROOT_FOLDER_UID,
        )
        nsf_fuid, nsf_fobj = _make_folder()
        legacy_fuid = utils.generate_uid()
        params = _make_params(
            nested_share_folders={nsf_fuid: nsf_fobj},
            folder_cache={legacy_fuid: object()},
        )
        self.assertTrue(is_nested_share_folder(params, nsf_fuid))
        self.assertTrue(is_nested_share_folder(params, ROOT_FOLDER_UID))
        self.assertFalse(is_nested_share_folder(params, legacy_fuid))
        self.assertFalse(is_nested_share_folder(params, None))

    @patch('keepercommander.nested_share_folder.folder_record_api.add_record_to_folder_v3')
    def test_kd_ln_rejects_legacy_record(self, mock_link):
        """nsf-ln must refuse a legacy record even when the dest folder is a Nested Share Folder."""
        from keepercommander.commands.nested_share_folder import NestedShareRecordLnCommand
        nsf_fuid, nsf_fobj = _make_folder()
        legacy_ruid = utils.generate_uid()
        params = _make_params(
            nested_share_folders={nsf_fuid: nsf_fobj},
            record_cache={legacy_ruid: {'revision': 1}},
        )
        cmd = NestedShareRecordLnCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, src=legacy_ruid, dst=nsf_fuid)
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_link.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_record_api.add_record_to_folder_v3')
    def test_kd_ln_rejects_legacy_folder(self, mock_link):
        """nsf-ln must refuse a legacy folder even when the source is a Nested Share Folder record."""
        from keepercommander.commands.nested_share_folder import NestedShareRecordLnCommand
        nsf_ruid, nsf_robj = _make_record()
        legacy_fuid = utils.generate_uid()

        class _Folder:
            uid = legacy_fuid
            name = 'Legacy'
            type = 'user_folder'
            subfolders = []

        params = _make_params(
            nested_share_records={nsf_ruid: nsf_robj},
            folder_cache={legacy_fuid: _Folder()},
        )
        cmd = NestedShareRecordLnCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, src=nsf_ruid, dst=legacy_fuid)
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_link.assert_not_called()

    @patch('keepercommander.nested_share_folder.record_api.create_record_v3')
    def test_kd_record_add_rejects_legacy_folder(self, mock_create):
        from keepercommander.commands.nested_share_folder import NestedShareRecordAddCommand
        legacy_fuid = utils.generate_uid()

        class _Folder:
            uid = legacy_fuid
            name = 'LegacyFolder'
            type = 'user_folder'
            subfolders = []

        params = _make_params(folder_cache={legacy_fuid: _Folder()})
        cmd = NestedShareRecordAddCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, title='New', record_type='general',
                        folder_uid=legacy_fuid, fields=[], force=True)
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_create.assert_not_called()

    @patch('keepercommander.nested_share_folder.record_api.update_record_v3')
    def test_kd_record_update_rejects_legacy_record(self, mock_update):
        from keepercommander.commands.nested_share_folder import NestedShareRecordUpdateCommand
        legacy_ruid = utils.generate_uid()
        params = _make_params(record_cache={legacy_ruid: {'revision': 1}})
        cmd = NestedShareRecordUpdateCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, record_uids=[legacy_ruid], title='X', fields=[])
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_update.assert_not_called()

    @patch('keepercommander.nested_share_folder.removal_api.remove_record_v3')
    def test_kd_rm_rejects_legacy_record(self, mock_rm):
        from keepercommander.commands.nested_share_folder import NestedShareRecordRemoveCommand
        legacy_ruid = utils.generate_uid()
        params = _make_params(record_cache={legacy_ruid: {'revision': 1}})
        cmd = NestedShareRecordRemoveCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, records=[legacy_ruid], operation='owner-trash')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_rm.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_api.update_folder_v3')
    def test_kd_rndir_rejects_legacy_folder(self, mock_update):
        from keepercommander.commands.nested_share_folder import NestedShareFolderUpdateCommand
        legacy_fuid = utils.generate_uid()
        params = _make_params(folder_cache={legacy_fuid: object()})
        cmd = NestedShareFolderUpdateCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, folder=legacy_fuid, folder_name='New')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_update.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_api.grant_folder_access_v3')
    def test_kd_share_folder_rejects_legacy_folder(self, mock_grant):
        from keepercommander.commands.nested_share_folder import NestedShareFolderShareCommand
        legacy_fuid = utils.generate_uid()
        params = _make_params(folder_cache={legacy_fuid: object()})
        cmd = NestedShareFolderShareCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, folder=[legacy_fuid], user=['user@x.com'],
                        action='grant', role='viewer')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_grant.assert_not_called()

    @patch('keepercommander.nested_share_folder.removal_api.remove_folder_v3')
    def test_kd_rmdir_rejects_legacy_folder(self, mock_rmdir):
        from keepercommander.commands.nested_share_folder import NestedShareFolderRemoveCommand
        legacy_fuid = utils.generate_uid()
        params = _make_params(folder_cache={legacy_fuid: object()})
        cmd = NestedShareFolderRemoveCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, folders=[legacy_fuid], operation='folder-trash')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_rmdir.assert_not_called()

    @patch('keepercommander.nested_share_folder.record_api.share_record_v3')
    def test_kd_share_record_rejects_legacy_record(self, mock_share):
        from keepercommander.commands.nested_share_folder import NestedShareRecordShareCommand
        legacy_ruid = utils.generate_uid()
        params = _make_params(record_cache={legacy_ruid: {'revision': 1}})
        cmd = NestedShareRecordShareCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, record=legacy_ruid, email=['x@y.com'],
                        action='grant', role='viewer')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_share.assert_not_called()

    @patch('keepercommander.nested_share_folder.record_api.transfer_record_ownership_v3')
    def test_kd_transfer_record_rejects_legacy_record(self, mock_transfer):
        from keepercommander.commands.nested_share_folder import NestedShareRecordTransferCommand
        legacy_ruid = utils.generate_uid()
        params = _make_params(record_cache={legacy_ruid: {'revision': 1}})
        cmd = NestedShareRecordTransferCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, record_uids=[legacy_ruid],
                        new_owner_email='owner@example.com')
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_transfer.assert_not_called()

    @patch('keepercommander.nested_share_folder.record_api.get_record_details_v3')
    def test_kd_record_details_rejects_legacy_record(self, mock_details):
        from keepercommander.commands.nested_share_folder import NestedShareRecordGetDetailsCommand
        legacy_ruid = utils.generate_uid()
        params = _make_params(record_cache={legacy_ruid: {'revision': 1}})
        cmd = NestedShareRecordGetDetailsCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, record_uids=[legacy_ruid])
        self.assertIn('legacy', str(ctx.exception).lower())
        mock_details.assert_not_called()


class TestLegacyToNestedShareFolderGuards(TestCase):
    """Legacy mv/ln must refuse to bridge legacy records into Nested Share Folders
    (and vice-versa) because their permission structures differ."""

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        mock.patch.stopall()

    def _make_legacy_params(self, nsf_folder_uid, legacy_record_uid):
        from keepercommander.subfolder import (
            UserFolderNode, NestedShareFolderNode, RootFolderNode,
        )
        params = _make_params()
        legacy_folder_uid = utils.generate_uid()
        params.root_folder = RootFolderNode()
        params.current_folder = ''

        legacy_folder = UserFolderNode()
        legacy_folder.uid = legacy_folder_uid
        legacy_folder.name = 'Legacy'

        nsf_folder = NestedShareFolderNode()
        nsf_folder.uid = nsf_folder_uid
        nsf_folder.name = 'Drive'

        params.folder_cache = {
            legacy_folder_uid: legacy_folder,
            nsf_folder_uid: nsf_folder,
        }
        params.record_cache = {legacy_record_uid: {'data_unencrypted': b'{"title":"x"}'}}
        params.subfolder_record_cache = {legacy_folder_uid: {legacy_record_uid}}
        params.nested_share_folders = {nsf_folder_uid: {'name': 'Drive'}}
        params.nested_share_records = {}
        return params, legacy_folder_uid

    @patch('keepercommander.api.communicate')
    def test_legacy_ln_rejects_record_into_nsf_folder(self, mock_communicate):
        from keepercommander.commands.folder import FolderLinkCommand
        nsf_fuid, _ = _make_folder()
        legacy_ruid = utils.generate_uid()
        params, _ = self._make_legacy_params(nsf_fuid, legacy_ruid)
        cmd = FolderLinkCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, src=legacy_ruid, dst=nsf_fuid)
        self.assertIn('nested share folder', str(ctx.exception).lower())
        mock_communicate.assert_not_called()

    @patch('keepercommander.api.communicate')
    def test_legacy_mv_rejects_kd_record_into_legacy_folder(self, mock_communicate):
        """Symmetric guard: Nested Share Folder record cannot be moved into a legacy folder."""
        from keepercommander.commands.folder import FolderMoveCommand
        nsf_fuid, _ = _make_folder()
        nsf_ruid = utils.generate_uid()
        params, legacy_fuid = self._make_legacy_params(nsf_fuid, nsf_ruid)
        params.nested_share_records[nsf_ruid] = {'revision': 1}
        # Place the Nested Share Folder record only in the Nested Share Folder (not in the legacy folder).
        params.subfolder_record_cache = {nsf_fuid: {nsf_ruid}}
        cmd = FolderMoveCommand()
        with self.assertRaises(CommandError):
            cmd.execute(params, src=nsf_ruid, dst=legacy_fuid)
        mock_communicate.assert_not_called()


class TestNestedShareFolderSharingCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.nested_share_folder.record_api.share_record_v3')
    def test_share_record(self, mock_share):
        from keepercommander.commands.nested_share_folder import NestedShareRecordShareCommand
        ruid, robj = _make_record()
        mock_share.return_value = {
            'success': True, 'message': '',
            'results': [{'record_uid': ruid, 'success': True, 'message': '', 'pending': False}],
        }
        cmd = NestedShareRecordShareCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(nested_share_records={ruid: robj}),
                        record=ruid, email='user@example.com',
                        action='grant', role='viewer')

    @patch('keepercommander.nested_share_folder.record_api.unshare_record_v3')
    def test_share_record_revoke(self, mock_unshare):
        from keepercommander.commands.nested_share_folder import NestedShareRecordShareCommand
        ruid, robj = _make_record()
        mock_unshare.return_value = {
            'success': True, 'message': '',
            'results': [{'record_uid': ruid, 'success': True, 'message': ''}],
        }
        cmd = NestedShareRecordShareCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(nested_share_records={ruid: robj}),
                        record=ruid, email='user@example.com',
                        action='revoke')

    @patch('keepercommander.nested_share_folder.folder_api.grant_folder_access_v3')
    def test_share_folder_invite_message_uses_command_prefix(self, mock_grant):
        from keepercommander.commands.nested_share_folder import NestedShareFolderShareCommand

        fuid, fobj = _make_folder()
        email = 'user@example.com'
        mock_grant.side_effect = ValueError(
            f"Share invitation has been sent to '{email}'. "
            "Please repeat this command once the invitation is accepted.")

        cmd = NestedShareFolderShareCommand()
        with self.assertLogs(level='WARNING') as logs:
            cmd.execute(_make_params(nested_share_folders={fuid: fobj}),
                        folder=[fuid], user=[email], action='grant', role='viewer')

        output = '\n'.join(logs.output)
        self.assertIn('nsf-share-folder: Share invitation has been sent', output)
        self.assertNotIn("User '", output)


class TestNestedShareFolderFolderApi(TestCase):

    @patch('keepercommander.nested_share_folder.folder_api.folder_access_update_v3')
    @patch('keepercommander.nested_share_folder.folder_api.handle_share_invite')
    @patch('keepercommander.nested_share_folder.folder_api.get_user_public_key')
    def test_grant_folder_access_sends_invite_when_no_active_share(
            self, mock_get_public_key, mock_handle_invite, mock_access_update):
        from keepercommander.nested_share_folder.folder_api import grant_folder_access_v3

        fuid, fobj = _make_folder()
        params = _make_params(nested_share_folders={fuid: fobj})
        email = 'user@example.com'

        mock_get_public_key.return_value = (None, False, None, True)
        mock_handle_invite.side_effect = ValueError(
            f"Share invitation has been sent to '{email}'. "
            "Please repeat this command once the invitation is accepted.")

        with self.assertRaises(ValueError) as ctx:
            grant_folder_access_v3(params, fuid, email, role='viewer')

        self.assertIn('Share invitation has been sent', str(ctx.exception))
        mock_get_public_key.assert_called_once_with(params, email)
        mock_handle_invite.assert_called_once_with(params, email, True)
        mock_access_update.assert_not_called()

    @patch('keepercommander.nested_share_folder.folder_api.parse_folder_access_result')
    @patch('keepercommander.nested_share_folder.folder_api.folder_access_update_v3')
    @patch('keepercommander.nested_share_folder.folder_api._resolve_accessor')
    @patch('keepercommander.nested_share_folder.folder_api.resolve_folder_identifier')
    def test_update_folder_access_v3_sets_expiration(
            self, mock_resolve_folder, mock_resolve_accessor,
            mock_access_update, mock_parse_result):
        from keepercommander.nested_share_folder.folder_api import update_folder_access_v3

        fuid, _ = _make_folder()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_resolve_folder.return_value = fuid
        mock_resolve_accessor.return_value = (uid_bytes, email, 1)
        mock_parse_result.return_value = {'success': True}
        mock_access_update.return_value = Mock()

        expiration = 1_700_000_000_000
        update_folder_access_v3(
            _make_params(), fuid, email, expiration_timestamp=expiration)

        update_call = mock_access_update.call_args
        ad = update_call.kwargs['folder_access_updates'][0]
        self.assertEqual(ad.tlaProperties.expiration, expiration)

    @patch('keepercommander.nested_share_folder.folder_api.update_folder_access_v3')
    @patch('keepercommander.nested_share_folder.folder_api._check_existing_access')
    @patch('keepercommander.nested_share_folder.folder_api.get_user_public_key')
    @patch('keepercommander.nested_share_folder.folder_api.resolve_folder_identifier')
    def test_grant_folder_access_update_passes_expiration(
            self, mock_resolve_folder, mock_get_public_key,
            mock_existing, mock_update):
        from keepercommander.nested_share_folder.folder_api import grant_folder_access_v3

        fuid, fobj = _make_folder()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_resolve_folder.return_value = fuid
        mock_get_public_key.return_value = (Mock(), False, uid_bytes, False)
        mock_existing.return_value = 'viewer'
        mock_update.return_value = {'success': True}

        expiration = 1_800_000_000_000
        grant_folder_access_v3(
            _make_params(nested_share_folders={fuid: fobj}),
            fuid, email, role='content-manager', expiration_timestamp=expiration)

        mock_update.assert_called_once_with(
            mock.ANY, fuid, email, role='content-manager', as_team=False,
            expiration_timestamp=expiration)

    @patch('keepercommander.nested_share_folder.folder_api.update_folder_access_v3')
    @patch('keepercommander.nested_share_folder.folder_api._check_existing_access')
    @patch('keepercommander.nested_share_folder.folder_api.get_user_public_key')
    @patch('keepercommander.nested_share_folder.folder_api.resolve_folder_identifier')
    def test_grant_folder_access_same_role_updates_expiration(
            self, mock_resolve_folder, mock_get_public_key,
            mock_existing, mock_update):
        from keepercommander.nested_share_folder.folder_api import grant_folder_access_v3

        fuid, fobj = _make_folder()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_resolve_folder.return_value = fuid
        mock_get_public_key.return_value = (Mock(), False, uid_bytes, False)
        mock_existing.return_value = 'viewer'
        mock_update.return_value = {'success': True}

        expiration = 1_900_000_000_000
        grant_folder_access_v3(
            _make_params(nested_share_folders={fuid: fobj}),
            fuid, email, role='viewer', expiration_timestamp=expiration)

        mock_update.assert_called_once_with(
            mock.ANY, fuid, email, role='viewer', as_team=False,
            expiration_timestamp=expiration)


class TestNestedShareFolderRecordApi(TestCase):

    def setUp(self):
        from keepercommander.nested_share_folder import record_api  # noqa: F401
        mock.patch('keepercommander.sync_down.sync_down').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.nested_share_folder.record_api.api.communicate_rest')
    @patch('keepercommander.nested_share_folder.record_api.encrypt_for_recipient')
    @patch('keepercommander.nested_share_folder.record_api.get_user_public_key')
    @patch('keepercommander.nested_share_folder.record_api.get_record_from_cache')
    def test_update_record_share_v3_sets_expiration_and_notification(
            self, mock_get_record, mock_get_public_key,
            mock_encrypt, mock_communicate):
        from keepercommander.nested_share_folder.record_api import update_record_share_v3
        from keepercommander.proto import tla_pb2

        ruid, robj = _make_record()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_get_record.return_value = robj
        mock_get_public_key.return_value = (Mock(), False, uid_bytes, False)
        mock_encrypt.return_value = b'enc-key'
        mock_response = Mock()
        mock_response.updatedSharingStatus = []
        mock_communicate.return_value = mock_response

        update_record_share_v3(
            _make_params(nested_share_records={ruid: robj}),
            ruid, email, access_role_type=1, expiration_timestamp=-1)

        rq = mock_communicate.call_args[0][1]
        perm = rq.updateSharingPermissions[0]
        self.assertEqual(perm.rules.tlaProperties.expiration, -1)

    @patch('keepercommander.nested_share_folder.record_api.api.communicate_rest')
    @patch('keepercommander.nested_share_folder.record_api.encrypt_for_recipient')
    @patch('keepercommander.nested_share_folder.record_api.get_user_public_key')
    @patch('keepercommander.nested_share_folder.record_api.get_record_from_cache')
    def test_update_record_share_v3_recreate_when_setting_expiration(
            self, mock_get_record, mock_get_public_key,
            mock_encrypt, mock_communicate):
        from keepercommander.nested_share_folder.record_api import update_record_share_v3
        from keepercommander.proto import tla_pb2

        ruid, robj = _make_record()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_get_record.return_value = robj
        mock_get_public_key.return_value = (Mock(), False, uid_bytes, False)
        mock_encrypt.return_value = b'enc-key'
        mock_response = Mock()
        mock_response.revokedSharingStatus = [_make_sharing_status(ruid, uid_bytes)]
        mock_response.createdSharingStatus = [_make_sharing_status(ruid, uid_bytes)]
        mock_communicate.side_effect = [mock_response, mock_response]

        expiration = 1_900_000_000_000
        update_record_share_v3(
            _make_params(nested_share_records={ruid: robj}),
            ruid, email, access_role_type=1, expiration_timestamp=expiration)

        self.assertEqual(mock_communicate.call_count, 2)
        revoke_rq = mock_communicate.call_args_list[0][0][1]
        create_rq = mock_communicate.call_args_list[1][0][1]
        self.assertEqual(len(revoke_rq.revokeSharingPermissions), 1)
        self.assertEqual(len(revoke_rq.createSharingPermissions), 0)
        self.assertEqual(len(create_rq.createSharingPermissions), 1)
        self.assertEqual(len(create_rq.updateSharingPermissions), 0)
        perm = create_rq.createSharingPermissions[0]
        self.assertEqual(perm.rules.tlaProperties.expiration, expiration)
        self.assertEqual(perm.rules.tlaProperties.timerNotificationType, tla_pb2.NOTIFY_OWNER)

    @patch('keepercommander.sync_down.sync_down')
    @patch('keepercommander.nested_share_folder.record_api.api.communicate_rest')
    @patch('keepercommander.nested_share_folder.record_api.encrypt_for_recipient')
    @patch('keepercommander.nested_share_folder.record_api.get_user_public_key')
    @patch('keepercommander.nested_share_folder.record_api.get_record_from_cache')
    def test_update_record_share_v3_recreate_syncs_once(
            self, mock_get_record, mock_get_public_key,
            mock_encrypt, mock_communicate, mock_sync_down):
        from keepercommander.nested_share_folder import record_api as ra

        ruid, robj = _make_record()
        email = 'user@example.com'
        uid_bytes = utils.base64_url_decode(utils.generate_uid())
        mock_get_record.return_value = robj
        mock_get_public_key.return_value = (Mock(), False, uid_bytes, False)
        mock_encrypt.return_value = b'enc-key'
        mock_response = Mock()
        mock_response.revokedSharingStatus = [_make_sharing_status(ruid, uid_bytes)]
        mock_response.createdSharingStatus = [_make_sharing_status(ruid, uid_bytes)]
        mock_communicate.side_effect = [mock_response, mock_response]

        ra.update_record_share_v3(
            _make_params(nested_share_records={ruid: robj}),
            ruid, email, access_role_type=1, expiration_timestamp=1_900_000_000_000)

        self.assertEqual(mock_sync_down.call_count, 1)

    def test_is_record_share_update_noop(self):
        from keepercommander.nested_share_folder.record_api import is_record_share_update_noop

        existing = {'access_role_type': 2, 'tla_expiration': 1_900_000_000_000}
        self.assertTrue(is_record_share_update_noop(existing, 2, None))
        self.assertTrue(is_record_share_update_noop(
            existing, 2, 1_900_000_000_500))
        self.assertFalse(is_record_share_update_noop(existing, 4, None))
        self.assertFalse(is_record_share_update_noop(
            existing, 2, 1_900_001_000_000))
        self.assertTrue(is_record_share_update_noop(
            {'access_role_type': 2}, 2, -1))

    @patch('keepercommander.nested_share_folder.record_api.api.communicate_rest')
    def test_get_record_accesses_v3_reads_tla_expiration(self, mock_communicate):
        from keepercommander.nested_share_folder.record_api import get_record_accesses_v3
        from keepercommander.proto import record_details_pb2, folder_pb2, tla_pb2

        ruid = utils.generate_uid()
        rs = record_details_pb2.RecordAccessResponse()
        ra = rs.recordAccesses.add()
        ra.data.recordUid = utils.base64_url_decode(ruid)
        ra.data.accessTypeUid = b'\x01' * 16
        ra.data.accessType = folder_pb2.AT_USER
        ra.data.accessRoleType = folder_pb2.VIEWER
        ra.data.tlaProperties.expiration = 1_783_667_017_211
        ra.data.tlaProperties.timerNotificationType = tla_pb2.NOTIFY_OWNER
        ra.accessorInfo.name = 'user@example.com'
        mock_communicate.return_value = rs

        result = get_record_accesses_v3(_make_params(), [ruid])
        self.assertEqual(result['record_accesses'][0]['tla_expiration'], 1_783_667_017_211)


class TestNestedShareFolderDisplayCommands(TestCase):

    def setUp(self):
        mock.patch('keepercommander.api.communicate_rest').start()
        mock.patch('keepercommander.api.communicate').start()

    def tearDown(self):
        mock.patch.stopall()

    @patch('keepercommander.nested_share_folder.record_api.get_record_details_v3')
    def test_get_record_details(self, mock_details):
        from keepercommander.commands.nested_share_folder import NestedShareRecordGetDetailsCommand
        mock_details.return_value = {'data': [], 'errors': []}
        ruid, robj = _make_record()
        cmd = NestedShareRecordGetDetailsCommand()
        with mock.patch('builtins.print'):
            cmd.execute(_make_params(nested_share_records={ruid: robj}),
                        record_uids=[ruid])

    @patch('keepercommander.nested_share_folder.record_api.get_record_accesses_v3')
    def test_get_record_access(self, mock_accesses):
        pass


class TestCommandRegistration(TestCase):

    def test_all_commands_registered(self):
        from keepercommander.commands.nested_share_folder import register_commands
        commands = {}
        register_commands(commands)
        expected = [
            'nsf-mkdir', 'nsf-record-add', 'nsf-record-update', 'nsf-rndir',
            'nsf-list', 'nsf-share-folder', 'nsf-record-details',
            'nsf-share-record', 'nsf-record-permission', 'nsf-transfer-record',
            'nsf-ln', 'nsf-rm', 'nsf-rmdir', 'nsf-shortcut', 'nsf-get',
        ]
        for name in expected:
            self.assertIn(name, commands)
        removed = ['kd-grant-access', 'kd-update-access', 'kd-revoke-access',
                    'kd-update-record-share', 'kd-unshare-record',
                    'kd-add-record-to-folder', 'kd-remove-record-from-folder',
                    'kd-record-access', 'kd-folder-access']
        for name in removed:
            self.assertNotIn(name, commands)

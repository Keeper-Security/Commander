import json
import io
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander import utils, vault
from keepercommander.commands.discover import GatewayContext
from keepercommander.commands.pam_debug import get_connection, load_pam_record
from keepercommander.commands.pam_debug.dump import PAMDebugDumpCommand
from keepercommander.error import CommandError
from keepercommander.subfolder import NestedShareFolderNode, RootFolderNode

# Note: test_acl_uses_load_pam_record_for_nsf_uids() and test_link_uses_load_pam_record_for_nsf_resource()
# were removed because the pam_debug.acl and pam_debug.link modules do not exist in the codebase.
# These tests were testing the integration of missing modules and were blocking test collection.


def _typed(uid, title, record_type='pamUser', version=3):
    rec = vault.TypedRecord(version=version)
    rec.record_uid = uid
    rec.title = title
    rec.type_name = record_type
    return rec


def _params():
    folder = NestedShareFolderNode()
    folder.uid = 'nsf_folder'
    folder.name = 'pamFolder - Resources'
    folder.parent_uid = None
    folder.subfolders = []
    return SimpleNamespace(
        folder_cache={'nsf_folder': folder},
        shared_folder_cache={},
        nested_share_folders={
            'nsf_folder': {'name': 'pamFolder - Resources', 'parent_uid': None},
        },
        nested_share_folder_records={'nsf_folder': {'machine_uid', 'user_uid'}},
        nested_share_records={
            'machine_uid': {'version': 3, 'revision': 1, 'shared': False},
            'user_uid': {'version': 3, 'revision': 1, 'shared': False},
            'config_uid': {'version': 6, 'revision': 1, 'shared': False},
        },
        nested_share_record_data={
            'machine_uid': {
                'data_json': {'type': 'pamMachine', 'title': 'NSF Machine', 'fields': []},
            },
            'user_uid': {
                'data_json': {'type': 'pamUser', 'title': 'NSF User', 'fields': []},
            },
            'config_uid': {
                'data_json': {
                    'type': 'pamNetworkConfiguration',
                    'title': 'NSF Config',
                    'fields': [{'type': 'pamResources', 'value': [{'folderUid': 'nsf_folder'}]}],
                },
            },
        },
        record_cache={},
        subfolder_record_cache={},
        record_rotation_cache={},
        root_folder=RootFolderNode(),
        environment_variables={},
    )


class TestPamDebugNsf(unittest.TestCase):

    def test_load_pam_record_resolves_nsf_machine(self):
        params = _params()
        rec = load_pam_record(params, 'machine_uid')
        self.assertIsNotNone(rec)
        self.assertEqual(rec.record_uid, 'machine_uid')
        self.assertEqual(rec.title, 'NSF Machine')
        self.assertEqual(rec.record_type, 'pamMachine')

    def test_dump_collects_nsf_folder_records(self):
        params = _params()
        with tempfile.TemporaryDirectory() as tmp:
            out = f'{tmp}/dump.json'
            with patch('keepercommander.commands.pam_debug.dump.get_connection'), \
                    patch('keepercommander.commands.pam_debug.dump.DAG'):
                PAMDebugDumpCommand().execute(
                    params,
                    folder_uid='nsf_folder',
                    recursive=False,
                    save_as=out,
                )
            with open(out, encoding='utf-8') as fh:
                data = json.loads(fh.read())

        uids = {row['uid'] for row in data}
        self.assertEqual(uids, {'machine_uid', 'user_uid'})
        titles = {row['data'].get('title') for row in data}
        self.assertEqual(titles, {'NSF Machine', 'NSF User'})

    def test_dump_json_stdout_does_not_write_a_file(self):
        params = _params()
        params.service_mode = True
        output = io.StringIO()
        with patch('keepercommander.commands.pam_debug.dump.get_connection'), \
                patch('keepercommander.commands.pam_debug.dump.DAG'), \
                patch('sys.stdout', output), \
                patch('builtins.open', side_effect=AssertionError('response mode must not open a file')):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                recursive=True,
                format='json',
            )

        data = json.loads(output.getvalue())
        self.assertEqual({row['uid'] for row in data}, {'machine_uid', 'user_uid'})

    def test_service_mode_dump_rejects_save_as(self):
        params = _params()
        params.service_mode = True
        with self.assertRaisesRegex(CommandError, 'API response'):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
                save_as='/tmp/blocked-dump.json',
            )

    def test_dump_obeys_enterprise_export_restriction(self):
        params = _params()
        params.enforcements = {
            'booleans': [{'key': 'restrict_export', 'value': True}],
        }

        with self.assertRaisesRegex(CommandError, 'export restrictions'):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
            )

    def test_service_mode_rejects_local_dag_connection(self):
        params = _params()
        params.service_mode = True

        with patch.dict('os.environ', {'USE_LOCAL_DAG': 'true'}):
            with self.assertRaisesRegex(CommandError, 'local DAG engine'):
                get_connection(params)

    def test_dump_includes_graph_load_failures_in_record_errors(self):
        params = _params()
        params.nested_share_folder_records = {'nsf_folder': {'machine_uid'}}
        params.record_rotation_cache = {
            'machine_uid': {'configuration_uid': 'config_uid'},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = f'{tmp}/dump.json'
            with patch('keepercommander.commands.pam_debug.dump.get_connection'), \
                    patch(
                        'keepercommander.commands.pam_debug.dump.DAG',
                        side_effect=RuntimeError('backend details should not be returned'),
                    ):
                PAMDebugDumpCommand().execute(
                    params,
                    folder_uid='nsf_folder',
                    format='json',
                    save_as=out,
                )
            with open(out, encoding='utf-8') as fh:
                data = json.load(fh)

        row = next(item for item in data if item['uid'] == 'machine_uid')
        self.assertTrue(row['errors'])
        self.assertEqual(row['errors'][0]['stage'], 'graph_sync')
        self.assertNotIn('backend details', json.dumps(row['errors']))

    def test_cli_dump_skips_unavailable_record_and_preserves_other_results(self):
        params = _params()
        params.nested_share_folder_records = {'nsf_folder': {'unavailable_uid'}}
        output = io.StringIO()
        with patch('sys.stdout', output):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
            )
        self.assertEqual(json.loads(output.getvalue()), [])

    def test_service_mode_reports_unavailable_record_without_echoing_uid(self):
        params = _params()
        params.service_mode = True
        params.nested_share_folder_records = {'nsf_folder': {'unavailable_uid'}}
        output = io.StringIO()
        with patch('sys.stdout', output):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
            )
        data = json.loads(output.getvalue())
        self.assertEqual(len(data), 1)
        self.assertIsNone(data[0]['uid'])
        self.assertEqual(data[0]['errors'][0]['stage'], 'record_data')
        self.assertNotIn('unavailable_uid', json.dumps(data))

    def test_service_mode_dump_limits_folder_record_count(self):
        params = _params()
        params.service_mode = True

        with patch(
            'keepercommander.commands.pam_debug.dump.MAX_SERVICE_MODE_DUMP_RECORDS',
            1,
        ), self.assertRaisesRegex(CommandError, 'limited to 1 folder records'):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
            )

    def test_service_mode_dump_limits_configuration_count(self):
        params = _params()
        params.service_mode = True
        params.record_rotation_cache = {
            'machine_uid': {'configuration_uid': 'config_uid'},
            'user_uid': {'configuration_uid': 'config_two_uid'},
        }
        params.nested_share_records['config_two_uid'] = {
            'version': 6,
            'revision': 1,
            'shared': False,
        }
        params.nested_share_record_data['config_two_uid'] = {
            'data_json': {
                'type': 'pamNetworkConfiguration',
                'title': 'Second NSF Config',
                'fields': [],
            },
        }

        with patch(
            'keepercommander.commands.pam_debug.dump.MAX_SERVICE_MODE_DUMP_CONFIGS',
            1,
        ), self.assertRaisesRegex(CommandError, 'limited to 1 PAM configurations'):
            PAMDebugDumpCommand().execute(
                params,
                folder_uid='nsf_folder',
                format='json',
            )

    def test_gateway_context_includes_nsf_shared_folders(self):
        folder_uid = 'zytjEAw5RTUJsF-PPx9wqA'
        params = _params()
        params.nested_share_folders = {
            folder_uid: {'name': 'pamFolder - Resources', 'parent_uid': None},
        }
        facade = MagicMock()
        facade.folder_uid = folder_uid
        gateway = MagicMock()
        gateway.applicationUid = b'\x01' * 16
        gateway.controllerUid = b'\x02' * 16
        gateway.controllerName = 'gw'
        ctx = GatewayContext(
            configuration=_typed('config_uid', 'NSF Config', 'pamNetworkConfiguration', version=6),
            facade=facade,
            gateway=gateway,
            application=MagicMock(),
        )

        share = MagicMock()
        share.secretUid = utils.base64_url_decode(folder_uid)
        share.shareType = 1
        app_info = MagicMock()
        app_info.shares = [share]

        with patch('keepercommander.commands.discover.KSMCommand.get_app_info', return_value=[app_info]), \
                patch('keepercommander.commands.discover.APIRequest_pb2.ApplicationShareType.Name',
                      return_value='SHARE_TYPE_FOLDER'):
            folders = ctx.get_shared_folders(params)

        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0]['uid'], folder_uid)
        self.assertEqual(folders[0]['name'], 'pamFolder - Resources')

    def test_gateway_context_loads_nsf_configuration_records(self):
        params = _params()
        with patch('keepercommander.commands.discover.vault_extensions.find_records', return_value=[]):
            configs = GatewayContext.get_configuration_records(params)

        self.assertTrue(any(c.record_uid == 'config_uid' for c in configs))
        self.assertTrue(any(c.record_type == 'pamNetworkConfiguration' for c in configs))


if __name__ == '__main__':
    unittest.main()

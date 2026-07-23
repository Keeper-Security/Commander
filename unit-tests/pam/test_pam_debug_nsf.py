import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander import utils, vault
from keepercommander.commands.discover import GatewayContext
from keepercommander.commands.pam_debug import load_pam_record
from keepercommander.commands.pam_debug.acl import PAMDebugACLCommand
from keepercommander.commands.pam_debug.dump import PAMDebugDumpCommand
from keepercommander.commands.pam_debug.link import PAMDebugLinkCommand
from keepercommander.subfolder import NestedShareFolderNode, RootFolderNode


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

    def test_acl_uses_load_pam_record_for_nsf_uids(self):
        params = _params()
        user = _typed('user_uid', 'NSF User', 'pamUser')
        parent = _typed('machine_uid', 'NSF Machine', 'pamMachine')
        gw = MagicMock()
        gw.configuration = _typed('config_uid', 'NSF Config', 'pamNetworkConfiguration', version=6)
        gw.configuration_uid = 'config_uid'

        with patch('keepercommander.commands.pam_debug.acl.GatewayContext.from_gateway', return_value=gw), \
                patch('keepercommander.commands.pam_debug.acl.RecordLink') as rl_cls, \
                patch('keepercommander.commands.pam_debug.acl.load_pam_record',
                      side_effect=[user, parent]) as load, \
                patch('builtins.input', side_effect=['n', 'n']):
            rl = rl_cls.return_value
            rl.get_acl.return_value = None
            rl.get_admin_record_uid.return_value = None
            rl.acl_has_belong_to_record_uid.return_value = None
            rl.dag.get_vertex.return_value = MagicMock()
            PAMDebugACLCommand().execute(
                params, gateway='gw', user_uid='user_uid', parent_uid='machine_uid')

        self.assertEqual(load.call_count, 2)
        self.assertEqual(load.call_args_list[0].args[1], 'user_uid')
        self.assertEqual(load.call_args_list[1].args[1], 'machine_uid')

    def test_link_uses_load_pam_record_for_nsf_resource(self):
        params = _params()
        parent = _typed('machine_uid', 'NSF Machine', 'pamMachine')
        gw = MagicMock()
        gw.configuration = _typed('config_uid', 'NSF Config', 'pamNetworkConfiguration', version=6)
        gw.configuration_uid = 'config_uid'

        with patch('keepercommander.commands.pam_debug.link.GatewayContext.from_gateway', return_value=gw), \
                patch('keepercommander.commands.pam_debug.link.RecordLink') as rl_cls, \
                patch('keepercommander.commands.pam_debug.link.load_pam_record', return_value=parent) as load:
            rl = rl_cls.return_value
            PAMDebugLinkCommand().execute(params, gateway='gw', resource_uid='machine_uid')
            rl.belongs_to.assert_called_once()
            rl.save.assert_called_once()
        self.assertEqual(load.call_args.args[1], 'machine_uid')

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

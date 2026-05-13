"""Structural tests for the Commander SDK clients.

These tests do NOT make live Commander calls — that requires an
authenticated tenant. Instead they verify:
  - Every protocol method is overridden on every SDK-backed client.
  - The _call() helper's success/failure contract (returns bool, never
    raises) using a fake Commander command object.
"""

import inspect
import logging
import unittest

from keepercommander.commands.keeper_tenant_migrate.attachments import AttachmentClient
from keepercommander.commands.keeper_tenant_migrate.commander_clients import (
    CommanderAttachmentClient,
    CommanderShareClient,
    CommanderStructureClient,
    CommanderUserClient,
    _call,
)
from keepercommander.commands.keeper_tenant_migrate.shares import ShareClient
from keepercommander.commands.keeper_tenant_migrate.structure import StructureClient
from keepercommander.commands.keeper_tenant_migrate.users import UserClient


def _protocol_methods(proto_cls):
    return [name for name, m in inspect.getmembers(proto_cls)
            if not name.startswith('_') and inspect.isfunction(m)]


class ProtocolCompletenessTests(unittest.TestCase):
    def test_structure_client_overrides_all(self):
        missing = [m for m in _protocol_methods(StructureClient)
                   if not hasattr(CommanderStructureClient, m)]
        self.assertEqual(missing, [])

    def test_user_client_overrides_all(self):
        missing = [m for m in _protocol_methods(UserClient)
                   if not hasattr(CommanderUserClient, m)]
        self.assertEqual(missing, [])

    def test_attachment_client_overrides_all(self):
        missing = [m for m in _protocol_methods(AttachmentClient)
                   if not hasattr(CommanderAttachmentClient, m)]
        self.assertEqual(missing, [])

    def test_share_client_overrides_all(self):
        missing = [m for m in _protocol_methods(ShareClient)
                   if not hasattr(CommanderShareClient, m)]
        self.assertEqual(missing, [])


class _FakeCmd:
    def __init__(self, outcome):
        self.outcome = outcome
        self.captured = None

    def execute(self, params, **kwargs):
        self.captured = kwargs
        if self.outcome == 'raise':
            raise RuntimeError('boom')
        if self.outcome == 'command_error':
            from keepercommander.error import CommandError
            raise CommandError('fake', 'fake error')
        return None


class CallHelperTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_success_returns_true_and_passes_kwargs(self):
        cmd = _FakeCmd('ok')
        self.assertTrue(_call(cmd, params=None, foo='bar', node=['x']))
        self.assertEqual(cmd.captured, {'foo': 'bar', 'node': ['x']})

    def test_command_error_returns_false(self):
        cmd = _FakeCmd('command_error')
        self.assertFalse(_call(cmd, params=None))

    def test_generic_exception_returns_false(self):
        cmd = _FakeCmd('raise')
        self.assertFalse(_call(cmd, params=None))


class FolderNameEscapingTests(unittest.TestCase):
    """Regression guard: Commander's mkdir rejects raw '/' in folder
    names. Source vault real-world contains names like
    'MIGTEST-SF-With/Slash' and 'KSM / KCM / PAM /Folder Emulation'
    that must be escaped before calling FolderMakeCommand."""

    def test_escape_single_slash(self):
        self.assertEqual(
            CommanderStructureClient._escape_folder_name('A/B'),
            'A//B',
        )

    def test_escape_multiple_slashes(self):
        self.assertEqual(
            CommanderStructureClient._escape_folder_name(
                'KSM / KCM / PAM /Folder Emulation'),
            'KSM // KCM // PAM //Folder Emulation',
        )

    def test_no_slash_is_identity(self):
        self.assertEqual(
            CommanderStructureClient._escape_folder_name('MIGTEST-SF-Root'),
            'MIGTEST-SF-Root',
        )

    def test_empty_and_none_safe(self):
        self.assertEqual(CommanderStructureClient._escape_folder_name(''), '')
        self.assertEqual(CommanderStructureClient._escape_folder_name(None), '')


class DeleteRecordPurgeForwardingTests(unittest.TestCase):
    """KC-625 regression: `delete_record` must forward `purge=True` iff
    the installed Commander is v17.2.14+. Without it, `cleanup` would
    silently degrade from hard-delete to per-user-unlink on the upgrade.
    """

    def setUp(self):
        from keepercommander.commands.keeper_tenant_migrate import commander_clients as cc
        self.cc = cc
        self.captured = {}

        class _CapturingRm:
            def execute(_self, params, **kwargs):
                self.captured.clear()
                self.captured.update(kwargs)
                return True

        import keepercommander.commands.record as rec_mod
        self._orig_rm = getattr(rec_mod, 'RecordRemoveCommand', None)
        rec_mod.RecordRemoveCommand = _CapturingRm
        self.client = cc.CommanderCleanupClient(object())

    def tearDown(self):
        import keepercommander.commands.record as rec_mod
        if self._orig_rm is not None:
            rec_mod.RecordRemoveCommand = self._orig_rm

    def _patch_version(self, version_str):
        import keepercommander
        self._orig_ver = getattr(keepercommander, '__version__', None)
        keepercommander.__version__ = version_str
        self.addCleanup(setattr, keepercommander, '__version__',
                        self._orig_ver)

    def test_purge_forwarded_on_17_2_14(self):
        self._patch_version('17.2.14')
        ok = self.client.delete_record('UID-A')
        self.assertTrue(ok)
        self.assertEqual(self.captured.get('record'), 'UID-A')
        self.assertIs(self.captured.get('force'), True)
        self.assertIs(self.captured.get('purge'), True,
                      'purge=True must be forwarded on v17.2.14+')

    def test_purge_forwarded_on_17_2_15(self):
        self._patch_version('17.2.15')
        self.client.delete_record('UID-B')
        self.assertIs(self.captured.get('purge'), True)

    def test_purge_forwarded_on_18_0_0(self):
        self._patch_version('18.0.0')
        self.client.delete_record('UID-C')
        self.assertIs(self.captured.get('purge'), True)

    def test_purge_omitted_on_17_2_13(self):
        self._patch_version('17.2.13')
        self.client.delete_record('UID-D')
        self.assertNotIn('purge', self.captured,
                         'pre-v17.2.14 Commander rejects unknown kwarg')

    def test_purge_omitted_on_unparseable_version(self):
        self._patch_version('garbage')
        self.client.delete_record('UID-E')
        self.assertNotIn('purge', self.captured,
                         'unparseable version must fall back to old kwargs')

    def test_purge_supported_helper_boundaries(self):
        import keepercommander
        original = getattr(keepercommander, '__version__', None)
        self.addCleanup(setattr, keepercommander, '__version__', original)
        cases = [
            ('17.2.13', False),
            ('17.2.14', True),
            ('17.2.15', True),
            ('17.3.0', True),
            ('18.0.0', True),
            ('17.2', False),     # treated as 17.2.0
            ('', False),
            ('not.a.version', False),
        ]
        for v, expected in cases:
            keepercommander.__version__ = v
            self.assertEqual(
                self.cc._purge_supported(), expected,
                f'_purge_supported({v!r}) expected {expected}',
            )


class _ParamsStub:
    """Bare params stub mirroring `KeeperParams.enterprise` shape used
    by the resume projections."""

    def __init__(self, enterprise=None, sf_cache=None, folder_cache=None):
        self.enterprise = enterprise or {}
        self.shared_folder_cache = sf_cache or {}
        self.folder_cache = folder_cache or {}


class StructureClientResumeProjectionTests(unittest.TestCase):
    """Verify the CommanderStructureClient's resume projections read
    `params.enterprise` correctly. These don't make live calls — the
    enterprise dict is hand-crafted to match Commander's flat-table
    shape."""

    def _client(self, enterprise=None, sf_cache=None, folder_cache=None):
        params = _ParamsStub(enterprise, sf_cache, folder_cache)
        return CommanderStructureClient(params)

    def test_list_node_names_no_scope(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_node_names(), {'Co', 'A'})

    def test_list_node_names_scope_filtered(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1},
                {'node_id': 3, 'data': {'displayname': 'AChild'},
                 'parent_id': 2},
                {'node_id': 4, 'data': {'displayname': 'B'},
                 'parent_id': 1},
            ],
        }
        c = self._client(ent)
        # Scope = 'A' → only A + descendants.
        self.assertEqual(c.list_node_names('A'), {'A', 'AChild'})

    def test_list_team_names_and_scope(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1},
            ],
            'teams': [
                {'name': 'T1', 'node_id': 1},
                {'name': 'T2', 'node_id': 2},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_team_names(), {'T1', 'T2'})
        self.assertEqual(c.list_team_names('A'), {'T2'})

    def test_list_role_names(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [{'node_id': 1, 'data': {'displayname': 'Co'},
                        'parent_id': None}],
            'roles': [
                {'role_id': 10, 'data': {'displayname': 'Admin'},
                 'node_id': 1},
                {'role_id': 11, 'name': 'LegacyName', 'node_id': 1,
                 'data': {}},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_role_names(), {'Admin', 'LegacyName'})

    def test_list_isolated_node_names(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None, 'restrict_visibility': False},
                {'node_id': 2, 'data': {'displayname': 'Iso'},
                 'parent_id': 1, 'restrict_visibility': True},
                {'node_id': 3, 'data': {'displayname': 'Vis'},
                 'parent_id': 1, 'restrict_visibility': False},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_isolated_node_names(), {'Iso'})

    def test_list_role_managed_nodes_and_privileges(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'NodeA'},
                 'parent_id': 1},
            ],
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'},
                        'node_id': 1}],
            'managed_nodes': [{
                'role_id': 10, 'managed_node_id': 2,
                'cascade_node_management': True,
            }],
            'role_privileges': [{
                'role_id': 10, 'managed_node_id': 2,
                'privilege': 'manage_users',
            }],
        }
        c = self._client(ent)
        self.assertEqual(c.list_role_managed_nodes('Admin'),
                         {('NodeA', 'on')})
        self.assertEqual(c.list_role_privileges('Admin'),
                         {('manage_users', 'NodeA')})
        # Unknown role → empty.
        self.assertEqual(c.list_role_managed_nodes('Missing'), set())
        self.assertEqual(c.list_role_privileges('Missing'), set())

    def test_list_role_enforcements_merges_per_role_rows(self):
        ent = {
            'enterprise_name': 'Co',
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'},
                        'node_id': 1}],
            'role_enforcements': [
                {'role_id': 10,
                 'enforcements': {'k1': 'v1', 'k2': 'v2'}},
                {'role_id': 10, 'enforcements': {'k3': 'v3'}},
                {'role_id': 99, 'enforcements': {'unrelated': 'x'}},
            ],
        }
        c = self._client(ent)
        merged = c.list_role_enforcements('Admin')
        self.assertEqual(merged, {'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(c.list_role_enforcements('Missing'), {})

    def test_list_user_node_assignments(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1},
            ],
            'users': [
                {'username': 'a@x.com', 'node_id': 2,
                 'enterprise_user_id': 100},
                {'username': 'B@X.com', 'node_id': 1,
                 'enterprise_user_id': 200},
                {'username': '', 'node_id': 2,
                 'enterprise_user_id': 300},
            ],
        }
        c = self._client(ent)
        out = c.list_user_node_assignments()
        self.assertEqual(out['a@x.com'], 'A')
        self.assertEqual(out['b@x.com'], 'Co')   # lowercased
        self.assertNotIn('', out)

    def test_list_user_team_memberships(self):
        ent = {
            'teams': [
                {'team_uid': 'TUID-1', 'name': 'T1'},
                {'team_uid': 'TUID-2', 'name': 'T2'},
            ],
            'users': [
                {'enterprise_user_id': 100, 'username': 'a@x.com'},
                {'enterprise_user_id': 200, 'username': 'b@x.com'},
            ],
            'team_users': [
                {'enterprise_user_id': 100, 'team_uid': 'TUID-1'},
                {'enterprise_user_id': 100, 'team_uid': 'TUID-2'},
                {'enterprise_user_id': 200, 'team_uid': 'TUID-1'},
            ],
        }
        c = self._client(ent)
        out = c.list_user_team_memberships()
        self.assertEqual(out['a@x.com'], {'T1', 'T2'})
        self.assertEqual(out['b@x.com'], {'T1'})

    def test_list_role_user_memberships_and_role_team_memberships(self):
        ent = {
            'roles': [
                {'role_id': 10, 'data': {'displayname': 'Admin'},
                 'node_id': 1},
                {'role_id': 11, 'data': {'displayname': 'Mgr'},
                 'node_id': 1},
            ],
            'users': [
                {'enterprise_user_id': 100, 'username': 'a@x.com'},
            ],
            'teams': [{'team_uid': 'TUID-1', 'name': 'T1'}],
            'role_users': [
                {'role_id': 10, 'enterprise_user_id': 100},
                {'role_id': 11, 'enterprise_user_id': 100},
            ],
            'role_teams': [
                {'role_id': 10, 'team_uid': 'TUID-1'},
            ],
        }
        c = self._client(ent)
        ru = c.list_role_user_memberships()
        self.assertEqual(ru['Admin'], {'a@x.com'})
        self.assertEqual(ru['Mgr'], {'a@x.com'})
        rt = c.list_role_team_memberships()
        self.assertEqual(rt['Admin'], {'T1'})
        self.assertNotIn('Mgr', rt)

    def test_list_shared_folder_names_handles_object_and_dict_entries(self):
        class _SF:
            def __init__(self, name):
                self.name = name
        cache = {
            'UID-1': _SF('SF-A'),
            'UID-2': {'name': 'SF-B'},
            'UID-3': _SF(''),
        }
        c = self._client(sf_cache=cache)
        self.assertEqual(c.list_shared_folder_names(), {'SF-A', 'SF-B'})

    def test_list_role_names_scope_filtered(self):
        # Role outside scope is dropped (covers the descendants-skip branch).
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1},
            ],
            'roles': [
                {'role_id': 10, 'data': {'displayname': 'Admin'},
                 'node_id': 1},     # outside scope 'A'
                {'role_id': 11, 'data': {'displayname': 'Inner'},
                 'node_id': 2},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_role_names('A'), {'Inner'})

    def test_list_isolated_node_names_scope_filtered(self):
        ent = {
            'enterprise_name': 'Co',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Co'},
                 'parent_id': None, 'restrict_visibility': True},
                {'node_id': 2, 'data': {'displayname': 'A'},
                 'parent_id': 1, 'restrict_visibility': False},
            ],
        }
        c = self._client(ent)
        # Node 1 outside scope → continue branch hit.
        self.assertEqual(c.list_isolated_node_names('A'), set())

    def test_list_role_managed_nodes_filters_other_roles(self):
        # Coverage: managed_nodes row whose role_id doesn't match.
        ent = {
            'roles': [{'role_id': 10, 'data': {'displayname': 'X'},
                        'node_id': 1}],
            'nodes': [{'node_id': 2, 'data': {'displayname': 'N'},
                        'parent_id': 1}],
            'managed_nodes': [
                {'role_id': 10, 'managed_node_id': 2,
                 'cascade_node_management': False},
                # Different role — must be skipped.
                {'role_id': 99, 'managed_node_id': 2,
                 'cascade_node_management': True},
                # Same role but unknown node id — must be dropped.
                {'role_id': 10, 'managed_node_id': 999,
                 'cascade_node_management': False},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_role_managed_nodes('X'),
                         {('N', 'off')})

    def test_list_role_privileges_filters_other_roles(self):
        ent = {
            'roles': [{'role_id': 10, 'data': {'displayname': 'X'},
                        'node_id': 1}],
            'nodes': [{'node_id': 2, 'data': {'displayname': 'N'},
                        'parent_id': 1}],
            'role_privileges': [
                {'role_id': 10, 'managed_node_id': 2,
                 'privilege': 'manage_users'},
                {'role_id': 99, 'managed_node_id': 2,
                 'privilege': 'irrelevant'},
            ],
        }
        c = self._client(ent)
        self.assertEqual(c.list_role_privileges('X'),
                         {('manage_users', 'N')})

    def test_find_folder_uid_delegates_to_helper(self):
        class _Folder:
            def __init__(self, name, parent_uid):
                self.name = name
                self.parent_uid = parent_uid
        folder_cache = {
            'UID-A': _Folder('Top', ''),
            'UID-B': _Folder('Sub', 'UID-A'),
        }
        c = self._client(folder_cache=folder_cache)
        self.assertEqual(c.find_folder_uid('Top', ''), 'UID-A')
        self.assertEqual(c.find_folder_uid('Sub', 'UID-A'), 'UID-B')
        self.assertEqual(c.find_folder_uid('Missing', ''), '')


class ResolveNodeIdByNameTests(unittest.TestCase):
    """Bug 73 — parent-name → node_id lookup used by the direct
    `node_add` bypass. Mirrors Commander's enterprise-node CLI lookup
    (case-insensitive, root-fallback to `enterprise_name`)."""

    def test_resolves_displayname_case_insensitive(self):
        ent = {'enterprise_name': 'ACME', 'nodes': [
            {'node_id': 1, 'parent_id': 0, 'data': {}},
            {'node_id': 7, 'parent_id': 1,
             'data': {'displayname': 'Subsidiary B'}},
        ]}
        nid = CommanderStructureClient._resolve_node_id_by_name(
            ent, 'subsidiary b')
        self.assertEqual(nid, 7)

    def test_resolves_root_via_enterprise_name(self):
        ent = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'node_id': 1, 'parent_id': 0, 'data': {}},  # rootless, no displayname
        ]}
        nid = CommanderStructureClient._resolve_node_id_by_name(
            ent, 'Keeperdemo')
        self.assertEqual(nid, 1)

    def test_unknown_parent_returns_none(self):
        ent = {'enterprise_name': 'ACME', 'nodes': [
            {'node_id': 1, 'parent_id': 0, 'data': {}},
        ]}
        self.assertIsNone(
            CommanderStructureClient._resolve_node_id_by_name(ent, 'Nope'))

    def test_empty_or_none_parent_name_returns_none(self):
        ent = {'enterprise_name': 'ACME', 'nodes': []}
        self.assertIsNone(
            CommanderStructureClient._resolve_node_id_by_name(ent, ''))
        self.assertIsNone(
            CommanderStructureClient._resolve_node_id_by_name(ent, None))


if __name__ == '__main__':
    unittest.main()

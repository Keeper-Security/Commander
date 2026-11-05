"""Integration-style tests for BatchPamImportEngine (import/extend batch paths)."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import vault
from keepercommander import utils
from keepercommander.commands.pam_import.base import (
    LoginUserObject,
    PamMachineObject,
    PamUserObject,
)
from keepercommander.commands.pam_import.batch_pipeline import (
    BatchPamImportEngine,
    assign_uids,
    configure_batch_tdag,
    PAM_DAG_SAVE_BATCH_COUNT,
)
from keepercommander.commands.pam_import.batch_step2 import (
    add_jit_domain_links,
    run_step2_extend_existing,
    run_step2_full,
)
from keepercommander.commands.pam_import.deferred_refs import (
    MAX_NUMBER_OF_RECORD_LINKS,
    _build_typed_record_update_pb,
)
from keepercommander.recordv3 import RecordV3


EXISTING_MACH = 'EEEEEEEEEEEEEEEEEEEEEA'
EXISTING_USER = 'UUUUUUUUUUUUUUUUUUUUUA'
NEW_USER = 'NNNNNNNNNNNNNNNNNNNNNA'
DIR_UID = 'DDDDDDDDDDDDDDDDDDDDDA'


class TestAssignUidsExtendMode(unittest.TestCase):
    def test_only_new_skips_existing_tag(self):
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        assign_uids([mach], only_new=True)
        self.assertEqual(mach.uid, EXISTING_MACH)

    def test_only_new_generates_for_new_tag(self):
        mach = PamMachineObject()
        mach.uid = ''
        mach._extend_tag = 'new'
        assign_uids([mach], only_new=True)
        self.assertTrue(RecordV3.is_valid_ref_uid(mach.uid))


class TestSimulateExtendStep2Dispatch(unittest.TestCase):
    def test_existing_machine_with_new_nested_user_uses_extend_step2(self):
        params = MagicMock()
        params.record_cache = {}
        existing = PamMachineObject()
        existing.uid = EXISTING_MACH
        existing._extend_tag = 'existing'
        new_user = PamUserObject()
        new_user.uid = NEW_USER
        new_user._extend_tag = 'new'
        existing.users = [new_user]
        engine = BatchPamImportEngine(
            params, {}, [], [existing],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
            extend_mode=True,
        )
        plan = engine.simulate()
        self.assertEqual(len(plan['step2_dispatch']), 1)
        dispatch = plan['step2_dispatch'][0]
        self.assertEqual(dispatch['step2'], 'run_step2_extend_existing')
        self.assertEqual(dispatch['new_users'], [NEW_USER])

    def test_existing_machine_without_new_users_skips_step2(self):
        params = MagicMock()
        params.record_cache = {}
        existing = PamMachineObject()
        existing.uid = EXISTING_MACH
        existing._extend_tag = 'existing'
        existing.users = []
        engine = BatchPamImportEngine(
            params, {}, [], [existing],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
            extend_mode=True,
        )
        plan = engine.simulate()
        self.assertEqual(plan['step2_dispatch'][0]['step2'], 'skip')


class TestExtendStep2DoesNotRunFullPath(unittest.TestCase):
    def test_run_step2_full_noop_for_existing_resource(self):
        params = MagicMock()
        tdag = MagicMock()
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._run_step2_machine',
        ) as machine_step, patch(
            'keepercommander.commands.pam_import.batch_step2._run_step2_rbi',
        ) as rbi_step:
            run_step2_full(
                params, tdag, mach, 'cfg', prc, 'sfu', 'sfr',
            )
            machine_step.assert_not_called()
            rbi_step.assert_not_called()
        tdag.link_resource_to_config.assert_not_called()

    def _run_full_with_admin_already_linked(self, launch_return):
        """Run run_step2_full with an admin already ACL-linked; return (tdag, admin_uid)."""
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = True  # already linked as admin
        admin_uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'new'
        mach.title = 'SSH Machine'
        admin = PamUserObject()
        admin.uid = admin_uid
        admin._extend_tag = 'new'
        mach.users = [admin]
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._run_step2_machine',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2.get_admin_credential',
            return_value=admin_uid,
        ), patch(
            'keepercommander.commands.pam_import.batch_step2.get_launch_credential',
            return_value=launch_return or '',
        ):
            run_step2_full(
                params, tdag, mach, 'cfg', prc, 'sfu', 'sfr',
            )
        return tdag, admin_uid

    def test_run_step2_full_sets_launch_even_when_admin_already_linked(self):
        """Launch == admin must still call set_launch_credentials (not skip)."""
        tdag, admin_uid = self._run_full_with_admin_already_linked('AAAAAAAAAAAAAAAAAAAAAA')
        tdag.set_launch_credentials.assert_called_once_with(
            EXISTING_MACH,
            launch_uid=admin_uid,
            admin_uid=admin_uid,
        )
        # allowedSettings re-applied after launch so connections survive meta wipe
        self.assertTrue(tdag.set_resource_allowed.called)

    def test_run_step2_full_admin_only_does_not_default_launch_to_admin(self):
        """KC-1525 / Web Vault meta v1: admin without launch -> launch=None, admin re-asserted."""
        tdag, admin_uid = self._run_full_with_admin_already_linked('')
        tdag.set_launch_credentials.assert_called_once_with(
            EXISTING_MACH,
            launch_uid=None,
            admin_uid=admin_uid,
        )
        self.assertTrue(tdag.set_resource_allowed.called)

    def test_extend_existing_only_links_new_nested_users(self):
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        new_user = PamUserObject()
        new_user.uid = NEW_USER
        new_user._extend_tag = 'new'
        # Rotation target → belongs_to=True (Web Vault parity).
        new_user.rotation_settings = MagicMock()
        new_user.rotation_settings.rotation = 'general'
        mach.users = [new_user]
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2._rotation_exists',
            return_value=True,
        ):
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
        tdag.link_user_to_resource.assert_called_once_with(
            NEW_USER, EXISTING_MACH, is_admin=False, belongs_to=True,
        )
        tdag.link_resource_to_config.assert_not_called()

    def test_extend_skips_non_admin_without_rotation(self):
        """RDP User-style nested records stay vault-only (not linked to the machine)."""
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        new_user = PamUserObject()
        new_user.uid = NEW_USER
        new_user._extend_tag = 'new'
        new_user.rotation_settings = None
        mach.users = [new_user]
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ):
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
        tdag.link_user_to_resource.assert_not_called()

    def test_admin_only_links_without_belongs_to(self):
        """MySQL/RDP/VNC Admin: is_admin=True, belongs_to=False (no Rotate Now)."""
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        admin_uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        admin = PamUserObject()
        admin.uid = admin_uid
        admin._extend_tag = 'new'
        admin.rotation_settings = None
        mach.users = [admin]
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2.get_admin_credential',
            return_value=admin_uid,
        ):
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
        tdag.link_user_to_resource.assert_called_once_with(
            admin_uid, EXISTING_MACH, is_admin=True, belongs_to=False,
        )


class TestConfigureBatchTdag(unittest.TestCase):
    def test_sets_chunked_save_and_defer(self):
        tdag = MagicMock()
        configure_batch_tdag(tdag)
        self.assertFalse(tdag.linking_dag.auto_save)
        self.assertEqual(tdag.linking_dag.save_batch_count, PAM_DAG_SAVE_BATCH_COUNT)
        tdag.defer_saves.assert_called_once_with(True)


class TestNestedUserFolderRouting(unittest.TestCase):
    """All user record types → Users folder (not Resources)."""

    def _engine(self, users=None, resources=None):
        return BatchPamImportEngine(
            MagicMock(), {}, users or [], resources or [],
            users_folder_uid='USERS_FOLDER',
            resources_folder_uid='RESOURCES_FOLDER',
            pam_cfg_uid='cfg',
        )

    def test_global_login_goes_to_users_folder(self):
        login = LoginUserObject()
        login.uid = NEW_USER
        eng = self._engine(users=[login])
        self.assertEqual(eng._resolve_folder(login), 'USERS_FOLDER')
        login.resolved_folder_uid = 'USERS_FOLDER'
        self.assertEqual(eng._resolve_folder(login), 'USERS_FOLDER')

    def test_global_pam_user_goes_to_users_folder(self):
        user = PamUserObject()
        user.uid = NEW_USER
        eng = self._engine(users=[user])
        self.assertEqual(eng._resolve_folder(user), 'USERS_FOLDER')
        user.resolved_folder_uid = 'USERS_FOLDER'
        self.assertEqual(eng._resolve_folder(user), 'USERS_FOLDER')

    def test_nested_pam_user_goes_to_users_folder(self):
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        user = PamUserObject()
        user.uid = NEW_USER
        mach.users = [user]
        eng = self._engine(resources=[mach])
        self.assertEqual(eng._resolve_folder(user), 'USERS_FOLDER')
        self.assertEqual(eng._resolve_folder(mach), 'RESOURCES_FOLDER')

    def test_resolve_folder_honors_incorrect_resource_stamp(self):
        """Documents why edit.py must not stamp nesteds with resources_folder_uid."""
        user = PamUserObject()
        user.uid = NEW_USER
        user.resolved_folder_uid = 'RESOURCES_FOLDER'
        eng = self._engine()
        self.assertEqual(eng._resolve_folder(user), 'RESOURCES_FOLDER')

    def test_default_stamp_all_user_kinds_use_users_folder(self):
        """Unspecified folder_path → Users for users, Resources for machines."""
        shfusr, shfres = 'USERS_FOLDER', 'RESOURCES_FOLDER'
        folder_path_map = {}

        def _resolve_folder_uid(obj, default_uid):
            fp = (getattr(obj, 'folder_path', None) or '').strip()
            if not fp:
                return default_uid
            return folder_path_map.get(fp) or default_uid

        global_login = LoginUserObject()
        global_pam = PamUserObject()
        global_login.resolved_folder_uid = _resolve_folder_uid(global_login, shfusr)
        global_pam.resolved_folder_uid = _resolve_folder_uid(global_pam, shfusr)

        mach = PamMachineObject()
        nested = PamUserObject()
        mach.users = [nested]
        mach.resolved_folder_uid = _resolve_folder_uid(mach, shfres)
        nested.resolved_folder_uid = _resolve_folder_uid(nested, shfusr)

        self.assertEqual(global_login.resolved_folder_uid, 'USERS_FOLDER')
        self.assertEqual(global_pam.resolved_folder_uid, 'USERS_FOLDER')
        self.assertEqual(nested.resolved_folder_uid, 'USERS_FOLDER')
        self.assertEqual(mach.resolved_folder_uid, 'RESOURCES_FOLDER')

    def test_explicit_folder_path_overrides_type_defaults(self):
        """folder_path from JSON wins over Users/Resources type defaults."""
        shfusr, shfres = 'USERS_FOLDER', 'RESOURCES_FOLDER'
        folder_path_map = {
            'Proj - Resources/TeamA': 'TEAM_A_RES',
            'Proj - Users/TeamA': 'TEAM_A_USR',
        }

        def _resolve_folder_uid(obj, default_uid):
            fp = (getattr(obj, 'folder_path', None) or '').strip()
            if not fp:
                return default_uid
            return folder_path_map.get(fp) or default_uid

        mach = PamMachineObject()
        mach.folder_path = 'Proj - Resources/TeamA'
        nested = PamUserObject()
        nested.folder_path = 'Proj - Users/TeamA'
        mach.users = [nested]
        global_login = LoginUserObject()
        global_login.folder_path = 'Proj - Users/TeamA'

        mach.resolved_folder_uid = _resolve_folder_uid(mach, shfres)
        nested.resolved_folder_uid = _resolve_folder_uid(nested, shfusr)
        global_login.resolved_folder_uid = _resolve_folder_uid(global_login, shfusr)

        self.assertEqual(mach.resolved_folder_uid, 'TEAM_A_RES')
        self.assertEqual(nested.resolved_folder_uid, 'TEAM_A_USR')
        self.assertEqual(global_login.resolved_folder_uid, 'TEAM_A_USR')

    def test_extend_stamp_preserves_explicit_folder_path(self):
        """Extend: path_to_folder_uid wins; unspecified nested users → Users."""
        path_to_folder_uid = {
            'Proj - Resources/TeamA': 'TEAM_A_RES',
            'Proj - Users/TeamA': 'TEAM_A_USR',
        }
        res_folder_uid, usr_folder_uid = 'RESOURCES_FOLDER', 'USERS_FOLDER'

        mach = PamMachineObject()
        mach._extend_tag = 'new'
        mach.type = 'pamMachine'
        mach.folder_path = 'Proj - Resources/TeamA'
        nested_explicit = PamUserObject()
        nested_explicit._extend_tag = 'new'
        nested_explicit.folder_path = 'Proj - Users/TeamA'
        nested_default = PamUserObject()
        nested_default._extend_tag = 'new'
        nested_default.folder_path = None
        mach.users = [nested_explicit, nested_default]

        fp = (getattr(mach, 'folder_path', None) or '').strip()
        mach.resolved_folder_uid = path_to_folder_uid.get(fp) or res_folder_uid
        for u in mach.users:
            ufp = (getattr(u, 'folder_path', None) or '').strip()
            u.resolved_folder_uid = path_to_folder_uid.get(ufp) or usr_folder_uid

        self.assertEqual(mach.resolved_folder_uid, 'TEAM_A_RES')
        self.assertEqual(nested_explicit.resolved_folder_uid, 'TEAM_A_USR')
        self.assertEqual(nested_default.resolved_folder_uid, 'USERS_FOLDER')


class TestImportFolderPathMaterialize(unittest.TestCase):
    def test_collect_pam_folder_paths(self):
        from keepercommander.commands.pam_import.edit import PAMProjectImportCommand
        pam_data = {
            'resources': [
                {
                    'folder_path': 'Proj - Resources/A',
                    'users': [{'folder_path': 'Proj - Users/A'}],
                },
                {'title': 'no-path'},
            ],
            'users': [{'folder_path': 'Proj - Users/B'}, {'title': 'bare'}],
        }
        paths = PAMProjectImportCommand._collect_pam_folder_paths(pam_data)
        self.assertEqual(
            paths,
            ['Proj - Resources/A', 'Proj - Users/A', 'Proj - Users/B'],
        )

    def test_materialize_creates_nested_under_known_roots(self):
        from keepercommander.commands.pam_import.edit import PAMProjectImportCommand

        cmd = PAMProjectImportCommand()
        params = MagicMock()
        params.folder_cache = {}
        params.nested_share_folders = {}
        project = {
            'options': {'dry_run': True, 'use_nsf': False},
            'folders': {
                'resources_folder': 'Proj - Resources',
                'resources_folder_uid': 'RES_UID',
                'users_folder': 'Proj - Users',
                'users_folder_uid': 'USR_UID',
                'safe_folder_map': {},
            },
        }
        pam_data = {
            'resources': [{
                'folder_path': 'Proj - Resources/TeamA',
                'users': [{'folder_path': 'Proj - Users/TeamA'}],
            }],
            'users': [],
        }
        with patch(
            'keepercommander.commands.pam_import.edit.api.generate_record_uid',
            side_effect=['NEST_RES', 'NEST_USR'],
        ):
            path_map = cmd._materialize_folder_paths(params, project, pam_data)

        self.assertEqual(path_map['Proj - Resources'], 'RES_UID')
        self.assertEqual(path_map['Proj - Users'], 'USR_UID')
        self.assertEqual(path_map['Proj - Resources/TeamA'], 'NEST_RES')
        self.assertEqual(path_map['Proj - Users/TeamA'], 'NEST_USR')

    def test_materialize_honors_safe_folder_map_without_recreate(self):
        from keepercommander.commands.pam_import.edit import PAMProjectImportCommand

        cmd = PAMProjectImportCommand()
        params = MagicMock()
        params.folder_cache = {}
        project = {
            'options': {'dry_run': False},
            'folders': {
                'resources_folder': 'Proj - Config',
                'resources_folder_uid': 'CFG',
                'users_folder': 'Proj - Config',
                'users_folder_uid': 'CFG',
                'safe_folder_map': {
                    'Safe1/Safe1 - Resources': 'SAFE_RES',
                    'Safe1/Safe1 - Users': 'SAFE_USR',
                },
            },
        }
        pam_data = {
            'resources': [{
                'folder_path': 'Safe1/Safe1 - Resources',
                'users': [{'folder_path': 'Safe1/Safe1 - Users'}],
            }],
        }
        cmd.create_subfolder = MagicMock()
        path_map = cmd._materialize_folder_paths(params, project, pam_data)
        self.assertEqual(path_map['Safe1/Safe1 - Resources'], 'SAFE_RES')
        self.assertEqual(path_map['Safe1/Safe1 - Users'], 'SAFE_USR')
        cmd.create_subfolder.assert_not_called()


class TestJitDomainLinkIdempotency(unittest.TestCase):
    def test_skips_when_link_already_exists(self):
        tdag = MagicMock()
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'new'
        ps = MagicMock()
        ps.jit_settings = MagicMock()
        ps.jit_settings.pam_directory_uid = DIR_UID
        mach.pam_settings = ps
        machine_v = MagicMock()
        machine_v.has.return_value = True
        dir_v = MagicMock()
        tdag.linking_dag.get_vertex.side_effect = lambda uid: {
            EXISTING_MACH: machine_v,
            DIR_UID: dir_v,
        }.get(uid)
        self.assertFalse(add_jit_domain_links(tdag, [mach]))
        machine_v.belongs_to.assert_not_called()


class TestAssignRecordKeysExtendMode(unittest.TestCase):
    def test_only_new_skips_existing_tag(self):
        from keepercommander.commands.pam_import.batch_pipeline import assign_record_keys

        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        keys = {}
        assign_record_keys([mach], keys, only_new=True)
        self.assertNotIn(EXISTING_MACH, keys)

    def test_only_new_assigns_for_new_tag(self):
        from keepercommander.commands.pam_import.batch_pipeline import assign_record_keys

        mach = PamMachineObject()
        mach.uid = NEW_USER
        mach._extend_tag = 'new'
        keys = {}
        assign_record_keys([mach], keys, only_new=True)
        self.assertIn(NEW_USER, keys)


class TestSimulateImportTail(unittest.TestCase):
    def test_flags_domain_admin_and_config_scripts(self):
        params = MagicMock()
        params.record_cache = {}
        pce = MagicMock()
        pce.environment = 'domain'
        pce.admin_credential_ref = 'ADMIN_UID_AAAAAAAAAAAAAA'
        script = MagicMock()
        script.record_refs = ['some_ref']
        pce.scripts.scripts = [script]
        project = {'pam_config': {'pam_config_object': pce}}
        engine = BatchPamImportEngine(
            params, project, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
            extend_mode=False,
        )
        with patch.object(engine, 'build_plan', return_value=[]):
            plan = engine.simulate()
        tail = plan['import_tail']
        self.assertTrue(tail['applies'])
        self.assertTrue(tail['pam_config_scripts'])
        self.assertTrue(tail['domain_admin_link'])

    def test_extend_mode_skips_import_tail(self):
        params = MagicMock()
        params.record_cache = {}
        engine = BatchPamImportEngine(
            params, {}, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
            extend_mode=True,
        )
        with patch.object(engine, 'build_plan', return_value=[]):
            plan = engine.simulate()
        self.assertFalse(plan['import_tail']['applies'])


class TestExtendSimulateOnlyNew(unittest.TestCase):
    def test_tiers_exclude_existing_resources(self):
        params = MagicMock()
        params.record_cache = {EXISTING_MACH: {}}
        existing = PamMachineObject()
        existing.uid = EXISTING_MACH
        existing._extend_tag = 'existing'
        new_mach = PamMachineObject()
        new_mach.uid = NEW_USER
        new_mach._extend_tag = 'new'
        engine = BatchPamImportEngine(
            params, {},
            [],
            [existing, new_mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
            extend_mode=True,
        )
        plan = engine.simulate()
        tier_uids = {u for t in plan['tiers'] for u in t['uids']}
        self.assertIn(NEW_USER, tier_uids)
        self.assertNotIn(EXISTING_MACH, tier_uids)
        dispatch = {d['resource']: d['step2'] for d in plan['step2_dispatch']}
        self.assertEqual(dispatch[EXISTING_MACH], 'skip')
        self.assertEqual(dispatch[NEW_USER], 'run_step2_full')


class TestExternalAdminStep2Order(unittest.TestCase):
    def test_links_external_admin_before_set_resource_allowed(self):
        from keepercommander.commands.pam_import.batch_step2 import _run_step2_machine

        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach.is_admin_external = True
        admin_uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        call_order = []

        def track_link(*args, **kwargs):
            call_order.append('link_user')
            return None

        def track_allowed(**kwargs):
            call_order.append('allowed')

        tdag.link_user_to_resource.side_effect = track_link
        tdag.set_resource_allowed.side_effect = track_allowed
        with patch(
            'keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2.parse_command_options',
            return_value={},
        ):
            _run_step2_machine(params, tdag, mach, 'cfg', admin_uid)
        self.assertEqual(call_order, ['link_user', 'allowed'])
        tdag.link_user_to_resource.assert_called_once_with(
            admin_uid, EXISTING_MACH, is_admin=True, belongs_to=False,
        )


class TestStep2RerunIdempotency(unittest.TestCase):
    def test_skips_link_resource_when_already_in_config(self):
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'new'
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._run_step2_machine',
        ), patch(
            'keepercommander.commands.pam_import.batch_step2._run_step2_rbi',
        ):
            run_step2_full(
                params, tdag, mach, 'cfg', prc, 'sfu', 'sfr',
            )
        tdag.link_resource_to_config.assert_not_called()

    def test_second_pass_skips_already_linked_nested_user(self):
        params = MagicMock()
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = True
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        new_user = PamUserObject()
        new_user.uid = NEW_USER
        new_user._extend_tag = 'new'
        mach.users = [new_user]
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ):
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
        self.assertEqual(tdag.link_user_to_resource.call_count, 0)


class TestExtendRotationIdempotency(unittest.TestCase):
    def _existing_machine_with_new_user(self):
        mach = PamMachineObject()
        mach.uid = EXISTING_MACH
        mach._extend_tag = 'existing'
        new_user = PamUserObject()
        new_user.uid = NEW_USER
        new_user._extend_tag = 'new'
        new_user.rotation_settings = MagicMock()
        mach.users = [new_user]
        return mach, new_user

    def test_skips_rotation_when_cache_has_matching_resource(self):
        params = MagicMock()
        params.record_rotation_cache = {
            NEW_USER: {'record_uid': NEW_USER, 'resource_uid': EXISTING_MACH},
        }
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        mach, _ = self._existing_machine_with_new_user()
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ) as rot:
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
            rot.assert_not_called()

    def test_applies_rotation_when_not_in_cache(self):
        params = MagicMock()
        params.record_rotation_cache = {}
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = False
        mach, _ = self._existing_machine_with_new_user()
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ) as rot:
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
            rot.assert_called_once()

    def test_applies_rotation_when_linked_but_not_configured(self):
        params = MagicMock()
        params.record_rotation_cache = {}
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = True
        mach, _ = self._existing_machine_with_new_user()
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ) as rot:
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
            rot.assert_called_once()
            tdag.link_user_to_resource.assert_not_called()

    def test_reapplies_when_rotation_bound_to_different_resource(self):
        other = 'OOOOOOOOOOOOOOOOOOOOOO'
        params = MagicMock()
        params.record_rotation_cache = {
            NEW_USER: {'record_uid': NEW_USER, 'resource_uid': other},
        }
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.user_belongs_to_resource.return_value = True
        mach, _ = self._existing_machine_with_new_user()
        prc = MagicMock()
        with patch(
            'keepercommander.commands.pam_import.batch_step2._apply_rotation',
        ) as rot:
            run_step2_extend_existing(params, tdag, mach, 'cfg', prc)
            rot.assert_called_once()


class TestRecordLinkCap(unittest.TestCase):
    def test_truncates_record_links_add_over_limit(self):
        params = MagicMock()
        params.enterprise_ec_key = None
        existing = vault.TypedRecord()
        existing.record_uid = EXISTING_MACH
        existing.revision = 1
        existing.record_key = b'\x01' * 32
        record = vault.TypedRecord()
        record.record_uid = EXISTING_MACH
        record.record_key = b'\x01' * 32
        refs = [utils.generate_uid() for _ in range(MAX_NUMBER_OF_RECORD_LINKS + 5)]
        record.linked_keys = {ref: b'\x02' * 32 for ref in refs}
        field = vault.TypedField.new_field('recordRef', refs, '')
        record.fields.append(field)
        with patch('keepercommander.commands.pam_import.deferred_refs.vault.KeeperRecord.load') as load:
            target = vault.TypedRecord()
            target.record_key = b'\x02' * 32
            load.return_value = target
            pb = _build_typed_record_update_pb(params, record, existing)
        self.assertLessEqual(len(pb.record_links_add), MAX_NUMBER_OF_RECORD_LINKS)


if __name__ == '__main__':
    unittest.main()

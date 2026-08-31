#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

import unittest
from unittest import mock

from keepercommander.service.commands.integrations.sailpoint.apply_entitlements import (
    SailPointEntitlementApplier,
)
from keepercommander.service.commands.integrations.sailpoint.command_parse import (
    SailPointCommandParser,
)
from keepercommander.service.commands.integrations.sailpoint.command_policy import (
    SailPointCommandPolicy,
)
from keepercommander.service.commands.integrations.sailpoint.pending_store import (
    SailPointPendingStore,
)
from keepercommander.service.commands.integrations.sailpoint.scim_guard import (
    SailPointScimGuard,
)
from keepercommander.service.commands.integrations.sailpoint.share_targets import (
    validate_share_targets,
)
from keepercommander.service.util.verified_command import Verifycommand


class SailPointParseTest(unittest.TestCase):
    def test_parse_invite_with_role_team(self):
        parsed = SailPointCommandParser.parse_invite(
            'enterprise-user user@co.com --invite --node Sales --add-role Admin --add-team AWS'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_invite)
        self.assertEqual(parsed.emails, ['user@co.com'])
        self.assertEqual(parsed.node, 'Sales')
        self.assertEqual(parsed.roles, ['Admin'])
        self.assertEqual(parsed.teams, ['AWS'])

    def test_parse_invite_multiple_roles_and_teams(self):
        parsed = SailPointCommandParser.parse_invite(
            'enterprise-user user@co.com --invite '
            '--add-role R1 --add-role R2 --add-team T1 --add-team T2'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.roles, ['R1', 'R2'])
        self.assertEqual(parsed.teams, ['T1', 'T2'])

    def test_parse_invite_equals_form_single_value(self):
        parsed = SailPointCommandParser.parse_invite(
            'eu user@co.com --invite --add-role=R1 --add-team=T1'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.roles, ['R1'])
        self.assertEqual(parsed.teams, ['T1'])

    def test_parse_invite_multi_value_after_one_flag_matches_commander(self):
        # Commander rejects "--add-role R1 R2"; R2 is left as a positional (not a role).
        parsed = SailPointCommandParser.parse_invite(
            'enterprise-user user@co.com --invite --add-role R1 R2 --add-team T1 T2'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.roles, ['R1'])
        self.assertEqual(parsed.teams, ['T1'])

    def test_parse_invite_comma_is_literal_role_name(self):
        # Commander treats this as one role named "R1,R2", not two roles.
        parsed = SailPointCommandParser.parse_invite(
            'eu user@co.com --invite --add-role=R1,R2'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.roles, ['R1,R2'])

    def test_parse_invite_alias(self):
        parsed = SailPointCommandParser.parse_invite('eu someone@x.com --add')
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_invite)

    def test_non_invite_returns_none(self):
        self.assertIsNone(
            SailPointCommandParser.parse_invite('enterprise-user user@co.com --add-role Admin')
        )

    def test_parse_identity_mutation(self):
        parsed = SailPointCommandParser.parse_identity_mutation(
            'enterprise-user user@co.com --add-role Admin'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.emails, ['user@co.com'])
        self.assertTrue(parsed.has_role_change)
        self.assertFalse(parsed.has_team_change)
        self.assertFalse(parsed.has_node_change)

    def test_parse_identity_mutation_team_and_node(self):
        parsed = SailPointCommandParser.parse_identity_mutation(
            'eu user@co.com --add-team T1 --node Sales'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_team_change)
        self.assertTrue(parsed.has_node_change)
        self.assertFalse(parsed.has_role_change)

    def test_parse_identity_mutation_ignores_non_mutating(self):
        self.assertIsNone(
            SailPointCommandParser.parse_identity_mutation(
                'enterprise-user user@co.com --lock'
            )
        )

    def test_parse_share_record(self):
        parsed = SailPointCommandParser.parse_share('share-record -e user@co.com -w RECORD_UID')
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_record)
        self.assertTrue(parsed.is_grant)
        self.assertTrue(parsed.can_edit)
        self.assertEqual(parsed.target, 'RECORD_UID')
        self.assertEqual(parsed.targets, ['RECORD_UID'])

    def test_parse_share_record_revoke_is_not_grant(self):
        parsed = SailPointCommandParser.parse_share(
            'share-record -a revoke -e user@co.com RECORD_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.action, 'revoke')
        self.assertFalse(parsed.is_grant)

    def test_parse_share_folder_remove_is_not_grant(self):
        parsed = SailPointCommandParser.parse_share(
            'share-folder -a remove -e user@co.com FOLDER_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.action, 'remove')
        self.assertFalse(parsed.is_grant)

    def test_parse_nsf_share_folder_remove_is_not_grant(self):
        parsed = SailPointCommandParser.parse_share(
            'nsf-share-folder -a remove -e user@co.com -r viewer NSF_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_nsf)
        self.assertEqual(parsed.action, 'remove')
        self.assertFalse(parsed.is_grant)

    def test_parse_share_folder_multi_target(self):
        parsed = SailPointCommandParser.parse_share(
            'share-folder -e user@co.com --manage-records on FOLDER_A FOLDER_B'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_folder)
        self.assertEqual(parsed.manage_records, 'on')
        self.assertEqual(parsed.targets, ['FOLDER_A', 'FOLDER_B'])

    def test_parse_nsf_share_folder_role(self):
        parsed = SailPointCommandParser.parse_share(
            'nsf-share-folder -e user@co.com -r content-manager NSF_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_nsf)
        self.assertTrue(parsed.is_folder)
        self.assertTrue(parsed.is_grant)
        self.assertEqual(parsed.nsf_role, 'content-manager')
        self.assertEqual(parsed.targets, ['NSF_UID'])

    def test_parse_nsf_share_record_role(self):
        parsed = SailPointCommandParser.parse_share(
            'nsf-share-record -e user@co.com -r viewer REC_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.is_nsf)
        self.assertTrue(parsed.is_record)
        self.assertEqual(parsed.nsf_role, 'viewer')

    def test_parse_share_equals_forms(self):
        parsed = SailPointCommandParser.parse_share(
            'share-record --email=user@co.com --action=revoke RECORD_UID'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.emails, ['user@co.com'])
        self.assertEqual(parsed.action, 'revoke')
        self.assertFalse(parsed.is_grant)

        folder = SailPointCommandParser.parse_share(
            'share-folder --email=user@co.com --manage-records=on FOLDER_UID'
        )
        self.assertIsNotNone(folder)
        self.assertEqual(folder.manage_records, 'on')
        self.assertEqual(folder.targets, ['FOLDER_UID'])

        nsf = SailPointCommandParser.parse_share(
            'nsf-share-folder --email=user@co.com --role=content-manager NSF_UID'
        )
        self.assertIsNotNone(nsf)
        self.assertEqual(nsf.nsf_role, 'content-manager')

    def test_parse_transfer(self):
        parsed = SailPointCommandParser.parse_transfer("transfer-user 'leaving@co.com' -f")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.emails, ['leaving@co.com'])
        self.assertTrue(parsed.has_force)
        self.assertFalse(parsed.has_target_user)

        parsed = SailPointCommandParser.parse_transfer(
            'transfer-user leaving@co.com --target-user=other@co.com -f'
        )
        self.assertTrue(parsed.has_target_user)
        self.assertTrue(parsed.has_force)

        self.assertIsNone(SailPointCommandParser.parse_transfer('enterprise-user x@co.com --delete'))


class SailPointPolicyTest(unittest.TestCase):
    def test_sanitize_strips_get(self):
        cleaned = SailPointCommandPolicy.sanitize('enterprise-user,get,share-record,export')
        self.assertNotIn('get', cleaned.split(','))
        self.assertNotIn('export', cleaned.split(','))
        self.assertIn('enterprise-user', cleaned.split(','))
        self.assertIn('share-record', cleaned.split(','))

    def test_default_allowlist_matches_integration_list(self):
        expected = [
            'whoami', 'sync-down', 'enterprise-info', 'enterprise-user',
            'enterprise-down', 'transfer-user',
            'share-folder', 'share-record', 'nsf-share-folder', 'nsf-share-record',
            'tree',
        ]
        self.assertEqual(SailPointCommandPolicy.default_allowlist().split(','), expected)

    def test_sanitize_adds_transfer_user_when_missing(self):
        cleaned = SailPointCommandPolicy.sanitize(
            'whoami,sync-down,enterprise-info,enterprise-user,enterprise-down,'
            'share-folder,share-record,tree'
        )
        parts = cleaned.split(',')
        self.assertIn('transfer-user', parts)
        self.assertNotIn('tu', parts)

    def test_enterprise_user_delete_blocked(self):
        for cmd in (
            'enterprise-user leaving@co.com --delete',
            'eu leaving@co.com --delete',
        ):
            err = SailPointCommandPolicy.validate_enterprise_user(cmd)
            self.assertIsNotNone(err, cmd)
            self.assertIn('--delete', err)
            self.assertIn('transfer-user', err)

    def test_enterprise_user_disable_2fa_blocked(self):
        for cmd in (
            'enterprise-user user@co.com --disable-2fa',
            'eu user@co.com --disable-2fa',
        ):
            err = SailPointCommandPolicy.validate_enterprise_user(cmd)
            self.assertIsNotNone(err, cmd)
            self.assertIn('--disable-2fa', err)

    def test_enterprise_user_expire_blocked(self):
        for cmd in (
            'enterprise-user user@co.com --expire',
            'eu user@co.com --expire',
        ):
            err = SailPointCommandPolicy.validate_enterprise_user(cmd)
            self.assertIsNotNone(err, cmd)
            self.assertIn('--expire', err)

    def test_enterprise_user_allows_safe_ops(self):
        self.assertIsNone(
            SailPointCommandPolicy.validate_enterprise_user(
                'eu user@co.com --add-role Admin'
            )
        )
        self.assertIsNone(
            SailPointCommandPolicy.validate_enterprise_user(
                'enterprise-user user@co.com --delete-alias old@co.com'
            )
        )
        self.assertIsNone(
            SailPointCommandPolicy.validate_enterprise_user(
                'enterprise-user user@co.com --add-team AWS'
            )
        )

    def test_prepare_transfer_appends_config_email(self):
        cmd = "transfer-user 'leaving@co.com' -f"
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'target@co.com')
        self.assertIsNone(err)
        self.assertTrue(rewritten.startswith(cmd))
        tokens = SailPointCommandParser.tokenize(rewritten)
        self.assertIn('--target-user', tokens)
        self.assertEqual(tokens[tokens.index('--target-user') + 1], 'target@co.com')

    def test_prepare_transfer_rejects_explicit_target(self):
        cmd = 'transfer-user leaving@co.com -f --target-user other@co.com'
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'target@co.com')
        self.assertEqual(rewritten, cmd)
        self.assertIsNotNone(err)
        self.assertIn('--target-user', err)

    def test_prepare_transfer_rejects_self_transfer(self):
        cmd = 'transfer-user Target@Co.com -f'
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'target@co.com')
        self.assertEqual(rewritten, cmd)
        self.assertIsNotNone(err)
        self.assertIn('itself', err)

    def test_prepare_transfer_requires_force_and_valid_config(self):
        cmd = 'transfer-user leaving@co.com'
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'target@co.com')
        self.assertEqual(rewritten, cmd)
        self.assertIn('-f', err)

        cmd = 'transfer-user leaving@co.com -f'
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, '')
        self.assertEqual(rewritten, cmd)
        self.assertIn('not configured', err)

        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'not-an-email')
        self.assertEqual(rewritten, cmd)
        self.assertIn('not configured', err)

    def test_prepare_transfer_ignores_other_commands(self):
        cmd = 'enterprise-user user@co.com --add-role Admin'
        rewritten, err = SailPointCommandPolicy.prepare_transfer(cmd, 'target@co.com')
        self.assertEqual(rewritten, cmd)
        self.assertIsNone(err)

    def test_share_record_ownership_transfer_blocked(self):
        for cmd in (
            'share-record record@uid --action owner -e user@co.com',
            'share-record record@uid -a owner -e user@co.com',
        ):
            err = SailPointCommandPolicy.validate_share_record(cmd)
            self.assertIsNotNone(err, cmd)
            self.assertIn('owner', err)

    def test_share_record_grant_allowed(self):
        for cmd in (
            'share-record record@uid -e user@co.com',
            'share-record record@uid --action grant -e user@co.com',
            'nsf-share-record record@uid -e user@co.com -r viewer',
        ):
            err = SailPointCommandPolicy.validate_share_record(cmd)
            self.assertIsNone(err, cmd)


class SailPointPendingMergeTest(unittest.TestCase):
    def test_merge_by_email(self):
        pending = SailPointPendingStore.merge_entry({}, 'User@Co.com', roles=['Admin'])
        pending = SailPointPendingStore.merge_entry(pending, 'user@co.com', teams=['AWS'])
        pending = SailPointPendingStore.merge_entry(
            pending, 'user@co.com', records=[{'uid': 'r1', 'can_edit': False}]
        )
        entry = pending['user@co.com']
        self.assertEqual(entry['roles'], ['Admin'])
        self.assertEqual(entry['teams'], ['AWS'])
        self.assertEqual(entry['records'][0]['uid'], 'r1')
        self.assertEqual(SailPointPendingStore.empty_entry()['roles'], [])

    def test_merge_folder_kind_nsf(self):
        pending = SailPointPendingStore.merge_entry(
            {},
            'user@co.com',
            folders=[{'uid': 'f1', 'kind': 'nsf', 'role': 'viewer'}],
        )
        self.assertEqual(pending['user@co.com']['folders'][0]['kind'], 'nsf')


class SailPointScimGuardTest(unittest.TestCase):
    def test_identity_change_error_loads_enterprise(self):
        params = mock.Mock()
        params.enterprise = None

        with mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.scim_guard.api.query_enterprise'
        ) as query:
            def _load(_params):
                _params.enterprise = {
                    'users': [{'username': 'user@co.com', 'node_id': 10, 'status': 'active'}],
                    'nodes': [{'node_id': 10, 'parent_id': None, 'scim_id': 1}],
                    'scims': [],
                }
            query.side_effect = _load
            err = SailPointScimGuard.identity_change_error(params, 'user@co.com')
            self.assertIsNotNone(err)
            query.assert_called()


class SailPointApplierTest(unittest.TestCase):
    def test_apply_nsf_folder_and_record_commands(self):
        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [],
            'teams': [],
        }
        entry = {
            'roles': [],
            'teams': [],
            'folders': [{'uid': 'F1', 'kind': 'nsf', 'role': 'content-manager'}],
            'records': [{'uid': 'R1', 'kind': 'nsf', 'role': 'viewer'}],
        }
        runs = []

        with mock.patch.object(SailPointEntitlementApplier, '_run', side_effect=lambda p, c: runs.append(c)):
            remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                params, 'user@co.com', entry
            )

        self.assertEqual(remaining, {})
        self.assertEqual(dropped, [])
        self.assertIn('nsf-share-folder', runs[0])
        self.assertIn('content-manager', runs[0])
        self.assertIn('nsf-share-record', runs[1])
        self.assertIn('viewer', runs[1])

    def test_does_not_drop_on_generic_invalid(self):
        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [],
            'teams': [],
        }
        entry = {
            'roles': [],
            'teams': [],
            'folders': [{'uid': 'F1', 'kind': 'classic', 'manage_records': 'on'}],
            'records': [],
        }

        with mock.patch.object(
            SailPointEntitlementApplier,
            '_run',
            side_effect=RuntimeError('invalid permission combination'),
        ):
            remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                params, 'user@co.com', entry
            )

        self.assertEqual(dropped, [])
        self.assertEqual(len(remaining.get('folders') or []), 1)


class SailPointRecordResolutionTest(unittest.TestCase):
    def test_record_uid_prefers_sailpoint_env_not_commander_record(self):
        from keepercommander.service.commands.integrations.sailpoint.service import (
            SailPointService,
        )
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        with mock.patch.dict(
            'os.environ',
            {'COMMANDER_RECORD': 'docker-uid', 'SAILPOINT_RECORD': 'sailpoint-uid'},
            clear=False,
        ):
            if hasattr(params, SailPointService.PARAMS_ATTR):
                delattr(params, SailPointService.PARAMS_ATTR)
            self.assertEqual(SailPointService.record_uid(params), 'sailpoint-uid')

    def test_record_uid_uses_params_attr_first(self):
        from keepercommander.service.commands.integrations.sailpoint.service import (
            SailPointService,
        )
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        SailPointService.bind_params(params, 'bound-uid')
        with mock.patch.dict(
            'os.environ',
            {'SAILPOINT_RECORD': 'env-uid'},
            clear=False,
        ):
            self.assertEqual(SailPointService.record_uid(params), 'bound-uid')

    def test_default_record_name_and_env_key(self):
        from keepercommander.service.commands.integrations.sailpoint_app_setup import (
            SailPointAppSetupCommand,
        )
        cmd = SailPointAppSetupCommand()
        self.assertEqual(cmd.get_default_record_name(), 'Commander Service Mode SailPoint Config')
        self.assertEqual(cmd.get_record_env_key(), 'SAILPOINT_RECORD')
        self.assertEqual(cmd.get_default_folder_name(), 'Commander Service Mode - SailPoint')


class SailPointShareTargetValidationTest(unittest.TestCase):
    def _params(self):
        params = mock.Mock()
        params.nested_share_folders = {'NSF_FOLDER': {}}
        params.nested_share_records = {'NSF_RECORD': {}}
        params.shared_folder_cache = {'CLASSIC_SF': {}}
        params.record_cache = {'CLASSIC_REC': {}, 'NSF_RECORD': {}}
        params.folder_cache = {}
        return params

    def test_share_folder_rejects_nsf_folder(self):
        share = SailPointCommandParser.parse_share(
            'share-folder -e user@co.com NSF_FOLDER'
        )
        err = validate_share_targets(self._params(), share)
        self.assertIsNotNone(err)
        self.assertIn('nsf-share-folder', err)

    def test_nsf_share_folder_rejects_classic_folder(self):
        share = SailPointCommandParser.parse_share(
            'nsf-share-folder -e user@co.com -r viewer CLASSIC_SF'
        )
        err = validate_share_targets(self._params(), share)
        self.assertIsNotNone(err)
        self.assertIn('share-folder', err)

    def test_share_record_rejects_nsf_folder_and_nsf_record(self):
        params = self._params()
        share_folder = SailPointCommandParser.parse_share(
            'share-record -e user@co.com NSF_FOLDER'
        )
        err = validate_share_targets(params, share_folder)
        self.assertIsNotNone(err)
        self.assertIn('folder', err.lower())

        share_rec = SailPointCommandParser.parse_share(
            'share-record -e user@co.com NSF_RECORD'
        )
        err = validate_share_targets(params, share_rec)
        self.assertIsNotNone(err)
        self.assertIn('nsf-share-record', err)

    def test_nsf_share_record_rejects_classic_record(self):
        share = SailPointCommandParser.parse_share(
            'nsf-share-record -e user@co.com -r viewer CLASSIC_REC'
        )
        err = validate_share_targets(self._params(), share)
        self.assertIsNotNone(err)
        self.assertIn('share-record', err)

    def test_matching_targets_ok(self):
        params = self._params()
        cases = [
            'share-folder -e user@co.com CLASSIC_SF',
            'nsf-share-folder -e user@co.com -r viewer NSF_FOLDER',
            'share-record -e user@co.com CLASSIC_REC',
            'nsf-share-record -e user@co.com -r viewer NSF_RECORD',
        ]
        for cmd in cases:
            share = SailPointCommandParser.parse_share(cmd)
            self.assertIsNone(validate_share_targets(params, share), cmd)


class EnterpriseUserForceValidationTest(unittest.TestCase):
    def test_admin_role_requires_force(self):
        params = mock.Mock()
        params.enterprise = {
            'roles': [{'role_id': 10, 'data': {'displayname': 'Commander RTI'}}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 1}],
        }
        err = Verifycommand.validate_enterprise_user_add_role_force(
            ['enterprise-user', 'user@co.com', '--add-role', 'Commander RTI'],
            params,
        )
        self.assertIsNotNone(err)
        self.assertIn('-f/--force', err)

    def test_admin_role_with_force_ok(self):
        params = mock.Mock()
        params.enterprise = {
            'roles': [{'role_id': 10, 'data': {'displayname': 'Commander RTI'}}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 1}],
        }
        err = Verifycommand.validate_enterprise_user_add_role_force(
            ['eu', '-f', 'user@co.com', '--add-role', 'Commander RTI'],
            params,
        )
        self.assertIsNone(err)

    def test_non_admin_role_ok_without_force(self):
        params = mock.Mock()
        params.enterprise = {
            'roles': [{'role_id': 11, 'data': {'displayname': 'QA Role'}}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 1}],
        }
        err = Verifycommand.validate_enterprise_user_add_role_force(
            ['enterprise-user', 'user@co.com', '--add-role', 'QA Role'],
            params,
        )
        self.assertIsNone(err)

    def test_invite_skips_force_check(self):
        params = mock.Mock()
        params.enterprise = {
            'roles': [{'role_id': 10, 'data': {'displayname': 'Commander RTI'}}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 1}],
        }
        err = Verifycommand.validate_enterprise_user_add_role_force(
            [
                'enterprise-user', 'user@co.com', '--invite',
                '--add-role', 'Commander RTI',
            ],
            params,
        )
        self.assertIsNone(err)

    def test_apply_role_uses_force_flag(self):
        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'}}],
            'teams': [],
        }
        runs = []
        with mock.patch.object(
            SailPointEntitlementApplier, '_run', side_effect=lambda p, c: runs.append(c)
        ):
            SailPointEntitlementApplier.apply_for_user(
                params,
                'user@co.com',
                {'roles': ['Admin'], 'teams': [], 'folders': [], 'records': []},
            )
        self.assertTrue(runs)
        self.assertIn(' -f ', f' {runs[0]} ')
        self.assertIn('--add-role', runs[0])


class SailPointCapabilityGateTest(unittest.TestCase):
    def test_roles_off_blocks_invite_add_role(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        caps = SailPointCapabilities(allow_roles=False, allow_teams=True)
        err = SailPointCommandHook._check_capability_gates(
            "eu user@co.com --invite --node N --add-role R", caps
        )
        self.assertIsNotNone(err)
        self.assertIn('allow_roles', err)

    def test_teams_off_blocks_add_team_allows_node(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        caps = SailPointCapabilities(allow_roles=True, allow_teams=False)
        err = SailPointCommandHook._check_capability_gates(
            'eu user@co.com --add-team Slack', caps
        )
        self.assertIsNotNone(err)
        self.assertIn('allow_teams', err)

        err = SailPointCommandHook._check_capability_gates(
            "eu user@co.com --invite --node 'Service Account Node'", caps
        )
        self.assertIsNone(err)

        err = SailPointCommandHook._check_capability_gates(
            'eu user@co.com --node Other', caps
        )
        self.assertIsNone(err)

    def test_capability_gates_catch_abbreviated_flags(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        roles_off = SailPointCapabilities(allow_roles=False, allow_teams=True)
        err = SailPointCommandHook._check_capability_gates(
            'enterprise-user user@co.com --add-rol Admin', roles_off
        )
        self.assertIsNotNone(err)
        self.assertIn('allow_roles', err)

        teams_off = SailPointCapabilities(allow_roles=True, allow_teams=False)
        err = SailPointCommandHook._check_capability_gates(
            'enterprise-user user@co.com --add-tea Slack', teams_off
        )
        self.assertIsNotNone(err)
        self.assertIn('allow_teams', err)

        share = SailPointCommandParser.parse_share(
            'share-record --emai attacker@co.com --write SOMERECORDUID'
        )
        self.assertIsNotNone(share)
        self.assertEqual(share.emails, ['attacker@co.com'])
        self.assertTrue(share.can_edit)

    def test_apply_skips_folders_and_records_when_disallowed(self):
        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [],
            'teams': [],
        }
        runs = []
        with mock.patch.object(
            SailPointEntitlementApplier, '_run', side_effect=lambda p, c: runs.append(c)
        ):
            remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                params,
                'user@co.com',
                {
                    'roles': [],
                    'teams': [],
                    'folders': [{'uid': 'FOLDER1', 'kind': 'classic'}],
                    'records': [{'uid': 'REC1'}],
                },
                allow_folders=False,
                allow_records=False,
            )
        self.assertEqual(runs, [])
        self.assertEqual(remaining, {})
        self.assertTrue(any('allow_folders' in m for m in dropped))
        self.assertTrue(any('allow_records' in m for m in dropped))

    def test_mixed_active_and_invited_share_rejected(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        params = mock.Mock()
        params.enterprise = {
            'users': [
                {'username': 'active@co.com', 'node_id': 1, 'status': 'active'},
                {'username': 'invited@co.com', 'node_id': 1, 'status': 'invited'},
            ],
            'nodes': [{'node_id': 1}],
            'scims': [],
        }
        share = SailPointCommandParser.parse_share(
            'share-record -e active@co.com -e invited@co.com RECORD_UID'
        )
        hook = SailPointCommandHook('cfg-uid')
        response, status = hook._before_share(
            params, share, SailPointCapabilities()
        )
        self.assertEqual(status, 400)
        self.assertIn('mix Active and non-Active', response['error'])

    def test_share_capability_gates_apply_to_non_grant_actions(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        hook = SailPointCommandHook('cfg-uid')
        params = mock.Mock()
        records_off = SailPointCapabilities(allow_records=False, allow_folders=True)
        folders_off = SailPointCapabilities(allow_records=True, allow_folders=False)
        both_on = SailPointCapabilities(allow_records=True, allow_folders=True)

        for cmd in (
            'share-record -e user@co.com --action owner RECORD_UID',
            'share-record -e user@co.com -a owner RECORD_UID',
            'share-record -e user@co.com --action revoke RECORD_UID',
            'share-record -e user@co.com --action cancel -f RECORD_UID',
            'nsf-share-record -e user@co.com --action owner -r viewer RECORD_UID',
        ):
            share = SailPointCommandParser.parse_share(cmd)
            self.assertIsNotNone(share, cmd)
            self.assertFalse(share.is_grant, cmd)
            response, status = hook._before_share(params, share, records_off)
            self.assertEqual(status, 403, cmd)
            self.assertIn('allow_records', response['error'], cmd)
            self.assertIsNone(hook._before_share(params, share, both_on), cmd)

        for cmd in (
            'share-folder -e user@co.com --action remove FOLDER_UID',
            'nsf-share-folder -e user@co.com --action remove FOLDER_UID',
        ):
            share = SailPointCommandParser.parse_share(cmd)
            self.assertIsNotNone(share, cmd)
            self.assertFalse(share.is_grant, cmd)
            response, status = hook._before_share(params, share, folders_off)
            self.assertEqual(status, 403, cmd)
            self.assertIn('allow_folders', response['error'], cmd)
            self.assertIsNone(hook._before_share(params, share, both_on), cmd)

    def test_non_grant_share_never_queues_for_invited_user(self):
        """Revoke/owner/remove must pass through to Commander, not pending entitlements."""
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )
        from keepercommander.service.commands.integrations.sailpoint.pending_store import (
            SailPointPendingStore,
        )

        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'invited@co.com', 'node_id': 1, 'status': 'invited'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
        }
        hook = SailPointCommandHook('cfg-uid')
        caps = SailPointCapabilities(allow_records=True, allow_folders=True)

        with mock.patch.object(SailPointPendingStore, 'update') as update:
            for cmd in (
                'share-record -e invited@co.com --action revoke RECORD_UID',
                'share-record -e invited@co.com --action owner RECORD_UID',
                'share-record -e invited@co.com --action cancel -f RECORD_UID',
                'share-folder -e invited@co.com --action remove FOLDER_UID',
                'nsf-share-record -e invited@co.com --action owner -r viewer RECORD_UID',
                'nsf-share-folder -e invited@co.com --action remove FOLDER_UID',
            ):
                share = SailPointCommandParser.parse_share(cmd)
                self.assertIsNotNone(share, cmd)
                self.assertFalse(share.is_grant, cmd)
                self.assertIsNone(hook._before_share(params, share, caps), cmd)
            update.assert_not_called()

    def test_before_command_injects_transfer_target(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )
        from keepercommander.service.commands.integrations.sailpoint.config_fields import (
            SailPointCapabilities,
        )

        caps = SailPointCapabilities(transfer_target_email='target@co.com')
        hook = SailPointCommandHook('cfg-uid')
        with mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.command_hook.read_capabilities',
            return_value=caps,
        ):
            command, short = hook.before_command(
                mock.Mock(), "transfer-user 'leaving@co.com' -f"
            )
        self.assertIsNone(short)
        self.assertIn('--target-user', command)
        self.assertIn('target@co.com', command)

        with mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.command_hook.read_capabilities',
            return_value=caps,
        ):
            command, short = hook.before_command(
                mock.Mock(), 'enterprise-user leaving@co.com --delete'
            )
        self.assertIsNotNone(short)
        self.assertEqual(short[1], 403)
        self.assertIn('--delete', short[0]['error'])

    def test_after_command_skips_missing_user(self):
        from keepercommander.service.commands.integrations.sailpoint.command_hook import (
            SailPointCommandHook,
        )

        params = mock.Mock()
        params.enterprise = {
            'users': [],
            'nodes': [],
            'scims': [],
        }
        hook = SailPointCommandHook('cfg-uid')
        with mock.patch.object(SailPointPendingStore, 'update') as update_mock:
            hook.after_command(
                params,
                'eu missing@co.com --invite --add-role Admin',
                success=True,
            )
            update_mock.assert_not_called()

    def test_poller_applies_outside_store_update(self):
        from keepercommander.service.commands.integrations.sailpoint.poller import (
            SailPointEntitlementPoller,
        )

        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'}}],
            'teams': [],
        }
        pending = {
            'user@co.com': {
                'roles': ['Admin'],
                'teams': [],
                'folders': [],
                'records': [],
            }
        }
        apply_calls = []
        update_calls = []

        def fake_update(p, uid, updater):
            update_calls.append(updater(dict(pending)))
            return update_calls[-1]

        poller = SailPointEntitlementPoller('cfg-uid')
        with mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.poller.read_capabilities',
            return_value=mock.Mock(
                allow_roles=True, allow_teams=True, allow_folders=True, allow_records=True
            ),
        ), mock.patch.object(SailPointPendingStore, 'load', return_value=pending), mock.patch.object(
            SailPointPendingStore, 'update', side_effect=fake_update
        ), mock.patch.object(
            SailPointEntitlementApplier,
            'apply_for_user',
            side_effect=lambda *a, **k: (apply_calls.append(1) or ({}, [])),
        ), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.poller.api.query_enterprise'
        ):
            poller.reconcile(params)

        self.assertEqual(len(apply_calls), 1)
        self.assertEqual(len(update_calls), 1)
        self.assertNotIn('user@co.com', update_calls[0])

    def test_apply_skips_roles_when_disallowed(self):
        params = mock.Mock()
        params.enterprise = {
            'users': [{'username': 'user@co.com', 'node_id': 1, 'status': 'active'}],
            'nodes': [{'node_id': 1}],
            'scims': [],
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'}}],
            'teams': [],
        }
        runs = []
        with mock.patch.object(
            SailPointEntitlementApplier, '_run', side_effect=lambda p, c: runs.append(c)
        ):
            remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                params,
                'user@co.com',
                {'roles': ['Admin'], 'teams': [], 'folders': [], 'records': []},
                allow_roles=False,
                allow_teams=True,
            )
        self.assertEqual(runs, [])
        self.assertEqual(remaining, {})
        self.assertTrue(any('allow_roles' in m for m in dropped))


if __name__ == '__main__':
    unittest.main()

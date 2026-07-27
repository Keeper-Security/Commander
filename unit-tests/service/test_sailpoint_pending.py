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
        self.assertTrue(parsed.can_edit)
        self.assertEqual(parsed.target, 'RECORD_UID')
        self.assertEqual(parsed.targets, ['RECORD_UID'])

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


class SailPointPolicyTest(unittest.TestCase):
    def test_sanitize_strips_get(self):
        cleaned = SailPointCommandPolicy.sanitize('enterprise-user,get,share-record,export')
        self.assertNotIn('get', cleaned.split(','))
        self.assertNotIn('export', cleaned.split(','))
        self.assertIn('enterprise-user', cleaned.split(','))
        self.assertIn('share-record', cleaned.split(','))

    def test_default_allowlist_matches_integration_list(self):
        expected = [
            'whoami', 'sync-down', 'enterprise-info', 'enterprise-user', 'enterprise-down',
            'share-folder', 'share-record', 'nsf-share-folder', 'nsf-share-record', 'tree',
        ]
        self.assertEqual(SailPointCommandPolicy.default_allowlist().split(','), expected)


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
                params, 'user@co.com', entry, entitlement_scope='both'
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
                params, 'user@co.com', entry, entitlement_scope='both'
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


if __name__ == '__main__':
    unittest.main()

"""Tests for Classic folder subtree conversion planning."""

from contextlib import redirect_stdout
import io
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from keepercommander.commands.nested_share_folder.conversion.conversion_acl import FolderPermissionMigration
from keepercommander.commands.nested_share_folder.conversion.conversion_app_shares import FolderApplicationShareMigration
from keepercommander.commands.nested_share_folder.conversion.conversion_planning import FolderConversionPlanner
from keepercommander.commands.nested_share_folder.conversion.conversion_records import FolderRecordMigration
from keepercommander.commands.nested_share_folder.conversion.conversion_retry import FolderConversionRetry
from keepercommander.commands.nested_share_folder.conversion.conversion_tree import FolderConversionTree
from keepercommander.commands.nested_share_folder.conversion.conversion_utils import (
    FolderConversionVerification,
)
from keepercommander.commands.nested_share_folder.conversion.conversion_commands import (
    NestedShareConvertCommand,
    NestedShareFolderConvertCommand,
    _collect_classic_subtree,
    _folder_plan,
    _pam_record_details,
    _read_applications,
    _resolve_destination_folder,
    _record_access_plan,
    _scope_accessors,
)
from keepercommander.commands.nested_share_folder import register_commands
from keepercommander.commands.nested_share_folder.parsers import (
    nested_share_convert_parser,
    nested_share_folder_convert_parser,
)
from keepercommander.commands.ksm import KSMCommand
from keepercommander.error import CommandError
from keepercommander.nested_share_folder.permissions import (
    classic_record_permissions_to_nsf_role,
    classic_shared_folder_permissions_to_nsf_role,
)
from keepercommander.nested_share_folder import record_api
from keepercommander.proto import folder_pb2, record_sharing_pb2
from keepercommander.subfolder import (
    SharedFolderFolderNode, SharedFolderNode, UserFolderNode,
)
from keepercommander import utils


def _uid():
    return utils.generate_uid()


class TestClassicFolderConversionPlanning(TestCase):

    def _chain(self, count):
        nodes = {}
        parents = {}
        depths = {}
        parent_uid = None
        for depth in range(1, count + 1):
            uid = _uid()
            node = UserFolderNode()
            node.uid = uid
            node.name = f'Folder {depth}'
            node.parent_uid = parent_uid
            node.subfolders = []
            if parent_uid:
                nodes[parent_uid].subfolders.append(uid)
            nodes[uid] = node
            parents[uid] = parent_uid
            depths[uid] = depth
            parent_uid = uid
        return nodes, parents, depths

    def test_overflow_folders_are_distinct_siblings_at_last_level(self):
        nodes, parents, depths = self._chain(7)

        available, target_levels, target_parents = _folder_plan(
            parents, depths, destination_depth=0)

        self.assertEqual(available, 5)
        source_uids = list(nodes)
        self.assertEqual(
            [target_levels[uid] for uid in source_uids],
            [1, 2, 3, 4, 5, 5, 5])
        # The two overflow folders remain separate and share the source
        # level-four folder as their target parent.
        self.assertEqual(target_parents[source_uids[5]], source_uids[3])
        self.assertEqual(target_parents[source_uids[6]], source_uids[3])
        self.assertNotEqual(source_uids[5], source_uids[6])

    def test_existing_destination_reduces_available_depth(self):
        nodes, parents, depths = self._chain(5)

        available, target_levels, target_parents = _folder_plan(
            parents, depths, destination_depth=2)

        source_uids = list(nodes)
        self.assertEqual(available, 3)
        self.assertEqual(
            [target_levels[uid] for uid in source_uids],
            [1, 2, 3, 3, 3])
        self.assertEqual(target_parents[source_uids[3]], source_uids[1])
        self.assertEqual(target_parents[source_uids[4]], source_uids[1])

    def test_duplicate_names_are_not_used_as_folder_identity(self):
        root_uid = _uid()
        left_uid, right_uid = _uid(), _uid()
        root = UserFolderNode()
        root.uid, root.name, root.subfolders = root_uid, 'Root', [left_uid, right_uid]
        left = UserFolderNode()
        left.uid, left.name, left.parent_uid, left.subfolders = left_uid, 'Same', root_uid, []
        right = UserFolderNode()
        right.uid, right.name, right.parent_uid, right.subfolders = right_uid, 'Same', root_uid, []
        params = SimpleNamespace(
            folder_cache={root_uid: root, left_uid: left, right_uid: right},
            subfolder_record_cache={},
        )

        nodes, parents, depths, _ = _collect_classic_subtree(params, root_uid)
        _, levels, target_parents = _folder_plan(parents, depths, 0)

        self.assertEqual(levels[left_uid], levels[right_uid])
        self.assertEqual(target_parents[left_uid], root_uid)
        self.assertEqual(target_parents[right_uid], root_uid)
        self.assertEqual(nodes[left_uid].name, nodes[right_uid].name)
        self.assertNotEqual(left_uid, right_uid)


    def test_classic_folder_and_record_permissions_map_independently(self):
        self.assertEqual(classic_shared_folder_permissions_to_nsf_role(), 'viewer')
        self.assertEqual(
            classic_shared_folder_permissions_to_nsf_role(manage_users=True),
            'share-manager')
        self.assertEqual(
            classic_shared_folder_permissions_to_nsf_role(manage_records=True),
            'content-manager')
        self.assertEqual(
            classic_shared_folder_permissions_to_nsf_role(
                manage_users=True, manage_records=True),
            'content-share-manager')
        self.assertEqual(classic_record_permissions_to_nsf_role(), 'viewer')
        self.assertEqual(classic_record_permissions_to_nsf_role(can_edit=True),
                         'content-manager')
        self.assertEqual(classic_record_permissions_to_nsf_role(can_share=True),
                         'share-manager')
        self.assertEqual(
            classic_record_permissions_to_nsf_role(can_edit=True, can_share=True),
            'content-share-manager')

    def test_shared_folder_record_permissions_are_applied_per_record(self):
        scope_uid = _uid()
        member_uid = _uid()
        shared_folder_uid, first_uid, second_uid = _uid(), _uid(), _uid()
        params = SimpleNamespace(shared_folder_cache={
            scope_uid: {
                'users': [{
                    'username': 'records-manager@example.com',
                    'account_uid': member_uid,
                    'manage_users': True,
                    'manage_records': True,
                }],
                'records': [
                    {'record_uid': first_uid, 'can_edit': True, 'can_share': False},
                    {'record_uid': second_uid, 'can_edit': False, 'can_share': False},
                ]
            }
        }, account_uid_bytes=None)
        record_roles = _record_access_plan(
            params,
            {first_uid: [shared_folder_uid], second_uid: [shared_folder_uid]},
            {shared_folder_uid: scope_uid},
            destination_accessors=[],
        )
        roles = {grant['record_uid']: grant['access_role_type'] for grant in record_roles}
        self.assertEqual(roles[first_uid], 'content-manager')
        self.assertEqual(roles[second_uid], 'viewer')
        self.assertEqual(len(record_roles), 2)

        accessors = _scope_accessors(
            params, scope_uid,
        )
        self.assertEqual(accessors[0]['role'], 'content-share-manager')

    def test_record_role_combines_classic_and_destination_access(self):
        scope_uid = _uid()
        shared_folder_uid, record_uid, member_uid = _uid(), _uid(), _uid()
        params = SimpleNamespace(
            shared_folder_cache={
                scope_uid: {
                    'users': [{
                        'username': 'records-manager@example.com',
                        'account_uid': member_uid,
                        'manage_users': False,
                        'manage_records': True,
                    }],
                    'records': [{
                        'record_uid': record_uid,
                        'can_edit': False,
                        'can_share': False,
                    }],
                }
            },
            account_uid_bytes=None,
        )
        plan = _record_access_plan(
            params, {record_uid: [shared_folder_uid]},
            {shared_folder_uid: scope_uid},
            destination_accessors=[{
                'access_type': 'AT_USER',
                'accessor_uid': member_uid,
                'role': 'share-manager',
            }],
        )
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]['access_role_type'], 'share-manager')

        expiring_destination = [{
            'access_type': 'AT_USER',
            'accessor_uid': member_uid,
            'role': 'share-manager',
            'tla_expiration': 5_000,
        }]
        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_acl.'
                'current_milli_time',
                return_value=1_000):
            with self.assertRaisesRegex(CommandError, 'Cannot safely preserve expiring'):
                _record_access_plan(
                    params, {record_uid: [shared_folder_uid]},
                    {shared_folder_uid: scope_uid}, expiring_destination)

    def test_record_access_plan_uses_classic_defaults_and_expiration(self):
        scope_uid, folder_uid, member_uid, expired_member_uid = (
            _uid(), _uid(), _uid(), _uid())
        explicit_uid, default_uid = _uid(), _uid()
        params = SimpleNamespace(
            shared_folder_cache={
                scope_uid: {
                    'default_can_edit': True,
                    'default_can_share': False,
                    'users': [{
                        'username': 'member@example.com',
                        'account_uid': member_uid,
                        'manage_users': True,
                        'manage_records': True,
                        'expiration': 5_000,
                    }, {
                        'username': 'expired@example.com',
                        'account_uid': expired_member_uid,
                        'manage_users': True,
                        'manage_records': True,
                        'expiration': 999,
                    }],
                    'records': [{
                        'record_uid': explicit_uid,
                        'can_edit': False,
                    }],
                }
            },
            account_uid_bytes=None,
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_acl.'
                'current_milli_time',
                return_value=1_000):
            plan = _record_access_plan(
                params,
                {explicit_uid: [folder_uid], default_uid: [folder_uid]},
                {folder_uid: scope_uid},
                [])

        roles = {entry['record_uid']: entry for entry in plan}
        self.assertEqual(roles[explicit_uid]['access_role_type'], 'viewer')
        self.assertEqual(roles[default_uid]['access_role_type'], 'content-manager')
        self.assertEqual(roles[explicit_uid]['expiration_timestamp'], 5_000)
        self.assertEqual(roles[default_uid]['expiration_timestamp'], 5_000)
        self.assertEqual(
            {entry['accessor_uid'] for entry in plan}, {member_uid})

    def test_record_access_plan_rejects_role_changes_during_overlapping_expirations(self):
        scope_uids, folder_uids, member_uid, record_uid = (
            [_uid(), _uid()], [_uid(), _uid()], _uid(), _uid())
        params = SimpleNamespace(
            shared_folder_cache={
                scope_uids[0]: {
                    'users': [{
                        'username': 'member@example.com',
                        'account_uid': member_uid,
                        'manage_users': True,
                        'manage_records': True,
                        'expiration': 3_000,
                    }],
                    'records': [{
                        'record_uid': record_uid,
                        'can_edit': True,
                        'can_share': False,
                    }],
                },
                scope_uids[1]: {
                    'users': [{
                        'username': 'member@example.com',
                        'account_uid': member_uid,
                        'manage_users': True,
                        'manage_records': True,
                        'expiration': 5_000,
                    }],
                    'records': [{
                        'record_uid': record_uid,
                        'can_edit': False,
                        'can_share': False,
                    }],
                },
            },
            account_uid_bytes=None,
        )
        placements = {record_uid: folder_uids}
        scope_by_folder = dict(zip(folder_uids, scope_uids))

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_acl.'
                'current_milli_time',
                return_value=1_000):
            with self.assertRaisesRegex(CommandError, 'change role before all access expires'):
                _record_access_plan(params, placements, scope_by_folder, [])

    def test_record_permission_reconciliation_preserves_stronger_direct_access(self):
        record_uids = [_uid(), _uid(), _uid(), _uid()]
        user_uid, team_uid, owner_uid = _uid(), _uid(), _uid()
        grants = [
            {
                'record_uid': record_uids[0], 'accessor_uid': user_uid,
                'access_type': 'AT_USER', 'access_role_type': 'viewer',
            },
            {
                'record_uid': record_uids[1], 'accessor_uid': team_uid,
                'access_type': 'AT_TEAM', 'access_role_type': 'content-manager',
            },
            {
                'record_uid': record_uids[2], 'accessor_uid': user_uid,
                'access_type': 'AT_USER', 'access_role_type': 'viewer',
            },
            {
                'record_uid': record_uids[3], 'accessor_uid': owner_uid,
                'access_type': 'AT_USER', 'access_role_type': 'viewer',
            },
        ]
        accesses = [
            {
                'record_uid': record_uids[0], 'access_type_uid': user_uid,
                'access_type': 'AT_USER', 'inherited': True,
                'access_role_type': folder_pb2.CONTENT_SHARE_MANAGER,
            },
            {
                'record_uid': record_uids[1], 'access_type_uid': team_uid,
                'access_type': 'AT_TEAM', 'inherited': False,
                'access_role_type': folder_pb2.VIEWER,
            },
            {
                'record_uid': record_uids[2], 'access_type_uid': user_uid,
                'access_type': 'AT_USER', 'inherited': False,
                'access_role_type': folder_pb2.CONTENT_MANAGER,
            },
            {
                'record_uid': record_uids[3], 'access_type_uid': owner_uid,
                'access_type': 'AT_USER', 'inherited': False, 'owner': True,
                'access_role_type': folder_pb2.MANAGER,
            },
        ]

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.get_record_accesses_v3',
                return_value={'record_accesses': accesses, 'forbidden_records': []}), \
                patch(
                    'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                    '_nsf.batch_upsert_record_accesses_v3',
                    return_value=[]) as apply_grants:
            failures = FolderPermissionMigration._grant_record_accesses(
                SimpleNamespace(), grants, set(record_uids))

        self.assertEqual(failures, [])
        applied = apply_grants.call_args.args[1]
        self.assertEqual(
            {(grant['record_uid'], grant['accessor_uid'], grant['action'])
             for grant in applied},
            {
                (record_uids[0], user_uid, 'create'),
                (record_uids[1], team_uid, 'update'),
            })
        team_update = next(grant for grant in applied if grant['record_uid'] == record_uids[1])
        self.assertEqual(team_update['access_role_type'], 'content-manager')

    def test_record_access_plan_does_not_override_classic_owner(self):
        scope_uid, folder_uid, record_uid, owner_uid = (
            _uid(), _uid(), _uid(), _uid())
        params = SimpleNamespace(
            shared_folder_cache={
                scope_uid: {
                    'owner_account_uid': owner_uid,
                    'users': [{
                        'username': 'owner@example.com',
                        'account_uid': owner_uid,
                        'manage_users': False,
                        'manage_records': False,
                    }],
                    'records': [{
                        'record_uid': record_uid,
                        'can_edit': False,
                        'can_share': False,
                    }],
                }
            },
            account_uid_bytes=None,
        )

        plan = _record_access_plan(
            params, {record_uid: [folder_uid]}, {folder_uid: scope_uid}, [])

        self.assertEqual(plan, [])

    def test_record_permission_reconciliation_does_not_override_denied_access(self):
        record_uid, user_uid = _uid(), _uid()
        grant = {
            'record_uid': record_uid, 'accessor_uid': user_uid,
            'access_type': 'AT_USER', 'access_role_type': 'viewer',
        }
        accesses = [{
            'record_uid': record_uid, 'access_type_uid': user_uid,
            'access_type': 'AT_USER', 'inherited': False,
            'denied_access': True,
        }]

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.get_record_accesses_v3',
                return_value={'record_accesses': accesses, 'forbidden_records': []}), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                 '_nsf.batch_upsert_record_accesses_v3') as apply_grants:
            failures = FolderPermissionMigration._grant_record_accesses(
                SimpleNamespace(), [grant], {record_uid})

        self.assertEqual(len(failures), 1)
        self.assertIn('explicitly denied', failures[0])
        apply_grants.assert_not_called()


class TestClassicFolderConversionVerification(TestCase):

    def _verify(self, params, retry=False):
        return FolderConversionVerification.verify(
            params,
            source_record_uids=['record'],
            converted_uids={'record'},
            target_uids={'source': 'target'},
            placements={'record': ['source']},
            retry=retry,
            link_failures=[],
            record_permission_failures=[],
            app_share_failures=[],
        )

    def test_verification_confirms_converted_records_and_folders(self):
        params = SimpleNamespace(
            nested_share_folders={'target': {}},
            nested_share_records={'record': {}},
            nested_share_folder_records={'target': {'record'}},
            sync_data=False,
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                'sync_down.sync_down'):
            complete, issues = self._verify(params, retry=True)

        self.assertTrue(complete)
        self.assertEqual(issues, [])
        self.assertTrue(params.sync_data)

    def test_retry_verification_detects_missing_record_placement(self):
        params = SimpleNamespace(
            nested_share_folders={'target': {}},
            nested_share_records={'record': {}},
            nested_share_folder_records={'target': set()},
            sync_data=False,
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                'sync_down.sync_down'):
            complete, issues = self._verify(params, retry=True)

        self.assertFalse(complete)
        self.assertIn('1 record placement(s) were not confirmed', issues)

    def test_verification_failure_is_incomplete_and_reported(self):
        params = SimpleNamespace(
            nested_share_folders={},
            nested_share_records={},
            nested_share_folder_records={},
            sync_data=False,
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                'sync_down.sync_down',
                side_effect=RuntimeError('offline')):
            complete, issues = self._verify(params)

        self.assertFalse(complete)
        self.assertIn('Final sync-down failed', issues[0])
        self.assertTrue(params.sync_data)


class TestRecordAccessShareApi(TestCase):

    def test_user_and_team_roles_are_encoded_as_nsf_enums(self):
        record_uid = _uid()
        user_uid, team_uid = _uid(), _uid()
        user_uid_bytes = utils.base64_url_decode(user_uid)
        team_uid_bytes = utils.base64_url_decode(team_uid)
        params = SimpleNamespace(
            record_cache={record_uid: {'record_key_unencrypted': b'record-key'}},
            forbid_rsa=False,
        )

        def build_user_permission(_params, _record_uid, _email, role, *_args, **_kwargs):
            return record_sharing_pb2.Permissions(
                recipientUid=user_uid_bytes,
                rules={'accessRoleType': role})

        with patch.object(
                record_api, 'resolve_uid_email',
                return_value=(user_uid_bytes, 'user@example.com')), \
             patch.object(record_api, '_build_share_permissions') as build_user:
            build_user.side_effect = build_user_permission
            user_permission = record_api._build_record_access_share_permission(
                params, {
                    'record_uid': record_uid,
                    'accessor_uid': user_uid,
                    'access_type': 'AT_USER',
                    'access_role_type': 'viewer',
                })

        self.assertEqual(build_user.call_args.args[3], folder_pb2.VIEWER)
        self.assertEqual(user_permission.rules.accessRoleType, folder_pb2.VIEWER)

        with patch.object(
                record_api, 'resolve_team_identifier',
                return_value=(team_uid, team_uid_bytes)), \
             patch.object(record_api, 'get_team_keys', return_value={}), \
             patch.object(
                 record_api, 'encrypt_for_team',
                 return_value=(b'encrypted-key', folder_pb2.encrypted_by_public_key_ecc)):
            team_permission = record_api._build_record_access_share_permission(
                params, {
                    'record_uid': record_uid,
                    'accessor_uid': team_uid,
                    'access_type': 'AT_TEAM',
                    'access_role_type': 'content-manager',
                })

        self.assertEqual(
            team_permission.rules.accessRoleType, folder_pb2.CONTENT_MANAGER)
        self.assertEqual(team_permission.recipientUid, team_uid_bytes)
        self.assertEqual(team_permission.recordKey, b'encrypted-key')

    def test_batch_matches_statuses_by_record_and_recipient_uid(self):
        record_uid = _uid()
        first_uid, second_uid = _uid(), _uid()
        grants = [
            {
                'record_uid': record_uid, 'accessor_uid': first_uid,
                'access_type': 'AT_USER', 'access_role_type': 'viewer',
                'action': 'create',
            },
            {
                'record_uid': record_uid, 'accessor_uid': second_uid,
                'access_type': 'AT_USER', 'access_role_type': 'viewer',
                'action': 'create',
            },
        ]

        def build_permission(_params, grant):
            return record_sharing_pb2.Permissions(
                recordUid=utils.base64_url_decode(grant['record_uid']),
                recipientUid=utils.base64_url_decode(grant['accessor_uid']))

        response = record_sharing_pb2.Response()
        for accessor_uid in (second_uid, first_uid):
            status = response.createdSharingStatus.add()
            status.recordUid = utils.base64_url_decode(record_uid)
            status.recipientUid = utils.base64_url_decode(accessor_uid)
            status.status = record_sharing_pb2.SUCCESS

        with patch.object(
                record_api, '_build_record_access_share_permission',
                side_effect=build_permission), \
             patch.object(record_api.api, 'communicate_rest', return_value=response) as send:
            outcomes = record_api.batch_upsert_record_accesses_v3(
                SimpleNamespace(), grants)

        self.assertEqual(
            {(grant['accessor_uid'], result['success']) for grant, result in outcomes},
            {(first_uid, True), (second_uid, True)})
        self.assertEqual(
            len(send.call_args.args[1].createSharingPermissions), 2)


    def test_classic_shared_folder_descendant_carries_its_shared_scope(self):
        shared_uid, child_uid = _uid(), _uid()
        shared = SharedFolderNode()
        shared.uid, shared.name, shared.subfolders = shared_uid, 'Shared', [child_uid]
        child = SharedFolderFolderNode()
        child.uid = child_uid
        child.name = 'Child'
        child.parent_uid = shared_uid
        child.shared_folder_uid = shared_uid
        child.subfolders = []
        params = SimpleNamespace(
            folder_cache={shared_uid: shared, child_uid: child},
            subfolder_record_cache={},
        )

        nodes, parents, depths, _ = _collect_classic_subtree(params, shared_uid)

        self.assertEqual(_scope_accessors(
            SimpleNamespace(
                shared_folder_cache={
                    shared_uid: {
                        'users': [{
                            'username': 'viewer@example.com',
                            'account_uid': _uid(),
                            'manage_users': False,
                            'manage_records': False,
                            'expiration': 1_900_000_000_000,
                        }],
                        'teams': [{
                            'team_uid': _uid(),
                            'manage_users': True,
                            'manage_records': False,
                        }],
                    }
                },
                account_uid_bytes=None,
            ), shared_uid)[0]['role'], 'viewer')
        self.assertEqual(parents[child_uid], shared_uid)
        self.assertEqual(depths[child_uid], 2)
        self.assertIsInstance(nodes[child_uid], SharedFolderFolderNode)

        scope_by_folder = {
            shared_uid: shared_uid,
            child_uid: shared_uid,
        }
        self.assertEqual(
            FolderPermissionMigration._scope_grant_targets(
                nodes, {shared_uid: None, child_uid: shared_uid},
                scope_by_folder),
            [(shared_uid, shared_uid)])

    def test_private_parent_and_shared_child_start_separate_acl_scopes(self):
        private_uid, shared_uid = _uid(), _uid()
        private = UserFolderNode()
        private.uid, private.name, private.subfolders = private_uid, 'Private', [shared_uid]
        shared = SharedFolderNode()
        shared.uid, shared.name, shared.subfolders = shared_uid, 'Shared', []
        params = SimpleNamespace(
            folder_cache={private_uid: private, shared_uid: shared},
            subfolder_record_cache={},
        )
        nodes, parents, _, _ = _collect_classic_subtree(params, private_uid)
        scope_by_folder = {
            private_uid: None,
            shared_uid: shared_uid,
        }

        self.assertEqual(
            FolderPermissionMigration._scope_grant_targets(
                nodes, {private_uid: None, shared_uid: private_uid},
                scope_by_folder),
            [(shared_uid, shared_uid)])


class TestNsfConversionDestinationSelection(TestCase):

    def test_exact_folder_uid_takes_precedence_over_a_matching_name(self):
        uid = _uid()
        params = SimpleNamespace(nested_share_folders={
            uid: {'name': 'Destination', 'parent_uid': ''},
            _uid(): {'name': uid, 'parent_uid': ''},
        })

        with patch('builtins.input') as prompt:
            result = _resolve_destination_folder(
                params, uid, 'nsf-convert-folder')

        self.assertEqual(result, uid)
        prompt.assert_not_called()

    def test_duplicate_destination_names_prompt_and_select_uid(self):
        parent_uid, first_uid, second_uid = _uid(), _uid(), _uid()
        params = SimpleNamespace(nested_share_folders={
            parent_uid: {'name': 'Parent', 'parent_uid': ''},
            first_uid: {'name': 'Destination', 'parent_uid': ''},
            second_uid: {'name': 'Destination', 'parent_uid': parent_uid},
        })

        with patch('builtins.input', return_value='2') as prompt, \
             redirect_stdout(io.StringIO()) as output:
            result = _resolve_destination_folder(
                params, 'Destination', 'nsf-convert-folder')

        selected_uid = sorted((first_uid, second_uid))[1]
        self.assertEqual(result, selected_uid)
        expected_path = (
            f'Parent/Destination ({selected_uid})'
            if selected_uid == second_uid else
            f'Destination ({selected_uid})')
        self.assertIn(expected_path, output.getvalue())
        prompt.assert_called_once()

    def test_force_requires_uid_for_ambiguous_destination(self):
        params = SimpleNamespace(nested_share_folders={
            _uid(): {'name': 'Destination', 'parent_uid': ''},
            _uid(): {'name': 'Destination', 'parent_uid': ''},
        })

        with patch('builtins.input') as prompt:
            with self.assertRaisesRegex(CommandError, 'Use a folder UID'):
                _resolve_destination_folder(
                    params, 'Destination', 'nsf-convert-record', force=True)

        prompt.assert_not_called()

    def test_destination_resolution_escapes_terminal_controls_in_input(self):
        input_name = 'missing\x1b[2J'
        params = SimpleNamespace(nested_share_folders={})

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.resolve_folder_identifier',
                return_value=None):
            with self.assertRaises(CommandError) as raised:
                _resolve_destination_folder(
                    params, input_name, 'nsf-convert-folder')

        self.assertIn(r'missing\u001b[2J', raised.exception.message)
        self.assertNotIn('\x1b', raised.exception.message)

    def test_destination_access_is_fully_paginated_and_deduplicated(self):
        destination_uid, user_uid, team_uid, app_uid = (
            _uid(), _uid(), _uid(), _uid())
        pages = [
            {
                'results': [{
                    'folder_uid': destination_uid,
                    'success': True,
                    'accessors': [{
                        'accessor_uid': user_uid,
                        'access_type': 'AT_USER',
                        'username': 'person@example.com',
                        'role': 'VIEWER',
                        'inherited': False,
                    }],
                }],
                'has_more': True,
                'continuation_token': 17,
            },
            {
                'results': [{
                    'folder_uid': destination_uid,
                    'success': True,
                    'accessors': [
                        {
                            'accessor_uid': user_uid,
                            'access_type': 'AT_USER',
                            'username': 'person@example.com',
                            'role': 'VIEWER',
                            'inherited': False,
                        },
                        {
                            'accessor_uid': team_uid,
                            'access_type': 'AT_TEAM',
                            'username': 'Operations',
                            'role': 'CONTENT_MANAGER',
                            'inherited': True,
                        },
                        {
                            'accessor_uid': app_uid,
                            'access_type': 'AT_APPLICATION',
                            'role': 'CONTENT_MANAGER',
                            'inherited': True,
                        },
                        {
                            'accessor_uid': _uid(),
                            'access_type': 'AT_USER',
                            'denied_access': True,
                        },
                    ],
                }],
                'has_more': False,
            },
        ]

        with patch(
                'keepercommander.nested_share_folder.folder_api.get_folder_access_v3',
                side_effect=pages) as get_access:
            accessors = FolderPermissionMigration._destination_accessors(
                SimpleNamespace(), destination_uid)

        self.assertEqual(len(accessors), 3)
        self.assertIn(app_uid, {accessor['accessor_uid'] for accessor in accessors})
        self.assertEqual(
            [page.kwargs['continuation_token'] for page in get_access.call_args_list],
            [None, 17])

    def test_destination_access_preview_discloses_users_teams_and_applications(self):
        folder_uid, destination_uid = _uid(), _uid()
        app_uid = _uid()
        folder = UserFolderNode()
        folder.uid, folder.name = folder_uid, 'Private'
        params = SimpleNamespace(
            nested_share_folders={destination_uid: {'name': 'Destination'}})
        accessors = [
            {
                'accessor_uid': _uid(),
                'access_type': 'AT_USER',
                'username': 'person@example.com',
                'role': 'VIEWER',
                'inherited': False,
            },
            {
                'accessor_uid': _uid(),
                'access_type': 'AT_TEAM',
                'username': 'Operations',
                'role': 'SHARE_MANAGER',
                'inherited': True,
            },
            {
                'accessor_uid': app_uid,
                'access_type': 'AT_APPLICATION',
                'role': 'CONTENT_MANAGER',
                'inherited': True,
            },
        ]

        output = io.StringIO()
        with redirect_stdout(output):
            NestedShareFolderConvertCommand._print_preview(
                params, {folder_uid: folder}, {folder_uid: []}, folder,
                destination_uid, 5, [], {folder_uid: 1}, {folder_uid: 1}, [],
                destination_accessors=accessors)

        rendered = output.getvalue()
        self.assertIn('Access inherited by new folders from the destination', rendered)
        self.assertIn('person@example.com', rendered)
        self.assertIn('Operations', rendered)
        self.assertIn(f'Application: {app_uid}', rendered)

class TestClassicFolderConversionApplicationReads(TestCase):

    def test_app_info_is_requested_in_batches_and_shares_are_mapped(self):
        app_uids = [_uid() for _ in range(101)]
        params = SimpleNamespace(
            record_cache={
                uid: {
                    'version': 5,
                    'data_unencrypted': b'{"type":"app"}',
                    'record_key_unencrypted': utils.generate_aes_key(),
                }
                for uid in app_uids
            },
            nested_share_records={},
        )
        calls = []
        shared_folder_uid = _uid()
        record_uid = _uid()

        def get_app_info_batch(_params, batch):
            calls.append(list(batch))
            results = []
            for uid in batch:
                shares = []
                if uid == app_uids[0]:
                    shares = [
                        SimpleNamespace(
                            secretUid=utils.base64_url_decode(shared_folder_uid),
                            shareType=1,
                            editable=True,
                        ),
                        SimpleNamespace(
                            secretUid=utils.base64_url_decode(record_uid),
                            shareType=0,
                            editable=False,
                        ),
                    ]
                results.append(SimpleNamespace(
                    appRecordUid=utils.base64_url_decode(uid),
                    shares=shares,
                ))
            return results

        with patch.object(
                KSMCommand, 'get_app_info_batch', side_effect=get_app_info_batch):
            applications = _read_applications(params)

        self.assertEqual([len(batch) for batch in calls], [100, 1])
        self.assertEqual(len(applications), 101)
        self.assertEqual(applications[app_uids[0]]['shares'], [
            {'uid': shared_folder_uid, 'type': 1, 'editable': True},
            {'uid': record_uid, 'type': 0, 'editable': False},
        ])
        self.assertEqual(applications[app_uids[-1]]['shares'], [])

    def test_get_app_info_batch_sends_multiple_unique_uids(self):
        app_uids = [_uid(), _uid()]
        response = SimpleNamespace(appInfo=[])

        with patch(
                'keepercommander.commands.ksm.api.communicate_rest',
                return_value=response) as communicate_rest:
            result = KSMCommand.get_app_info_batch(
                SimpleNamespace(), [app_uids[0], app_uids[1], app_uids[0]])

        self.assertEqual(result, [])
        request = communicate_rest.call_args.args[1]
        self.assertEqual(list(request.appRecordUid), [
            utils.base64_url_decode(uid) for uid in app_uids
        ])
        self.assertEqual(communicate_rest.call_args.args[2], 'vault/get_app_info')

    def test_missing_application_details_abort_before_conversion(self):
        app_uid = _uid()
        params = SimpleNamespace(
            record_cache={
                app_uid: {
                    'version': 5,
                    'data_unencrypted': b'{"type":"app"}',
                    'record_key_unencrypted': utils.generate_aes_key(),
                }
            },
            nested_share_records={},
        )

        with patch.object(KSMCommand, 'get_app_info_batch', return_value=[]):
            with self.assertRaises(CommandError):
                _read_applications(params)

    def test_converted_record_shares_fetch_each_application_once(self):
        app_uid = _uid()
        record_uids = [_uid(), _uid()]
        params = SimpleNamespace()
        application_shares = {
            uid: [{'app_uid': app_uid, 'editable': True}]
            for uid in record_uids
        }
        app_info = SimpleNamespace(
            appRecordUid=utils.base64_url_decode(app_uid),
            shares=[],
        )

        with patch.object(
                KSMCommand, 'get_app_info_batch', return_value=[app_info]) as read_apps, \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                 '_nsf.share_record_to_application_v3',
                 return_value={'success': True}) as share_record:
            failures = FolderApplicationShareMigration._grant_record_app_shares(
                params,
                application_shares,
                set(record_uids),
                {app_uid: {'key': utils.generate_aes_key()}},
            )

        self.assertEqual(failures, [])
        read_apps.assert_called_once_with(params, [app_uid])
        self.assertEqual(share_record.call_count, 2)


class TestClassicFolderConversionTargetCreation(TestCase):

    def test_retry_reuses_unique_existing_folders_and_creates_missing_folders(self):
        source_root_uid, source_child_uid = _uid(), _uid()
        destination_uid, existing_root_uid = _uid(), _uid()
        source_root = UserFolderNode()
        source_root.uid, source_root.name = source_root_uid, 'Root'
        source_child = UserFolderNode()
        source_child.uid, source_child.name = source_child_uid, 'Child'
        params = SimpleNamespace(nested_share_folders={
            destination_uid: {'name': 'Destination', 'parent_uid': ''},
            existing_root_uid: {
                'name': 'Root',
                'parent_uid': destination_uid,
                'folder_key_unencrypted': utils.generate_aes_key(),
            },
        }, nested_share_folder_records={})
        nodes = {source_root_uid: source_root, source_child_uid: source_child}
        levels = {source_root_uid: 1, source_child_uid: 2}
        parents = {source_root_uid: None, source_child_uid: source_root_uid}
        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_retry.'
                'user_choice', return_value='y'):
            retry_mapping = FolderConversionRetry._select_retry_folders(
                params, nodes, levels, parents, destination_uid, {})

        self.assertEqual(retry_mapping, {source_root_uid: existing_root_uid})
        created_specs = []

        def create_batch(_params, specs):
            created_specs.extend(specs)
            return [{
                'folder_uid': _uid(),
                'folder_key_unencrypted': utils.generate_aes_key(),
                'name': spec['name'],
                'parent_uid': spec['parent_uid'],
                'success': True,
            } for spec in specs]

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.create_folders_batch_v3', side_effect=create_batch), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_retry.'
                 'user_choice', return_value='y'):
            target_uids = FolderConversionTree._create_target_tree(
                params, nodes, levels, parents, destination_uid, False,
                existing_target_uids=retry_mapping)

        self.assertEqual(target_uids[source_root_uid], existing_root_uid)
        self.assertEqual(len(created_specs), 1)
        self.assertEqual(created_specs[0]['name'], 'Child')
        self.assertEqual(created_specs[0]['parent_uid'], existing_root_uid)

    def test_retry_requires_explicit_mapping_for_same_name_candidates(self):
        source_one_uid, source_two_uid = _uid(), _uid()
        candidate_one_uid, candidate_two_uid = 'A' * 22, 'B' * 22
        source_one, source_two = UserFolderNode(), UserFolderNode()
        source_one.uid, source_one.name = source_one_uid, 'Same'
        source_two.uid, source_two.name = source_two_uid, 'Same'
        params = SimpleNamespace(
            nested_share_folders={
                candidate_one_uid: {
                    'name': 'Same', 'parent_uid': '',
                    'folder_key_unencrypted': utils.generate_aes_key(),
                },
                candidate_two_uid: {
                    'name': 'Same', 'parent_uid': '',
                    'folder_key_unencrypted': utils.generate_aes_key(),
                },
            },
            nested_share_folder_records={},
        )

        with patch('builtins.input', side_effect=['2', '1']), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_retry.'
                 'user_choice', return_value='y') as confirm, \
             redirect_stdout(io.StringIO()):
            mapping = FolderConversionRetry._select_retry_folders(
                params,
                {source_one_uid: source_one, source_two_uid: source_two},
                {source_one_uid: 1, source_two_uid: 1},
                {source_one_uid: None, source_two_uid: None},
                None,
                {},
            )

        self.assertEqual(mapping, {
            source_one_uid: candidate_two_uid,
            source_two_uid: candidate_one_uid,
        })
        confirm.assert_called_once()

    def test_retry_does_not_reuse_candidates_when_user_rejects(self):
        source_uid, candidate_uid = _uid(), _uid()
        source = UserFolderNode()
        source.uid, source.name = source_uid, 'Same'
        params = SimpleNamespace(
            nested_share_folders={
                candidate_uid: {
                    'name': 'Same',
                    'parent_uid': '',
                    'folder_key_unencrypted': utils.generate_aes_key(),
                },
            },
            nested_share_folder_records={},
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_retry.'
                'user_choice', return_value='n'), \
             redirect_stdout(io.StringIO()):
            mapping = FolderConversionRetry._select_retry_folders(
                params, {source_uid: source}, {source_uid: 1},
                {source_uid: None}, None, {})

        self.assertEqual(mapping, {})

    def test_retry_does_not_reuse_candidate_without_decrypted_folder_key(self):
        source_uid, candidate_uid = _uid(), _uid()
        source = UserFolderNode()
        source.uid, source.name = source_uid, 'Same'
        params = SimpleNamespace(
            nested_share_folders={
                candidate_uid: {'name': 'Same', 'parent_uid': ''},
            },
            nested_share_folder_records={},
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_retry.'
                'user_choice') as confirm, \
             redirect_stdout(io.StringIO()) as output:
            mapping = FolderConversionRetry._select_retry_folders(
                params, {source_uid: source}, {source_uid: 1},
                {source_uid: None}, None, {})

        self.assertEqual(mapping, {})
        self.assertIn('folder key unavailable', output.getvalue())
        confirm.assert_not_called()

    def test_source_root_inherits_destination_permissions_but_vault_root_does_not(self):
        scenarios = (
            ('private destination root', UserFolderNode(), _uid(), True),
            ('shared destination root', SharedFolderNode(), _uid(), True),
            ('private vault root', UserFolderNode(), None, False),
        )

        for name, node, destination_uid, expected_inheritance in scenarios:
            with self.subTest(name=name):
                source_uid = _uid()
                node.uid, node.name = source_uid, name
                params = SimpleNamespace(nested_share_folders={})
                captured_specs = []

                def create_batch(_params, specs):
                    captured_specs.extend(specs)
                    return [{
                        'folder_uid': _uid(),
                        'folder_key_unencrypted': utils.generate_aes_key(),
                        'name': spec['name'],
                        'parent_uid': spec['parent_uid'],
                        'success': True,
                    } for spec in specs]

                with patch(
                        'keepercommander.commands.nested_share_folder.conversion.'
                        'conversion_commands._nsf.create_folders_batch_v3',
                        side_effect=create_batch):
                    FolderConversionTree._create_target_tree(
                        params,
                        {source_uid: node},
                        {source_uid: 1},
                        {source_uid: None},
                        destination_uid=destination_uid,
                        show_progress=False,
                    )

                self.assertEqual(len(captured_specs), 1)
                self.assertEqual(
                    captured_specs[0]['inherit_permissions'], expected_inheritance)
                self.assertEqual(captured_specs[0]['parent_uid'], destination_uid)

    def test_classic_shared_boundary_inherits_destination_through_private_parent(self):
        private_uid, shared_uid = _uid(), _uid()
        private = UserFolderNode()
        private.uid, private.name = private_uid, 'Private'
        shared = SharedFolderNode()
        shared.uid, shared.name = shared_uid, 'Shared'
        params = SimpleNamespace(nested_share_folders={})
        captured_specs = []

        def create_batch(_params, specs):
            captured_specs.extend(specs)
            return [{
                'folder_uid': _uid(),
                'folder_key_unencrypted': utils.generate_aes_key(),
                'name': spec['name'],
                'parent_uid': spec['parent_uid'],
                'success': True,
            } for spec in specs]

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.'
                'conversion_commands._nsf.create_folders_batch_v3',
                side_effect=create_batch):
            FolderConversionTree._create_target_tree(
                params,
                {private_uid: private, shared_uid: shared},
                {private_uid: 1, shared_uid: 2},
                {private_uid: None, shared_uid: private_uid},
                destination_uid=_uid(),
                show_progress=False,
            )

        self.assertEqual(
            [spec['inherit_permissions'] for spec in captured_specs],
            [True, True])

    def test_duplicate_names_get_distinct_generated_folder_uids(self):
        first_uid, second_uid = _uid(), _uid()
        first = UserFolderNode()
        first.uid, first.name, first.color = first_uid, 'Duplicate', 'blue'
        second = UserFolderNode()
        second.uid, second.name = second_uid, 'Duplicate'
        nodes = {first_uid: first, second_uid: second}
        params = SimpleNamespace(nested_share_folders={})

        def create_batch(params, specs):
            return [
                {
                    'folder_uid': _uid(),
                    'folder_key_unencrypted': utils.generate_aes_key(),
                    'name': spec['name'],
                    'success': True,
                }
                for spec in specs
            ]

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.create_folders_batch_v3',
                side_effect=create_batch):
            target_uids = FolderConversionTree._create_target_tree(
                params,
                nodes,
                {first_uid: 1, second_uid: 1},
                {first_uid: None, second_uid: None},
                destination_uid=None,
                show_progress=False,
            )

        self.assertNotEqual(target_uids[first_uid], target_uids[second_uid])
        self.assertEqual(
            params.nested_share_folders[target_uids[first_uid]]['name'], 'Duplicate')
        self.assertEqual(
            params.nested_share_folders[target_uids[second_uid]]['name'], 'Duplicate')
        self.assertEqual(
            params.nested_share_folders[target_uids[first_uid]]['color'], 'blue')


class TestPamRecordConversionRestrictions(TestCase):

    def test_retry_collects_records_already_converted_in_a_prior_attempt(self):
        source_uid, record_uid = _uid(), _uid()
        params = SimpleNamespace(
            nested_share_records={record_uid: {}},
            record_cache={},
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                '_record_type', return_value='login'):
            record_uids, placements, skipped = (
                FolderConversionPlanner._collect_records(
                    params,
                    {source_uid: object()},
                    {source_uid: [record_uid]},
                    allow_converted=True,
                ))

        self.assertEqual(record_uids, [record_uid])
        self.assertEqual(placements, {record_uid: [source_uid]})
        self.assertEqual(skipped, [])

    def test_pam_detection_uses_typed_record_type_and_captures_title(self):
        pam_uid, regular_uid = _uid(), _uid()
        params = SimpleNamespace(
            record_cache={
                pam_uid: {
                    'record_uid': pam_uid,
                    'version': 3,
                    'record_key_unencrypted': utils.generate_aes_key(),
                    'data_unencrypted': b'{"type":"pamRemoteBrowser","title":"Browser"}',
                },
                regular_uid: {
                    'record_uid': regular_uid,
                    'version': 3,
                    'record_key_unencrypted': utils.generate_aes_key(),
                    'data_unencrypted': b'{"type":"login","title":"Login"}',
                },
            },
        )

        self.assertEqual(
            _pam_record_details(params, pam_uid),
            {
                'record_uid': pam_uid,
                'record_type': 'pamRemoteBrowser',
                'title': 'Browser',
            })
        self.assertIsNone(_pam_record_details(params, regular_uid))

    def test_folder_collection_skips_all_pam_record_types(self):
        folder_uid = _uid()
        pam_types = (
            'pamMachine', 'pamUser', 'pamDatabase', 'pamDirectory',
            'pamRemoteBrowser', 'pamAwsConfiguration',
        )
        pam_uids = [_uid() for _ in pam_types]
        regular_uid = _uid()
        record_uids = pam_uids + [regular_uid]
        params = SimpleNamespace(
            nested_share_records={},
            record_cache={uid: {} for uid in record_uids},
        )
        types_by_uid = dict(zip(pam_uids, pam_types))
        types_by_uid[regular_uid] = 'login'

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                '_record_type',
                side_effect=lambda _params, uid: types_by_uid[uid]):
            converted_uids, placements, skipped = (
                FolderConversionPlanner._collect_records(
                    params, {folder_uid: object()},
                    {folder_uid: record_uids}))

        self.assertEqual(converted_uids, [regular_uid])
        self.assertEqual(placements, {regular_uid: [folder_uid]})
        self.assertEqual(
            [record['record_type'] for record in skipped], list(pam_types))
        self.assertEqual(
            [record['record_uid'] for record in skipped], pam_uids)

    def test_folder_preview_lists_each_skipped_pam_record(self):
        folder_uid, destination_uid = _uid(), _uid()
        folder = UserFolderNode()
        folder.uid, folder.name = folder_uid, 'PAM Folder'
        params = SimpleNamespace(
            nested_share_folders={destination_uid: {'name': 'Destination'}})
        skipped = [
            {'record_uid': _uid(), 'record_type': 'pamMachine', 'title': 'Machine'},
            {'record_uid': _uid(), 'record_type': 'pamUser', 'title': 'User'},
        ]

        output = io.StringIO()
        with redirect_stdout(output):
            NestedShareFolderConvertCommand._print_preview(
                params, {folder_uid: folder}, {folder_uid: []}, folder,
                destination_uid, 5, [],
                {folder_uid: 1}, {folder_uid: 1}, skipped)

        self.assertIn('PAM records skipped: 2', output.getvalue())
        self.assertIn(
            f'Destination: Destination ({destination_uid})', output.getvalue())
        self.assertIn('Machine', output.getvalue())
        self.assertIn('pamMachine', output.getvalue())
        self.assertIn('User', output.getvalue())
        self.assertIn('pamUser', output.getvalue())
        self.assertIn('source tree will be retained', output.getvalue())
        self.assertLess(
            output.getvalue().index('Source folders:'),
            output.getvalue().index('Summary'))
        self.assertLess(
            output.getvalue().index('Summary'),
            output.getvalue().index('Folders: 1'))

    def test_folder_conversion_output_escapes_terminal_control_characters(self):
        folder_uid, destination_uid, target_uid = _uid(), _uid(), _uid()
        unsafe_name = 'Private\n\x1b[2J'
        escaped_name = r'Private\u000a\u001b[2J'
        folder = UserFolderNode()
        folder.uid, folder.name = folder_uid, unsafe_name
        params = SimpleNamespace(
            nested_share_folders={destination_uid: {'name': unsafe_name}})

        output = io.StringIO()
        with redirect_stdout(output):
            NestedShareFolderConvertCommand._print_preview(
                params, {folder_uid: folder}, {folder_uid: []}, folder,
                destination_uid, 5, [], {folder_uid: 1}, {folder_uid: 1}, [])
            FolderConversionTree._print_uid_mapping(
                {folder_uid: folder}, {folder_uid: target_uid})

        rendered = output.getvalue()
        self.assertIn(f'Source: {escaped_name} ({folder_uid})', rendered)
        self.assertIn(f'Destination: {escaped_name} ({destination_uid})', rendered)
        self.assertIn(f'{escaped_name} ({folder_uid}) -> {target_uid}', rendered)
        self.assertNotIn('\x1b[2J', rendered)
        self.assertNotIn(unsafe_name, rendered)

    def test_record_command_skips_pam_but_converts_selected_classic_records(self):
        pam_uid, regular_uid = _uid(), _uid()
        params = SimpleNamespace(
            record_cache={pam_uid: {}, regular_uid: {}},
            nested_share_records={},
            sync_data=False,
        )
        types_by_uid = {pam_uid: 'pamMachine', regular_uid: 'login'}

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                '_record_type',
                side_effect=lambda _params, uid: types_by_uid[uid]), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                 '_nsf.convert_records_v3',
                 return_value=[{
                     'record_uid': regular_uid,
                     'status': 'SUCCESS',
                     'success': True,
                 }]) as convert_records:
            output = io.StringIO()
            with redirect_stdout(output):
                NestedShareConvertCommand().execute(
                    params, records=[pam_uid, regular_uid], force=True)

        convert_records.assert_called_once_with(
            params, record_uids=[regular_uid], folder_uid=None)
        self.assertIn('[1/2]', output.getvalue())
        self.assertIn('Converting 1 Classic record(s)...', output.getvalue())
        self.assertIn('[2/2]', output.getvalue())
        self.assertIn('Processing conversion results...', output.getvalue())
        self.assertIn(pam_uid, output.getvalue())
        self.assertIn('pamMachine', output.getvalue())

    def test_record_command_does_not_call_conversion_for_only_pam_records(self):
        pam_uid = _uid()
        params = SimpleNamespace(
            record_cache={pam_uid: {}},
            nested_share_records={},
            sync_data=False,
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                '_record_type',
                return_value='pamUser'), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                 '_nsf.convert_records_v3') as convert_records:
            output = io.StringIO()
            with redirect_stdout(output):
                NestedShareConvertCommand().execute(
                    params, records=[pam_uid], force=True)

        convert_records.assert_not_called()
        self.assertIn(pam_uid, output.getvalue())
        self.assertIn('pamUser', output.getvalue())

    def test_conversion_help_explains_pam_records_are_skipped(self):
        self.assertIn('PAM', nested_share_convert_parser.format_help())
        self.assertIn('PAM', nested_share_folder_convert_parser.format_help())
        self.assertIn('--retry', nested_share_folder_convert_parser.format_help())

    def test_legacy_nsf_convert_alias_warns_before_running(self):
        commands = {}
        register_commands(commands)
        self.assertIn('nsf-convert', commands)

        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(CommandError):
            NestedShareConvertCommand().execute(
                SimpleNamespace(), command='nsf-convert', records=[])
        self.assertIn('nsf-convert is deprecated', output.getvalue())
        self.assertIn('nsf-convert-record', output.getvalue())


class TestClassicFolderConversionExecution(TestCase):

    def _params(self):
        folder_uid, record_uid, target_uid = _uid(), _uid(), _uid()
        folder = UserFolderNode()
        folder.uid, folder.name, folder.subfolders = folder_uid, 'Private', []
        params = SimpleNamespace(
            folder_cache={folder_uid: folder},
            subfolder_record_cache={folder_uid: {record_uid}},
            record_cache={record_uid: {'record_uid': record_uid}},
            nested_share_records={},
            nested_share_folders={},
            shared_folder_cache={},
            data_key=utils.generate_aes_key(),
            user='owner@example.com',
            sync_data=False,
        )
        return params, folder_uid, record_uid, target_uid

    def _run_command(self, params, folder_uid, record_uid, target_uid, *,
                     force=False, converted=True, record_type=''):
        def create_tree(*args, **kwargs):
            params.nested_share_folders[target_uid] = {
                'name': 'Private',
                'parent_uid': '',
                'folder_key_unencrypted': utils.generate_aes_key(),
            }
            return {folder_uid: target_uid}

        def convert_records(_params, record_uids, _placements, _target_uids):
            if converted and record_uid in record_uids:
                params.nested_share_records[record_uid] = {}
                return set(record_uids)
            return set()

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_app_shares.'
                'FolderApplicationShareMigration._read_applications', return_value={}), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_utils.'
                 '_record_type', return_value=record_type), \
             patch.object(NestedShareFolderConvertCommand, '_print_preview'), \
             patch.object(
                 FolderConversionTree, '_create_target_tree',
                 side_effect=create_tree), \
             patch.object(
                 FolderRecordMigration, '_convert_records',
                 side_effect=convert_records), \
             patch.object(
                 FolderRecordMigration, '_create_additional_placements',
                 return_value=[]), \
             patch.object(
                 FolderApplicationShareMigration, '_grant_record_app_shares',
                 return_value=[]), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.folder_conversion.'
                 'sync_down.sync_down'), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.folder_conversion.'
                 'user_choice', return_value='y') as user_choice, \
             patch.object(
                 FolderConversionTree, '_delete_classic_source') as delete_source:
            NestedShareFolderConvertCommand().execute(
                params, source=folder_uid, folder_uid=None, force=force)
        return user_choice, delete_source

    def test_success_prompts_before_deleting_classic_tree(self):
        params, folder_uid, record_uid, target_uid = self._params()

        user_choice, delete_source = self._run_command(
            params, folder_uid, record_uid, target_uid)

        self.assertEqual(user_choice.call_count, 2)
        delete_source.assert_called_once_with(params, folder_uid)

    def test_force_deletes_only_after_success_without_prompts(self):
        params, folder_uid, record_uid, target_uid = self._params()

        user_choice, delete_source = self._run_command(
            params, folder_uid, record_uid, target_uid, force=True)

        user_choice.assert_not_called()
        delete_source.assert_called_once_with(params, folder_uid)

    def test_force_keeps_classic_source_if_record_conversion_is_partial(self):
        params, folder_uid, record_uid, target_uid = self._params()

        user_choice, delete_source = self._run_command(
            params, folder_uid, record_uid, target_uid,
            force=True, converted=False)

        user_choice.assert_not_called()
        delete_source.assert_not_called()

    def test_retry_cannot_be_combined_with_force(self):
        with self.assertRaisesRegex(CommandError, 'cannot be combined with --force'):
            NestedShareFolderConvertCommand().execute(
                SimpleNamespace(), source='source', retry=True, force=True)

    def test_initial_refresh_failure_aborts_before_conversion(self):
        params, folder_uid, _, _ = self._params()

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.folder_conversion.'
                'sync_down.sync_down',
                side_effect=RuntimeError('offline')), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion.conversion_app_shares.'
                 'FolderApplicationShareMigration._read_applications') as read_applications:
            with self.assertRaisesRegex(CommandError, 'no changes were made'):
                NestedShareFolderConvertCommand().execute(
                    params, source=folder_uid, force=True)

        read_applications.assert_not_called()
        self.assertNotIn(folder_uid, params.nested_share_folders)

    def test_force_retains_classic_source_when_pam_records_are_skipped(self):
        params, folder_uid, record_uid, target_uid = self._params()

        user_choice, delete_source = self._run_command(
            params, folder_uid, record_uid, target_uid,
            force=True, record_type='pamMachine')

        user_choice.assert_not_called()
        delete_source.assert_not_called()
        self.assertNotIn(record_uid, params.nested_share_records)

    def test_incomplete_conversion_reports_moved_remaining_and_retry(self):
        folder_uid, moved_uid, remaining_uid, uncertain_uid = (
            _uid(), _uid(), _uid(), _uid())
        target_uid, destination_uid = _uid(), _uid()
        folder = UserFolderNode()
        folder.uid, folder.name, folder.subfolders = folder_uid, 'Private', []
        params = SimpleNamespace(
            folder_cache={folder_uid: folder},
            subfolder_record_cache={folder_uid: {remaining_uid}},
            nested_share_records={moved_uid: {}},
        )
        output = io.StringIO()

        with redirect_stdout(output):
            FolderConversionRetry._print_incomplete_conversion(
                params,
                folder_uid,
                destination_uid,
                [moved_uid, remaining_uid, uncertain_uid],
                {moved_uid},
                {folder_uid: target_uid},
                {},
            )

        rendered = output.getvalue()
        self.assertIn(f'Records confirmed in NSF: 1\n    - {moved_uid}', rendered)
        self.assertIn(f'Records still placed in Classic: 1\n    - {remaining_uid}', rendered)
        self.assertIn(
            f'Records with an unconfirmed conversion result: 1\n    - {uncertain_uid}',
            rendered)
        self.assertIn('no automatic rollback was attempted', rendered)
        self.assertIn(
            f'nsf-convert-folder "{folder_uid}" --retry --folder "{destination_uid}"',
            rendered)

    def test_delete_refuses_to_remove_nonempty_source_tree(self):
        params, folder_uid, record_uid, _ = self._params()
        remove_path = 'keepercommander.commands.folder.FolderRemoveCommand.execute'

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_tree.'
                'sync_down.sync_down'), patch(remove_path) as remove:
            deleted = FolderConversionTree._delete_classic_source(
                params, folder_uid)

        self.assertFalse(deleted)
        remove.assert_not_called()

    def test_delete_refreshes_and_removes_only_an_empty_source_tree(self):
        params, folder_uid, _, _ = self._params()
        params.subfolder_record_cache[folder_uid] = set()
        sync_calls = []

        def refresh(_params):
            sync_calls.append(True)
            if len(sync_calls) == 2:
                params.folder_cache.pop(folder_uid, None)

        remove_path = 'keepercommander.commands.folder.FolderRemoveCommand.execute'
        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_tree.'
                'sync_down.sync_down', side_effect=refresh), \
             patch(remove_path) as remove:
            deleted = FolderConversionTree._delete_classic_source(
                params, folder_uid)

        self.assertTrue(deleted)
        self.assertEqual(len(sync_calls), 2)
        remove.assert_called_once()
        self.assertEqual(remove.call_args.kwargs, {
            'pattern': [folder_uid], 'force': True, 'quiet': True,
        })

    def test_delete_does_not_continue_when_fresh_sync_fails(self):
        params, folder_uid, _, _ = self._params()
        remove_path = 'keepercommander.commands.folder.FolderRemoveCommand.execute'

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_tree.'
                'sync_down.sync_down', side_effect=RuntimeError('sync failed')), \
             patch(remove_path) as remove:
            result = FolderConversionTree._delete_classic_source(
                params, folder_uid)

        self.assertIsNone(result)
        remove.assert_not_called()

    def test_missing_additional_placement_result_is_a_conversion_failure(self):
        source_uids = [_uid(), _uid()]
        record_uid = _uid()
        target_uids = {
            source_uids[0]: _uid(),
            source_uids[1]: _uid(),
        }

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.manage_folder_records_batch_v3',
                return_value=[]):
            failures = FolderRecordMigration._create_additional_placements(
                SimpleNamespace(),
                {record_uid},
                {record_uid: source_uids},
                target_uids,
            )

        self.assertEqual(len(failures), 1)
        self.assertIn('no link result returned', failures[0])

    def test_retry_adds_only_missing_record_placements(self):
        source_folders = [_uid(), _uid()]
        target_folders = [_uid(), _uid()]
        record_uid = _uid()
        params = SimpleNamespace(
            nested_share_folder_records={target_folders[0]: {record_uid}},
        )

        with patch(
                'keepercommander.commands.nested_share_folder.conversion.conversion_commands.'
                '_nsf.manage_folder_records_batch_v3',
                return_value=[{'record_uid': record_uid, 'success': True}]) as add:
            failures = FolderRecordMigration._create_additional_placements(
                params,
                {record_uid},
                {record_uid: source_folders},
                dict(zip(source_folders, target_folders)),
                include_primary_for={record_uid},
            )

        self.assertEqual(failures, [])
        add.assert_called_once_with(
            params, target_folders[1], records_to_add=[record_uid])

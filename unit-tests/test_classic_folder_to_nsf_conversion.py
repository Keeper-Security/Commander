"""Tests for Classic folder subtree conversion planning."""

from contextlib import redirect_stdout
import io
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from keepercommander.commands.nested_share_folder.conversion_commands import (
    NestedShareConvertCommand,
    NestedShareFolderConvertCommand,
    _collect_classic_subtree,
    _folder_plan,
    _pam_record_details,
    _read_applications,
    _resolve_destination_folder,
    _scope_record_permissions,
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
)
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

    def test_shared_folder_acl_roles_do_not_treat_manage_records_as_record_edit(self):
        self.assertEqual(classic_record_permissions_to_nsf_role(), 'viewer')
        self.assertEqual(
            classic_record_permissions_to_nsf_role(manage_users=True), 'share-manager')
        self.assertEqual(
            classic_record_permissions_to_nsf_role(can_edit=True), 'content-manager')
        self.assertEqual(
            classic_record_permissions_to_nsf_role(can_share=True), 'share-manager')
        self.assertEqual(
            classic_record_permissions_to_nsf_role(can_edit=True, can_share=True),
            'content-share-manager')

    def test_shared_folder_record_permissions_use_the_most_restrictive_flags(self):
        scope_uid = _uid()
        first_uid, second_uid = _uid(), _uid()
        params = SimpleNamespace(shared_folder_cache={
            scope_uid: {
                'records': [
                    {'record_uid': first_uid, 'can_edit': True, 'can_share': True},
                    {'record_uid': second_uid, 'can_edit': False, 'can_share': True},
                ]
            }
        })

        permissions = _scope_record_permissions(params, scope_uid)
        self.assertFalse(permissions['can_edit'])
        self.assertTrue(permissions['can_share'])
        self.assertEqual(permissions['restricted_records'], [first_uid])
        accessors = _scope_accessors(
            SimpleNamespace(
                shared_folder_cache={
                    scope_uid: {
                        'users': [{
                            'username': 'records-manager@example.com',
                            'manage_users': False,
                            'manage_records': True,
                        }]
                    }
                },
                account_uid_bytes=None,
            ),
            scope_uid,
            permissions,
        )
        self.assertEqual(accessors[0]['role'], 'share-manager')

    def test_manage_records_does_not_grant_edit_when_classic_record_is_read_only(self):
        scope_uid = _uid()
        params = SimpleNamespace(
            shared_folder_cache={
                scope_uid: {
                    'users': [{
                        'username': 'records-manager@example.com',
                        'manage_users': False,
                        'manage_records': True,
                    }],
                    'records': [{
                        'record_uid': _uid(),
                        'can_edit': False,
                        'can_share': False,
                    }],
                }
            },
            account_uid_bytes=None,
        )

        accessors = _scope_accessors(params, scope_uid)

        self.assertEqual(accessors[0]['role'], 'viewer')


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
            NestedShareFolderConvertCommand._scope_grant_targets(
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
            NestedShareFolderConvertCommand._scope_grant_targets(
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

    def test_destination_access_is_fully_paginated_and_deduplicated(self):
        destination_uid, user_uid, team_uid = _uid(), _uid(), _uid()
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
            accessors = NestedShareFolderConvertCommand._destination_accessors(
                SimpleNamespace(), destination_uid)

        self.assertEqual(len(accessors), 2)
        self.assertEqual(
            [page.kwargs['continuation_token'] for page in get_access.call_args_list],
            [None, 17])

    def test_destination_access_preview_discloses_users_and_teams(self):
        folder_uid, destination_uid = _uid(), _uid()
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

    def test_folder_preview_explains_restricted_classic_permissions(self):
        folder_uid, scope_uid = _uid(), _uid()
        folder = UserFolderNode()
        folder.uid, folder.name = folder_uid, 'Shared'
        params = SimpleNamespace(nested_share_folders={})
        restricted_record_uid = _uid()
        output = io.StringIO()

        with redirect_stdout(output):
            NestedShareFolderConvertCommand._print_preview(
                params, {folder_uid: folder}, {folder_uid: []}, folder,
                None, 5, [], {folder_uid: 1}, {folder_uid: 1}, [],
                permission_warnings={
                    scope_uid: {
                        'restricted_records': [restricted_record_uid],
                        'unmapped_manage_records': ['member@example.com'],
                    }
                })

        rendered = output.getvalue()
        self.assertIn(restricted_record_uid, rendered)
        self.assertIn('most restrictive permissions', rendered)
        self.assertIn('member@example.com', rendered)
        self.assertIn('manage_records permissions cannot be mapped', rendered)


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
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 '_nsf.share_record_to_application_v3',
                 return_value={'success': True}) as share_record:
            failures = NestedShareFolderConvertCommand._grant_record_app_shares(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'user_choice', return_value='y'):
            retry_mapping = NestedShareFolderConvertCommand._select_retry_folders(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_nsf.create_folders_batch_v3', side_effect=create_batch), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 'user_choice', return_value='y'):
            target_uids = NestedShareFolderConvertCommand._create_target_tree(
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
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 'user_choice', return_value='y') as confirm, \
             redirect_stdout(io.StringIO()):
            mapping = NestedShareFolderConvertCommand._select_retry_folders(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'user_choice', return_value='n'), \
             redirect_stdout(io.StringIO()):
            mapping = NestedShareFolderConvertCommand._select_retry_folders(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'user_choice') as confirm, \
             redirect_stdout(io.StringIO()) as output:
            mapping = NestedShareFolderConvertCommand._select_retry_folders(
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
                        'keepercommander.commands.nested_share_folder.'
                        'conversion_commands._nsf.create_folders_batch_v3',
                        side_effect=create_batch):
                    NestedShareFolderConvertCommand._create_target_tree(
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
                'keepercommander.commands.nested_share_folder.'
                'conversion_commands._nsf.create_folders_batch_v3',
                side_effect=create_batch):
            NestedShareFolderConvertCommand._create_target_tree(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_nsf.create_folders_batch_v3',
                side_effect=create_batch):
            target_uids = NestedShareFolderConvertCommand._create_target_tree(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_record_type', return_value='login'):
            record_uids, placements, skipped = (
                NestedShareFolderConvertCommand._collect_records(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_record_type',
                side_effect=lambda _params, uid: types_by_uid[uid]):
            converted_uids, placements, skipped = (
                NestedShareFolderConvertCommand._collect_records(
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
            NestedShareFolderConvertCommand._print_uid_mapping(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_record_type',
                side_effect=lambda _params, uid: types_by_uid[uid]), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_record_type',
                return_value='pamUser'), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_read_applications', return_value={}), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 '_record_type', return_value=record_type), \
             patch.object(NestedShareFolderConvertCommand, '_print_preview'), \
             patch.object(
                 NestedShareFolderConvertCommand, '_create_target_tree',
                 side_effect=create_tree), \
             patch.object(
                 NestedShareFolderConvertCommand, '_convert_records',
                 side_effect=convert_records), \
             patch.object(
                 NestedShareFolderConvertCommand, '_create_additional_placements',
                 return_value=[]), \
             patch.object(
                 NestedShareFolderConvertCommand, '_grant_record_app_shares',
                 return_value=[]), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 'sync_down.sync_down'), \
             patch(
                 'keepercommander.commands.nested_share_folder.conversion_commands.'
                 'user_choice', return_value='y') as user_choice, \
             patch.object(
                 NestedShareFolderConvertCommand, '_delete_classic_source') as delete_source:
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
            NestedShareFolderConvertCommand._print_incomplete_conversion(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'sync_down.sync_down'), patch(remove_path) as remove:
            deleted = NestedShareFolderConvertCommand._delete_classic_source(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'sync_down.sync_down', side_effect=refresh), \
             patch(remove_path) as remove:
            deleted = NestedShareFolderConvertCommand._delete_classic_source(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                'sync_down.sync_down', side_effect=RuntimeError('sync failed')), \
             patch(remove_path) as remove:
            result = NestedShareFolderConvertCommand._delete_classic_source(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_nsf.manage_folder_records_batch_v3',
                return_value=[]):
            failures = NestedShareFolderConvertCommand._create_additional_placements(
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
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_nsf.manage_folder_records_batch_v3',
                return_value=[{'record_uid': record_uid, 'success': True}]) as add:
            failures = NestedShareFolderConvertCommand._create_additional_placements(
                params,
                {record_uid},
                {record_uid: source_folders},
                dict(zip(source_folders, target_folders)),
                include_primary_for={record_uid},
            )

        self.assertEqual(failures, [])
        add.assert_called_once_with(
            params, target_folders[1], records_to_add=[record_uid])

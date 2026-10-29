"""Tests for Classic folder subtree conversion planning."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from keepercommander.commands.nested_share_folder.conversion_commands import (
    NestedShareFolderConvertCommand,
    _collect_classic_subtree,
    _folder_plan,
    _read_applications,
    _scope_accessors,
)
from keepercommander.commands.ksm import KSMCommand
from keepercommander.error import CommandError
from keepercommander.nested_share_folder.permissions import classic_perms_to_nsf_role
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

    def test_shared_folder_acl_roles_follow_requested_mapping(self):
        self.assertEqual(classic_perms_to_nsf_role(False, False), 'viewer')
        self.assertEqual(classic_perms_to_nsf_role(True, False), 'share-manager')
        self.assertEqual(classic_perms_to_nsf_role(False, True), 'content-manager')
        self.assertEqual(classic_perms_to_nsf_role(True, True), 'content-share-manager')

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
                     force=False, converted=True):
        def create_tree(*args, **kwargs):
            params.nested_share_folders[target_uid] = {
                'name': 'Private',
                'parent_uid': '',
                'folder_key_unencrypted': utils.generate_aes_key(),
            }
            return {folder_uid: target_uid}

        def convert_records(_params, record_uids, _placements, _target_uids):
            if converted:
                params.nested_share_records[record_uid] = {}
                return set(record_uids)
            return set()

        with patch(
                'keepercommander.commands.nested_share_folder.conversion_commands.'
                '_read_applications', return_value={}), \
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

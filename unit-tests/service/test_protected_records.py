import json
import os
from unittest import TestCase, mock

from keepercommander import params as params_module, vault
from keepercommander.subfolder import RootFolderNode, SharedFolderNode
from keepercommander.utils import generate_uid
from keepercommander.service.util.protected_records import (
    _attachment_file_uids,
    _expand_with_attachment_uids,
    _has_reserved_attachment,
    get_protected_folder_uids,
    get_protected_record_title_set,
    get_protected_record_uids,
    hide_from_folder_cache,
    hide_from_record_cache,
    resolve_sync_down_exempt_uid,
)

PROTECTED_TITLE = 'Commander Service Mode Config'
PROTECTED_DOCKER_TITLE = 'Commander Service Mode Docker Config'


def _record_cache_entry(uid, title, version=2):
    return {
        'record_uid': uid,
        'version': version,
        'revision': 1,
        'client_modified_time': 0,
        'shared': False,
        'record_key_unencrypted': b'0' * 32,
        'data_unencrypted': json.dumps({'title': title}).encode('utf-8'),
    }


def _params_with_records(entries):
    p = params_module.KeeperParams()
    p.record_cache = {uid: _record_cache_entry(uid, title) for uid, title in entries.items()}
    return p


class TestGetProtectedRecordTitleSet(TestCase):
    def test_contains_expected_titles_lowercased(self):
        titles = get_protected_record_title_set()
        self.assertIn('commander service mode config', titles)
        self.assertIn('commander service mode docker config', titles)
        self.assertIn('commander service mode', titles)

    def test_contains_terraform_slack_teams_gchat_titles(self):
        titles = get_protected_record_title_set()
        self.assertIn('commander service mode terraform config', titles)
        self.assertIn('commander service mode slack app config', titles)
        self.assertIn('commander service mode teams app config', titles)
        self.assertIn('commander service mode google chat app config', titles)


class TestGetProtectedRecordUids(TestCase):
    def test_returns_only_matching_protected_records(self):
        p = _params_with_records({
            'UID_CONFIG': PROTECTED_TITLE,
            'UID_DOCKER': PROTECTED_DOCKER_TITLE,
            'UID_OTHER': 'My Normal Record',
        })
        result = get_protected_record_uids(p)
        self.assertEqual(set(result.keys()), {'UID_CONFIG', 'UID_DOCKER'})
        self.assertEqual(result['UID_CONFIG'], PROTECTED_TITLE)
        self.assertEqual(result['UID_DOCKER'], PROTECTED_DOCKER_TITLE)

    def test_no_protected_records_present(self):
        p = _params_with_records({'UID_OTHER': 'My Normal Record'})
        self.assertEqual(get_protected_record_uids(p), {})

    def test_empty_record_cache(self):
        p = params_module.KeeperParams()
        p.record_cache = {}
        self.assertEqual(get_protected_record_uids(p), {})

    def test_params_none(self):
        self.assertEqual(get_protected_record_uids(None), {})

    def test_record_cache_not_a_dict_is_ignored(self):
        """A Mock/non-dict record_cache (as some tests construct) must fail safe to {}."""
        class FakeParams:
            record_cache = object()

        self.assertEqual(get_protected_record_uids(FakeParams()), {})

    def test_similar_but_not_exact_title_is_not_matched(self):
        """A title that shares every token with a protected title but isn't an exact match must not be protected."""
        p = _params_with_records({'UID_OTHER': 'Commander Service Mode Config Backup'})
        self.assertEqual(get_protected_record_uids(p), {})

    def test_docker_record_protected_by_uid_even_with_custom_title(self):
        """--record-name can give the Docker config record a custom title; COMMANDER_RECORD must still identify it."""
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'COMMANDER_RECORD': uid}):
            p = _params_with_records({uid: 'My Totally Custom Docker Title'})
            result = get_protected_record_uids(p)
        self.assertIn(uid, result)

    def test_docker_env_uid_present_even_without_params(self):
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'COMMANDER_RECORD': uid}):
            self.assertIn(uid, get_protected_record_uids(None))

    def test_no_docker_env_var_falls_back_to_title_only(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE})
            result = get_protected_record_uids(p)
        self.assertEqual(set(result.keys()), {'UID_CONFIG'})

    def test_malformed_env_uid_falls_back_to_title_matching(self):
        """A misconfigured pinning env var (not a real record UID) must not become a phantom protected token."""
        with mock.patch.dict(os.environ, {'TERRAFORM_RECORD': '1'}):
            p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE})
            result = get_protected_record_uids(p)
        self.assertEqual(set(result.keys()), {'UID_CONFIG'})

    def test_terraform_record_protected_by_uid_even_with_custom_title(self):
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'TERRAFORM_RECORD': uid}):
            p = _params_with_records({uid: 'My Totally Custom Terraform Title'})
            self.assertIn(uid, get_protected_record_uids(p))

    def test_slack_record_protected_by_uid_even_with_custom_title(self):
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'SLACK_RECORD': uid}):
            p = _params_with_records({uid: 'My Totally Custom Slack Title'})
            self.assertIn(uid, get_protected_record_uids(p))

    def test_teams_record_protected_by_uid_even_with_custom_title(self):
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'TEAMS_RECORD': uid}):
            p = _params_with_records({uid: 'My Totally Custom Teams Title'})
            self.assertIn(uid, get_protected_record_uids(p))

    def test_gchat_record_protected_by_uid_even_with_custom_title(self):
        uid = generate_uid()
        with mock.patch.dict(os.environ, {'GCHAT_RECORD': uid}):
            p = _params_with_records({uid: 'My Totally Custom GChat Title'})
            self.assertIn(uid, get_protected_record_uids(p))

    def test_no_pinned_env_vars_falls_back_to_title_only(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE})
            result = get_protected_record_uids(p)
        self.assertEqual(set(result.keys()), {'UID_CONFIG'})

    def test_malformed_record_entry_is_skipped_not_raised(self):
        """A record missing an expected key must not break the scan for every other record."""
        p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE})
        p.record_cache['MALFORMED_UID'] = {
            'record_uid': 'MALFORMED_UID', 'version': 2, 'revision': 1,
            'data_unencrypted': json.dumps({'title': 'whatever'}).encode('utf-8'),
            # record_key_unencrypted deliberately missing.
        }
        result = get_protected_record_uids(p)
        self.assertEqual(set(result.keys()), {'UID_CONFIG'})


class TestGetProtectedRecordUidsNotCached(TestCase):
    """Not memoized -- a newly added protected record must be picked up immediately, without needing a revision change."""

    def test_newly_added_record_is_found_without_a_revision_change(self):
        p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE})
        p.revision = 100
        first = get_protected_record_uids(p)
        self.assertEqual(set(first.keys()), {'UID_CONFIG'})

        p.record_cache['UID_DOCKER'] = _record_cache_entry('UID_DOCKER', PROTECTED_DOCKER_TITLE)
        second = get_protected_record_uids(p)
        self.assertEqual(set(second.keys()), {'UID_CONFIG', 'UID_DOCKER'})

    def test_removed_record_is_no_longer_found(self):
        p = _params_with_records({'UID_CONFIG': PROTECTED_TITLE, 'UID_DOCKER': PROTECTED_DOCKER_TITLE})
        p.revision = 100
        first = get_protected_record_uids(p)
        self.assertEqual(set(first.keys()), {'UID_CONFIG', 'UID_DOCKER'})

        del p.record_cache['UID_DOCKER']
        second = get_protected_record_uids(p)
        self.assertEqual(set(second.keys()), {'UID_CONFIG'})


class TestHideFromRecordCache(TestCase):
    def test_hides_protected_uid_inside_the_block(self):
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE, 'NORMAL': 'Other'})
        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            self.assertNotIn('PROTECTED', p.record_cache)
            self.assertIn('NORMAL', p.record_cache)

    def test_restores_original_entry_and_plain_dict_after_block(self):
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE, 'NORMAL': 'Other'})
        original_entry = p.record_cache['PROTECTED']
        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            pass
        self.assertIs(type(p.record_cache), dict)
        self.assertEqual(p.record_cache['PROTECTED'], original_entry)

    def test_restores_even_if_block_raises(self):
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE})
        with self.assertRaises(ValueError):
            with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
                raise ValueError('boom')
        self.assertIs(type(p.record_cache), dict)
        self.assertIn('PROTECTED', p.record_cache)

    def test_reintroduction_during_block_is_blocked(self):
        """A forced sync-down writing the protected UID back into record_cache mid-command must not make it visible."""
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE, 'NORMAL': 'Other'})
        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            p.record_cache['PROTECTED'] = _record_cache_entry('PROTECTED', 'reintroduced')
            self.assertNotIn('PROTECTED', p.record_cache)

            p.record_cache.update({'PROTECTED': _record_cache_entry('PROTECTED', 'via-update'),
                                    'NEW': _record_cache_entry('NEW', 'legit new record')})
            self.assertNotIn('PROTECTED', p.record_cache)
            self.assertIn('NEW', p.record_cache)

        # Legit mutations made during the block survive; the protected entry is restored.
        self.assertIn('NEW', p.record_cache)
        self.assertIn('PROTECTED', p.record_cache)

    def test_no_protected_uids_is_a_noop(self):
        p = _params_with_records({'NORMAL': 'Other'})
        with hide_from_record_cache(p, {}):
            self.assertIn('NORMAL', p.record_cache)

    def test_params_none_is_a_noop(self):
        with hide_from_record_cache(None, {'PROTECTED': PROTECTED_TITLE}):
            pass

    def test_nested_share_caches_are_guarded_too(self):
        """load_pam_record falls back to nested_share_records, so guarding record_cache alone isn't enough."""
        p = _params_with_records({'NORMAL': 'Other'})
        p.nested_share_records = {'PROTECTED': {'title': 'nsf copy'}, 'OTHER_NSF': {'title': 'x'}}
        p.nested_share_record_data = {'PROTECTED': {'data_json': {'title': 'nsf data copy'}}}

        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            self.assertNotIn('PROTECTED', p.nested_share_records)
            self.assertIn('OTHER_NSF', p.nested_share_records)
            self.assertNotIn('PROTECTED', p.nested_share_record_data)

            # Reintroduction mid-command must be blocked here too.
            p.nested_share_records['PROTECTED'] = {'title': 'reintroduced'}
            self.assertNotIn('PROTECTED', p.nested_share_records)

        self.assertIn('PROTECTED', p.nested_share_records)
        self.assertIn('PROTECTED', p.nested_share_record_data)
        self.assertIs(type(p.nested_share_records), dict)

    def test_subfolder_record_cache_uid_is_stripped_for_the_duration(self):
        """_build_folder_json leaks the bare UID from a folder's set even when the record fails to load."""
        p = _params_with_records({'NORMAL': 'Other'})
        p.subfolder_record_cache = {'FOLDER1': {'PROTECTED', 'NORMAL'}, 'FOLDER2': {'OTHER'}}

        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            self.assertNotIn('PROTECTED', p.subfolder_record_cache['FOLDER1'])
            self.assertIn('NORMAL', p.subfolder_record_cache['FOLDER1'])
            self.assertEqual(p.subfolder_record_cache['FOLDER2'], {'OTHER'})

        self.assertIn('PROTECTED', p.subfolder_record_cache['FOLDER1'])
        self.assertIn('NORMAL', p.subfolder_record_cache['FOLDER1'])

    def test_missing_optional_caches_do_not_raise(self):
        """A params fixture with only default-empty NSF/subfolder caches must not break the guard."""
        p = _params_with_records({'NORMAL': 'Other'})
        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            pass

    def test_attribute_replaced_with_none_mid_command_does_not_mask_the_original_error(self):
        """A command that clears/replaces a guarded attribute mid-execution must not
        turn a real error into a confusing 'NoneType is not iterable' one, and the
        protected entry must still be restored on a best-effort basis."""
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE})
        with self.assertRaises(ValueError) as ctx:
            with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
                p.record_cache = None
                raise ValueError('original command error')
        self.assertEqual(str(ctx.exception), 'original command error')
        self.assertIn('PROTECTED', p.record_cache)

    def test_attribute_replaced_with_plain_dict_preserves_its_contents(self):
        """A command that replaces the guarded attribute with a fresh plain dict
        (not just mutating the guarded one) must not lose that dict's entries."""
        p = _params_with_records({'PROTECTED': PROTECTED_TITLE, 'NORMAL': 'Other'})
        with hide_from_record_cache(p, {'PROTECTED': PROTECTED_TITLE}):
            p.record_cache = {'REPLACED': _record_cache_entry('REPLACED', 'from a full reassignment')}

        self.assertIn('REPLACED', p.record_cache)
        self.assertIn('PROTECTED', p.record_cache)


class TestResolveSyncDownExemptUid(TestCase):
    def test_returns_env_uid_for_slack_sync_down(self):
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'SLACK_UID'}, clear=True):
            self.assertEqual(
                resolve_sync_down_exempt_uid(['slack-app-setup', '--sync-down']), 'SLACK_UID'
            )

    def test_returns_env_uid_regardless_of_explicit_dash_r_value(self):
        """Never derived from the admin's own -r value -- always the env-pinned UID."""
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'SLACK_UID'}, clear=True):
            self.assertEqual(
                resolve_sync_down_exempt_uid(['slack-app-setup', '--sync-down', '-r', 'SOME_OTHER_UID']),
                'SLACK_UID',
            )

    def test_none_without_sync_down_token(self):
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'SLACK_UID'}, clear=True):
            self.assertIsNone(resolve_sync_down_exempt_uid(['slack-app-setup']))

    def test_none_for_unrelated_command(self):
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'SLACK_UID'}, clear=True):
            self.assertIsNone(resolve_sync_down_exempt_uid(['get', '--sync-down']))

    def test_none_when_env_var_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(resolve_sync_down_exempt_uid(['slack-app-setup', '--sync-down']))

    def test_gchat_uses_its_own_env_var(self):
        with mock.patch.dict(os.environ, {'GCHAT_RECORD': 'G_UID'}, clear=True):
            self.assertEqual(resolve_sync_down_exempt_uid(['gchat-app-setup', '--sync-down']), 'G_UID')

    def test_teams_has_no_sync_down_exemption_yet(self):
        """Teams has no approvals profile yet, so --sync-down isn't even a registered flag for it;
        this must stay None rather than exempting a UID for a flow that can't actually run."""
        with mock.patch.dict(os.environ, {'TEAMS_RECORD': 'T_UID'}, clear=True):
            self.assertIsNone(resolve_sync_down_exempt_uid(['teams-app-setup', '--sync-down']))

    def test_empty_tokens_returns_none(self):
        self.assertIsNone(resolve_sync_down_exempt_uid([]))

    def test_abbreviated_flag_does_not_grant_the_exemption(self):
        """Exact match only -- granting an exemption is the permissive direction, so an
        abbreviation like '--s' (ambiguous with --skip-device-setup on the real parser
        anyway) must not be treated as --sync-down."""
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'SLACK_UID'}, clear=True):
            self.assertIsNone(resolve_sync_down_exempt_uid(['slack-app-setup', '--s']))
            self.assertIsNone(resolve_sync_down_exempt_uid(['slack-app-setup', '--sync']))


def _folder_node(uid, name, parent_uid=None):
    node = SharedFolderNode()
    node.uid = uid
    node.parent_uid = parent_uid
    node.name = name
    return node


def _params_with_folder(folder_uid='FOLDER1', record_uid='PROTECTED', parent_uid=None):
    p = params_module.KeeperParams()
    p.root_folder = RootFolderNode()
    node = _folder_node(folder_uid, 'Commander Service Mode - Docker', parent_uid)
    p.folder_cache = {folder_uid: node}
    parent_list = p.root_folder.subfolders if not parent_uid else None
    if parent_list is not None:
        parent_list.append(folder_uid)
    p.shared_folder_cache = {folder_uid: {'name_unencrypted': node.name}}
    p.subfolder_cache = {folder_uid: {'type': 'shared_folder', 'shared_folder_uid': folder_uid}}
    p.subfolder_record_cache = {folder_uid: {record_uid}, 'OTHER_FOLDER': {'OTHER_RECORD'}}
    return p


class TestGetProtectedFolderUids(TestCase):
    def test_returns_folder_containing_a_protected_record(self):
        p = _params_with_folder(folder_uid='FOLDER1', record_uid='PROTECTED')
        result = get_protected_folder_uids(p, {'PROTECTED': 'Commander Service Mode Docker Config'})
        self.assertEqual(result, {'FOLDER1'})

    def test_no_protected_records_present(self):
        p = _params_with_folder(folder_uid='FOLDER1', record_uid='PROTECTED')
        self.assertEqual(get_protected_folder_uids(p, {'UNRELATED': 'x'}), set())

    def test_empty_protected_record_uids_is_a_noop(self):
        p = _params_with_folder()
        self.assertEqual(get_protected_folder_uids(p, {}), set())

    def test_params_none(self):
        self.assertEqual(get_protected_folder_uids(None, {'PROTECTED': 'x'}), set())

    def test_missing_subfolder_record_cache_is_ignored(self):
        p = params_module.KeeperParams()
        self.assertEqual(get_protected_folder_uids(p, {'PROTECTED': 'x'}), set())

    def test_renamed_folder_is_still_found(self):
        """Derived from record containment, not a title list -- a rename doesn't lose protection."""
        p = _params_with_folder(folder_uid='FOLDER1', record_uid='PROTECTED')
        p.folder_cache['FOLDER1'].name = 'My Totally Renamed Folder'
        p.shared_folder_cache['FOLDER1']['name_unencrypted'] = 'My Totally Renamed Folder'
        result = get_protected_folder_uids(p, {'PROTECTED': 'Commander Service Mode Docker Config'})
        self.assertEqual(result, {'FOLDER1'})


class TestHideFromFolderCache(TestCase):
    def test_hides_protected_folder_from_all_three_caches_inside_the_block(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            self.assertNotIn('FOLDER1', p.folder_cache)
            self.assertNotIn('FOLDER1', p.shared_folder_cache)
            self.assertNotIn('FOLDER1', p.subfolder_cache)

    def test_strips_uid_from_root_folder_subfolders_during_the_block(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            self.assertNotIn('FOLDER1', p.root_folder.subfolders)

    def test_strips_uid_from_parent_folders_subfolders_when_nested(self):
        p = _params_with_folder(folder_uid='FOLDER1', parent_uid='PARENT')
        parent = _folder_node('PARENT', 'Some Parent Folder')
        p.folder_cache['PARENT'] = parent
        parent.subfolders.append('FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            self.assertNotIn('FOLDER1', parent.subfolders)
        self.assertIn('FOLDER1', parent.subfolders)

    def test_restores_everything_after_the_block(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            pass
        self.assertIn('FOLDER1', p.folder_cache)
        self.assertIn('FOLDER1', p.shared_folder_cache)
        self.assertIn('FOLDER1', p.subfolder_cache)
        self.assertIn('FOLDER1', p.root_folder.subfolders)

    def test_restores_even_if_block_raises(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with self.assertRaises(ValueError):
            with hide_from_folder_cache(p, {'FOLDER1'}):
                raise ValueError('boom')
        self.assertIn('FOLDER1', p.folder_cache)
        self.assertIn('FOLDER1', p.root_folder.subfolders)

    def test_reintroduction_during_block_is_blocked(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            p.folder_cache['FOLDER1'] = _folder_node('FOLDER1', 'reintroduced')
            self.assertNotIn('FOLDER1', p.folder_cache)
        self.assertIn('FOLDER1', p.folder_cache)

    def test_no_protected_folders_is_a_noop(self):
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, set()):
            self.assertIn('FOLDER1', p.folder_cache)

    def test_params_none_is_a_noop(self):
        with hide_from_folder_cache(None, {'FOLDER1'}):
            pass

    def test_missing_root_folder_does_not_raise(self):
        """A params fixture with no root_folder set (e.g. never synced) must not crash the guard."""
        p = _params_with_folder(folder_uid='FOLDER1')
        p.root_folder = None
        with hide_from_folder_cache(p, {'FOLDER1'}):
            self.assertNotIn('FOLDER1', p.folder_cache)

    def test_a_resync_mid_block_self_heals_without_reintroducing_the_folder(self):
        """A forced resync mid-command rebuilds folder_cache/root_folder from the (still-guarded)
        raw subfolder_cache/shared_folder_cache, so the protected folder must not reappear."""
        p = _params_with_folder(folder_uid='FOLDER1')
        with hide_from_folder_cache(p, {'FOLDER1'}):
            from keepercommander.sync_down import prepare_folder_tree
            prepare_folder_tree(p)
            self.assertNotIn('FOLDER1', p.folder_cache)
            self.assertNotIn('FOLDER1', p.root_folder.subfolders)


class TestHasReservedAttachment(TestCase):
    def test_password_record_with_reserved_attachment_name(self):
        record = vault.PasswordRecord()
        record.attachments = [vault.AttachmentFile({'name': 'config.json', 'title': 'config.json'})]
        self.assertTrue(_has_reserved_attachment(None, record))

    def test_password_record_with_reserved_title_but_different_name(self):
        """attachment.py itself checks title OR name -- match either."""
        record = vault.PasswordRecord()
        record.attachments = [vault.AttachmentFile({'name': 'file123', 'title': 'service_config.json'})]
        self.assertTrue(_has_reserved_attachment(None, record))

    def test_password_record_with_unrelated_attachment(self):
        record = vault.PasswordRecord()
        record.attachments = [vault.AttachmentFile({'name': 'notes.pdf', 'title': 'notes.pdf'})]
        self.assertFalse(_has_reserved_attachment(None, record))

    def test_password_record_with_no_attachments(self):
        record = vault.PasswordRecord()
        self.assertFalse(_has_reserved_attachment(None, record))

    def test_typed_record_with_reserved_file_ref(self):
        record = vault.TypedRecord()
        record.fields = [vault.TypedField({'type': 'fileRef', 'value': ['FILE_UID_1']})]
        file_record = vault.FileRecord()
        file_record.title = 'config.json'
        file_record.name = 'config.json'
        with mock.patch('keepercommander.vault.KeeperRecord.load', return_value=file_record):
            self.assertTrue(_has_reserved_attachment(object(), record))

    def test_typed_record_with_unrelated_file_ref(self):
        record = vault.TypedRecord()
        record.fields = [vault.TypedField({'type': 'fileRef', 'value': ['FILE_UID_1']})]
        file_record = vault.FileRecord()
        file_record.title = 'notes.pdf'
        file_record.name = 'notes.pdf'
        with mock.patch('keepercommander.vault.KeeperRecord.load', return_value=file_record):
            self.assertFalse(_has_reserved_attachment(object(), record))

    def test_typed_record_with_no_file_ref(self):
        record = vault.TypedRecord()
        self.assertFalse(_has_reserved_attachment(object(), record))

    def test_neither_password_nor_typed_record(self):
        record = vault.FileRecord()
        self.assertFalse(_has_reserved_attachment(None, record))


class TestGetProtectedRecordUidsWithReservedAttachments(TestCase):
    def test_arbitrary_titled_record_with_reserved_attachment_is_protected(self):
        """A record with none of the known titles is still protected if it carries
        one of Commander's own reserved config-file attachments."""
        p = _params_with_records({'UID_ARBITRARY': 'My Totally Unrelated Title'})
        with mock.patch(
            'keepercommander.service.util.protected_records._has_reserved_attachment',
            side_effect=lambda params, record: record.record_uid == 'UID_ARBITRARY',
        ):
            result = get_protected_record_uids(p)
        self.assertIn('UID_ARBITRARY', result)

    def test_arbitrary_titled_record_without_reserved_attachment_is_not_protected(self):
        p = _params_with_records({'UID_ARBITRARY': 'My Totally Unrelated Title'})
        with mock.patch(
            'keepercommander.service.util.protected_records._has_reserved_attachment',
            return_value=False,
        ):
            result = get_protected_record_uids(p)
        self.assertEqual(result, {})


class TestExpandWithAttachmentUids(TestCase):
    """Regression test for a live gap: get 'service_config.json' returned the attachment's own
    FileRecord (a separate record_cache entry, its own UID) directly, since only the parent
    record was ever added to protected_uids -- the attachment's own UID was never blocked."""

    def test_typed_record_file_ref_uid_is_protected(self):
        parent = vault.TypedRecord()
        parent.record_uid = 'PARENT_UID'
        parent.fields = [vault.TypedField({'type': 'fileRef', 'value': ['FILE_UID_1']})]
        found = {'PARENT_UID': 'Commander Service Mode Slack App Config'}

        p = _params_with_records({'PARENT_UID': 'x', 'FILE_UID_1': 'y'})
        with mock.patch('keepercommander.vault.KeeperRecord.load', return_value=parent):
            _expand_with_attachment_uids(p, found)
        self.assertIn('FILE_UID_1', found)

    def test_legacy_password_record_attachment_id_is_protected(self):
        parent = vault.PasswordRecord()
        parent.record_uid = 'PARENT_UID'
        parent.attachments = [vault.AttachmentFile({'id': 'ATTA_ID_1', 'name': 'config.json'})]
        found = {'PARENT_UID': 'Commander Service Mode Docker Config'}

        p = _params_with_records({'PARENT_UID': 'x'})
        with mock.patch('keepercommander.vault.KeeperRecord.load', return_value=parent):
            _expand_with_attachment_uids(p, found)
        self.assertIn('ATTA_ID_1', found)

    def test_noop_without_record_cache(self):
        found = {'PARENT_UID': 'x'}
        _expand_with_attachment_uids(params_module.KeeperParams(), found)
        self.assertEqual(found, {'PARENT_UID': 'x'})

    def test_noop_when_protected_uid_is_not_loadable(self):
        found = {'PARENT_UID': 'x'}
        p = _params_with_records({'PARENT_UID': 'x'})
        with mock.patch('keepercommander.vault.KeeperRecord.load', return_value=None):
            _expand_with_attachment_uids(p, found)
        self.assertEqual(found, {'PARENT_UID': 'x'})

    def test_end_to_end_arbitrary_titled_parent_with_attachment_protects_the_file_uid(self):
        """Reproduces the exact reported scenario: a record with a normal title carrying a
        service_config.json fileRef attachment -- both the parent and the attachment's own
        FileRecord UID must come back protected."""
        parent = vault.TypedRecord()
        parent.record_uid = 'PARENT_UID'
        parent.title = 'My Totally Unrelated Title'
        parent.fields = [vault.TypedField({'type': 'fileRef', 'value': ['FILE_UID_1']})]

        file_record = vault.FileRecord()
        file_record.record_uid = 'FILE_UID_1'
        file_record.title = 'service_config.json'
        file_record.name = 'service_config.json'

        records = {'PARENT_UID': parent, 'FILE_UID_1': file_record}
        p = _params_with_records({'PARENT_UID': 'x', 'FILE_UID_1': 'y'})
        with mock.patch('keepercommander.vault.KeeperRecord.load', side_effect=lambda params, uid: records.get(uid)):
            result = get_protected_record_uids(p)
        self.assertIn('PARENT_UID', result)
        self.assertIn('FILE_UID_1', result)


class TestAttachmentFileUids(TestCase):
    def test_password_record_returns_attachment_ids(self):
        record = vault.PasswordRecord()
        record.attachments = [
            vault.AttachmentFile({'id': 'A1', 'name': 'x'}),
            vault.AttachmentFile({'id': 'A2', 'name': 'y'}),
        ]
        self.assertEqual(set(_attachment_file_uids(record)), {'A1', 'A2'})

    def test_typed_record_returns_file_ref_values(self):
        record = vault.TypedRecord()
        record.fields = [vault.TypedField({'type': 'fileRef', 'value': ['F1', 'F2']})]
        self.assertEqual(set(_attachment_file_uids(record)), {'F1', 'F2'})

    def test_record_with_no_attachments_returns_empty(self):
        self.assertEqual(_attachment_file_uids(vault.PasswordRecord()), [])
        self.assertEqual(_attachment_file_uids(vault.TypedRecord()), [])

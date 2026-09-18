import json
import os
from unittest import TestCase, mock

from keepercommander import params as params_module
from keepercommander.service.util.protected_records import (
    get_protected_record_title_set,
    get_protected_record_uids,
    hide_from_record_cache,
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
        with mock.patch.dict(os.environ, {'COMMANDER_RECORD': 'DOCKER_CUSTOM_UID'}):
            p = _params_with_records({'DOCKER_CUSTOM_UID': 'My Totally Custom Docker Title'})
            result = get_protected_record_uids(p)
        self.assertIn('DOCKER_CUSTOM_UID', result)

    def test_docker_env_uid_present_even_without_params(self):
        with mock.patch.dict(os.environ, {'COMMANDER_RECORD': 'DOCKER_CUSTOM_UID'}):
            self.assertIn('DOCKER_CUSTOM_UID', get_protected_record_uids(None))

    def test_no_docker_env_var_falls_back_to_title_only(self):
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

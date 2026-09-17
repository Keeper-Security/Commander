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
        """--record-name can give the Docker config record any title at setup time;
        COMMANDER_RECORD is the only reliable way to identify it in that case."""
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
        """A forced sync-down (or anything else) writing the protected UID back into
        record_cache mid-command must not make it visible before the block exits."""
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

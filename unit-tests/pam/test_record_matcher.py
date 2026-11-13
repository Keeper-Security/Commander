#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import time
import unittest

from keepercommander.commands.pam_import.record_matcher import (
    CODE_AMBIGUOUS, CODE_FOLDER_MISSING, CODE_FOLDER_UNRESOLVED, CODE_IN_OTHER_FOLDER, CODE_NO_PERMISSION,
    CODE_OTHER_CONFIG, CODE_OUTSIDE_SCOPE, CODE_TYPE_MISMATCH, CODE_UID_NOT_FOUND, MODE_EXTEND, MODE_UPDATE,
    STATUS_ERROR, STATUS_EXISTING, STATUS_MISSING, STATUS_NEW, MatchRecord, RecordIndex, match_record,
)

UID_A = 'A' * 22
UID_B = 'B' * 22
UID_C = 'C' * 22


def _index(*records):
    return RecordIndex(records)


class TestRecordIndex(unittest.TestCase):

    def test_same_record_in_two_folders_is_one_record(self):
        index = _index(MatchRecord(UID_A, 'web', folder_uids=('f1',)),
                       MatchRecord(UID_A, 'web', folder_uids=('f2',)))
        self.assertEqual(len(index), 1)
        self.assertEqual(index.get(UID_A).folder_uids, ('f1', 'f2'))
        self.assertEqual(len(index.by_title('web')), 1)
        self.assertEqual(len(index.in_folder('f1', 'web')), 1)
        self.assertEqual(len(index.in_folder('f2', 'web')), 1)

    def test_shared_is_true_when_any_copy_is_shared(self):
        index = _index(MatchRecord(UID_A, 'web', shared=False), MatchRecord(UID_A, 'web', shared=True))
        self.assertTrue(index.get(UID_A).shared)

    def test_titles_are_matched_trimmed(self):
        index = _index(MatchRecord(UID_A, '  web  '))
        self.assertEqual(len(index.by_title('web ')), 1)


class TestMatchExtendMode(unittest.TestCase):
    """The rules `pam project extend` always had (characterization)."""

    def _match(self, index, **kw):
        kw.setdefault('ident', '"x"')
        return match_record(index, mode=MODE_EXTEND, **kw)

    def test_uid_in_scope_is_existing(self):
        r = self._match(_index(MatchRecord(UID_A, 'web')), uid_imported=UID_A)
        self.assertEqual((r.status, r.uid), (STATUS_EXISTING, UID_A))

    def test_uid_not_in_scope_is_error_with_legacy_text(self):
        r = self._match(_index(), uid_imported=UID_A, ident='"web"', machine_suffix=' user on machine "m"')
        self.assertEqual(r.status, STATUS_ERROR)
        self.assertEqual(r.code, CODE_UID_NOT_FOUND)
        self.assertEqual(r.message, f'uid "{UID_A}" not found in KSM app for record "web" user on machine "m"')

    def test_unshared_record_still_counts_as_existing_in_extend(self):
        # extend must never create a duplicate of a record that sits in an unshared child folder
        r = self._match(_index(MatchRecord(UID_A, 'web', folder_uids=('f1',), shared=False)), title='web')
        self.assertEqual((r.status, r.uid), (STATUS_EXISTING, UID_A))

    def test_title_only_unique_ambiguous_and_new(self):
        index = _index(MatchRecord(UID_A, 'web'), MatchRecord(UID_B, 'db'), MatchRecord(UID_C, 'db'))
        self.assertEqual(self._match(index, title='web').uid, UID_A)
        self.assertEqual(self._match(index, title='none').status, STATUS_NEW)
        r = self._match(index, title='db', ident='"db"')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_AMBIGUOUS))
        self.assertEqual(r.message, 'Multiple matches for record "db"; add folder_path to disambiguate')

    def test_same_record_reachable_twice_is_not_ambiguous(self):
        # regression: extend used to report "Multiple matches" for a record found through two folders
        index = _index(MatchRecord(UID_A, 'web', folder_uids=('f1',)),
                       MatchRecord(UID_A, 'web', folder_uids=('f2',)))
        r = self._match(index, title='web')
        self.assertEqual((r.status, r.uid), (STATUS_EXISTING, UID_A))

    def test_no_title_and_no_login_is_new(self):
        self.assertEqual(self._match(_index(MatchRecord(UID_A, '')), title='', login='').status, STATUS_NEW)

    def test_folder_path_unresolved_new_and_known(self):
        index = _index(MatchRecord(UID_A, 'web', folder_uids=('f1',)))
        r = self._match(index, folder_path='sf/x', folder_uid='', title='web', ident='"web"')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_FOLDER_UNRESOLVED))
        self.assertEqual(r.message, 'folder_path "sf/x" could not be resolved for record "web"')
        self.assertEqual(self._match(index, folder_path='sf/x', folder_uid='', folder_path_is_new=True,
                                     title='web').status, STATUS_NEW)
        self.assertEqual(self._match(index, folder_path='sf', folder_uid='f1', title='web').uid, UID_A)
        self.assertEqual(self._match(index, folder_path='sf', folder_uid='f2', title='web').status, STATUS_NEW)

    def test_folder_path_ambiguous_text(self):
        index = _index(MatchRecord(UID_A, 'db', folder_uids=('f1',)), MatchRecord(UID_B, 'db', folder_uids=('f1',)))
        r = self._match(index, folder_path='sf', folder_uid='f1', title='db', ident='"db"')
        self.assertEqual(r.message,
                         'Multiple matches for record "db" in folder "sf"; add folder_path to disambiguate')


class TestMatchUpdateMode(unittest.TestCase):

    def _match(self, index, **kw):
        kw.setdefault('ident', '"x"')
        return match_record(index, mode=MODE_UPDATE, **kw)

    def test_not_found_is_missing_not_new(self):
        r = self._match(_index(), title='web')
        self.assertEqual(r.status, STATUS_MISSING)

    def test_uid_not_found_anywhere_is_missing(self):
        r = self._match(_index(), uid_imported=UID_A, vault_has_uid=lambda uid: False)
        self.assertEqual((r.status, r.code), (STATUS_MISSING, CODE_UID_NOT_FOUND))

    def test_uid_in_vault_but_outside_the_index_is_outside_scope(self):
        r = self._match(_index(), uid_imported=UID_A, vault_has_uid=lambda uid: uid == UID_A,
                        describe_location=lambda uid: 'folder "A/B/C" (closest shared folder on the path: "B")')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_OUTSIDE_SCOPE))
        self.assertIn('exists in folder "A/B/C" (closest shared folder on the path: "B")', r.message)
        self.assertIn('Share the folder to the app; update does not change shares.', r.message)

    def test_record_in_unshared_folder_is_outside_scope_by_title_and_uid(self):
        index = _index(MatchRecord(UID_A, 'web', folder_uids=('g1',), shared=False))
        loc = lambda uid: f'folder "{uid}"'  # noqa: E731
        by_title = self._match(index, title='web', describe_location=loc)
        by_uid = self._match(index, uid_imported=UID_A, describe_location=loc)
        by_folder = self._match(index, folder_path='sf/c/g1', folder_uid='g1', title='web', describe_location=loc)
        for r in (by_title, by_uid, by_folder):
            self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_OUTSIDE_SCOPE))

    def test_shared_record_is_existing_and_a_hidden_twin_is_ignored(self):
        index = _index(MatchRecord(UID_A, 'web', shared=True), MatchRecord(UID_B, 'web', shared=False))
        r = self._match(index, title='web')
        self.assertEqual((r.status, r.uid), (STATUS_EXISTING, UID_A))

    def test_folder_path_missing_is_an_error_not_new(self):
        r = self._match(_index(), folder_path='sf/x', folder_uid='', folder_path_is_new=True, title='web')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_FOLDER_MISSING))
        self.assertIn('update never creates folders', r.message)

    def test_title_in_another_folder_is_an_error(self):
        index = _index(MatchRecord(UID_A, 'web', folder_uids=('f1',)))
        r = self._match(index, folder_path='sf/other', folder_uid='f2', title='web',
                        folder_label=lambda uid: 'sf/one')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_IN_OTHER_FOLDER))
        self.assertIn('found in folder "sf/one", the JSON says "sf/other"', r.message)
        self.assertIn('update never moves records', r.message)

    def test_type_mismatch(self):
        index = _index(MatchRecord(UID_A, 'web', record_type='pamMachine'))
        r = self._match(index, title='web', expected_type='pamDatabase')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_TYPE_MISMATCH))
        self.assertEqual(self._match(index, title='web', expected_type='PAMMACHINE').status, STATUS_EXISTING)

    def test_other_configuration(self):
        index = _index(MatchRecord(UID_A, 'web'))
        r = self._match(index, title='web', config_uid='CFG1', config_of=lambda uid: 'CFG2')
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_OTHER_CONFIG))
        # unknown configuration (not linked yet) stays matchable
        self.assertEqual(self._match(index, title='web', config_uid='CFG1', config_of=lambda uid: None).status,
                         STATUS_EXISTING)
        self.assertEqual(self._match(index, title='web', config_uid='CFG1', config_of=lambda uid: 'CFG1').status,
                         STATUS_EXISTING)

    def test_write_permission_false_is_an_error_unknown_is_allowed(self):
        index = _index(MatchRecord(UID_A, 'web'))
        r = self._match(index, title='web', can_write=lambda uid: False)
        self.assertEqual((r.status, r.code), (STATUS_ERROR, CODE_NO_PERMISSION))
        self.assertEqual(self._match(index, title='web', can_write=lambda uid: None).status, STATUS_EXISTING)
        self.assertEqual(self._match(index, title='web', can_write=lambda uid: True).status, STATUS_EXISTING)

    def test_hooks_are_not_used_in_extend_mode(self):
        index = _index(MatchRecord(UID_A, 'web', record_type='pamMachine'))
        r = match_record(index, ident='"x"', title='web', mode=MODE_EXTEND, expected_type='pamDatabase',
                         config_uid='CFG1', config_of=lambda uid: 'CFG2', can_write=lambda uid: False)
        self.assertEqual(r.status, STATUS_EXISTING)


class TestMatcherCost(unittest.TestCase):

    def test_matching_is_linear(self):
        # 20,000 records x 20,000 JSON items: a scan per item would be 4x10^8 steps (minutes)
        n = 20000
        index = RecordIndex(MatchRecord(f'U{i:021d}', f'rec-{i}', folder_uids=('f1',)) for i in range(n))
        started = time.time()
        for i in range(n):
            r = match_record(index, ident='"x"', title=f'rec-{i}', mode=MODE_EXTEND)
            self.assertEqual(r.status, STATUS_EXISTING)
            r = match_record(index, ident='"x"', title=f'rec-{i}', folder_path='sf', folder_uid='f1',
                             mode=MODE_EXTEND)
            self.assertEqual(r.status, STATUS_EXISTING)
        self.assertLess(time.time() - started, 10)


if __name__ == '__main__':
    unittest.main()

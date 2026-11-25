"""Write permission of a Nested Share Folder record for `pam project update` (`nsf_record_can_edit`, `update._can_write`).

Sync stores the current user's access rows in ``params.nested_share_record_accesses``; the plan must refuse a record the
user cannot edit (a viewer) and must not refuse on missing or unmatched data (the server decides then).
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from keepercommander import utils
from keepercommander.commands.pam_import import nsf_helpers as nh
from keepercommander.commands.pam_import import update as up

ME = 'me@example.com'
ME_UID_BYTES = b'm' * 16
ME_UID = utils.base64_url_encode(ME_UID_BYTES)


def row(**kw):
    base = {'record_uid': 'R', 'username': ME, 'owner': False, 'can_edit': False, 'denied_access': False,
            'inherited': False}
    base.update(kw)
    return base


def params(nsf=('R',), rows=None, classic=None):
    return SimpleNamespace(user=ME, account_uid_bytes=ME_UID_BYTES,
                           nested_share_records={uid: {'revision': 1} for uid in nsf},
                           nested_share_record_accesses=rows or {}, record_cache=classic or {})


class TestNsfRecordCanEdit(unittest.TestCase):
    def test_not_an_nsf_record_is_unknown(self):
        self.assertIsNone(nh.nsf_record_can_edit(params(nsf=(), rows={'R': [row(can_edit=True)]}), 'R'))

    def test_no_access_rows_is_unknown(self):
        self.assertIsNone(nh.nsf_record_can_edit(params(), 'R'))
        self.assertIsNone(nh.nsf_record_can_edit(params(rows={'R': []}), 'R'))

    def test_editor_and_owner_can_edit(self):
        self.assertTrue(nh.nsf_record_can_edit(params(rows={'R': [row(can_edit=True)]}), 'R'))
        self.assertTrue(nh.nsf_record_can_edit(params(rows={'R': [row(owner=True)]}), 'R'))

    def test_a_viewer_cannot_edit(self):
        self.assertFalse(nh.nsf_record_can_edit(params(rows={'R': [row()]}), 'R'))

    def test_any_granting_row_wins_over_an_inherited_viewer_row(self):
        rows = {'R': [row(inherited=True), row(can_edit=True)]}
        self.assertTrue(nh.nsf_record_can_edit(params(rows=rows), 'R'))

    def test_a_denied_row_does_not_grant(self):
        self.assertFalse(nh.nsf_record_can_edit(params(rows={'R': [row(can_edit=True, denied_access=True)]}), 'R'))

    def test_rows_of_other_users_only_is_unknown(self):
        rows = {'R': [row(username='someone@else.com', can_edit=False)]}
        self.assertIsNone(nh.nsf_record_can_edit(params(rows=rows), 'R'))

    def test_a_row_without_a_username_matches_by_account_uid(self):
        mine = row(can_edit=True)
        del mine['username']
        mine['access_uid'] = ME_UID
        self.assertTrue(nh.nsf_record_can_edit(params(rows={'R': [mine]}), 'R'))


class TestCanWrite(unittest.TestCase):
    def test_a_viewer_of_an_nsf_record_is_refused(self):
        p = params(rows={'R': [row()]}, classic={'R': {}})
        with patch.object(up.api, 'resolve_record_write_path', return_value='path') as classic:
            self.assertIs(up._can_write(p)('R'), False)
            classic.assert_not_called()                                   # the NSF rows decide, not the classic cache

    def test_an_nsf_editor_is_allowed_without_the_classic_check(self):
        p = params(rows={'R': [row(can_edit=True)]}, classic={'R': {}})
        with patch.object(up.api, 'resolve_record_write_path', return_value=None) as classic:
            self.assertIs(up._can_write(p)('R'), True)
            classic.assert_not_called()

    def test_an_nsf_record_without_rows_is_unknown_and_allowed(self):
        self.assertIsNone(up._can_write(params())('R'))

    def test_a_classic_record_keeps_the_classic_rule(self):
        p = params(nsf=(), classic={'C': {}})
        with patch.object(up.api, 'resolve_record_write_path', return_value=None):
            self.assertIs(up._can_write(p)('C'), False)
        with patch.object(up.api, 'resolve_record_write_path', return_value='path'):
            self.assertIs(up._can_write(p)('C'), True)


if __name__ == '__main__':
    unittest.main()

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
"""`pam project extend` matching of JSON items to existing records, run through map_records().

Characterization of the rules extend always had, plus the fixes of the shared matcher:
a record reachable through two sources is ONE record, direct app shares count, and the
matching never loads a record per JSON item.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam_import import ksm_scope
from keepercommander.commands.pam_import.extend import PAMProjectExtendCommand
from keepercommander.commands.pam_import.ksm_scope import AppShares, collect_ksm_scope

UID_WEB = 'W' * 22
UID_BOB = 'B' * 22
UID_DB1 = 'D' * 22
UID_DB2 = 'E' * 22
UID_G1 = 'G' * 22
UID_DIRECT = 'X' * 22

RECORDS = {
    UID_WEB: (UID_WEB, 'web', 'pamMachine', ''),
    UID_BOB: (UID_BOB, 'bob-user', 'pamUser', 'bob'),
    UID_DB1: (UID_DB1, 'db', 'pamDatabase', ''),
    UID_DB2: (UID_DB2, 'db', 'pamDatabase', ''),
    UID_G1: (UID_G1, 'in-unshared-child', 'pamMachine', ''),
    UID_DIRECT: (UID_DIRECT, 'direct-rec', 'pamMachine', ''),
}


def _params():
    p = MagicMock()
    p.shared_folder_cache = {'SHF': {}}
    p.folder_cache = {'SHF': SimpleNamespace(uid='SHF', name='sf', parent_uid='', subfolders=[])}
    p.nested_share_folders = {}
    p.nested_share_records = {}
    p.nested_share_folder_records = {}
    p.subfolder_record_cache = {'SHF': [UID_WEB, UID_BOB, UID_DB1, UID_DB2]}
    return p


def _scope(params, shares=None, roots=None):
    calls = []

    def summary(_params, uid):
        calls.append(uid)
        return RECORDS.get(uid)

    with patch.object(ksm_scope, 'get_record_summary', side_effect=summary):
        scope = collect_ksm_scope(
            params, 'app1',
            folder_roots=roots if roots is not None else [{'uid': 'SHF', 'source': 'classic', 'name': 'sf'}],
            shares=shares or AppShares(folder_uids=['SHF']))
    return scope, calls


def _map(params, scope, resources=(), users=(), folder_paths=None):
    project = {
        'data': {'pam_data': {'resources': list(resources), 'users': list(users)}},
        'options': {'dry_run': True},
        'ksm_app_uid': 'app1',
        'ksm_shared_folders': [{'uid': 'SHF', 'name': 'sf', 'source': 'classic'}],
        'folders': {'path_to_folder_uid': dict(folder_paths or {}),
                    'good_paths': [(path, [path]) for path in (folder_paths or {})]},
        'pam_config': {'pam_config_uid': 'CFG', 'pam_config_object': None},
        'error_count': 0,
        'ksm_scope': scope,
    }
    return PAMProjectExtendCommand().map_records(params, project)


def _machine(title, **kw):
    return {'type': 'pamMachine', 'title': title, 'host': 'h', 'users': [], **kw}


class TestExtendMatching(unittest.TestCase):

    def test_existing_and_new_by_title(self):
        params = _params()
        scope, _ = _scope(params)
        resources, users, errors, new_count = _map(
            params, scope, resources=[_machine('web'), _machine('brand-new')],
            users=[{'type': 'pamUser', 'title': 'bob-user', 'login': 'bob'}])
        self.assertEqual(errors, [])
        self.assertEqual([(r.title, r._extend_tag) for r in resources], [('web', 'existing'), ('brand-new', 'new')])
        self.assertEqual(resources[0].uid, UID_WEB)
        self.assertEqual((users[0]._extend_tag, users[0].uid), ('existing', UID_BOB))
        self.assertEqual(new_count, 1)

    def test_duplicate_titles_in_the_vault_are_ambiguous(self):
        params = _params()
        scope, _ = _scope(params)
        _, _, errors, _ = _map(params, scope, resources=[_machine('db')])
        self.assertEqual(len(errors), 1)
        # (the identifier is the generated uid: extend assigns uids before it matches, as it always did)
        self.assertRegex(errors[0], r'^Multiple matches for record uid "[\w-]{22}"; add folder_path to disambiguate$')

    def test_uid_outside_the_scope_is_an_error_with_the_legacy_text(self):
        params = _params()
        scope, _ = _scope(params)
        missing = 'Z' * 22
        _, _, errors, _ = _map(params, scope, resources=[_machine('anything', uid=missing)])
        self.assertEqual(errors, [f'uid "{missing}" not found in KSM app for record uid "{missing}"'])

    def test_uid_in_scope_is_existing(self):
        params = _params()
        scope, _ = _scope(params)
        resources, _, errors, _ = _map(params, scope, resources=[_machine('renamed', uid=UID_WEB)])
        self.assertEqual(errors, [])
        self.assertEqual((resources[0]._extend_tag, resources[0].uid), ('existing', UID_WEB))

    def test_folder_path_matches_inside_that_folder_only(self):
        params = _params()
        scope, _ = _scope(params)
        resources, _, errors, _ = _map(params, scope, resources=[_machine('web', folder_path='sf')],
                                       folder_paths={'sf': 'SHF'})
        self.assertEqual(errors, [])
        self.assertEqual(resources[0]._extend_tag, 'existing')

    def test_folder_path_that_cannot_be_resolved_is_an_error(self):
        params = _params()
        scope, _ = _scope(params)
        _, _, errors, _ = _map(params, scope, resources=[_machine('web', folder_path='nope/x')])
        self.assertEqual(len(errors), 1)
        self.assertRegex(errors[0], r'^folder_path "nope/x" could not be resolved for record uid "[\w-]{22}"$')

    def test_record_shared_directly_and_through_a_folder_is_not_ambiguous(self):
        # the KSM API returns such a record twice; extend used to report "Multiple matches"
        params = _params()
        scope, _ = _scope(params, shares=AppShares(folder_uids=['SHF'], record_uids=[UID_WEB, UID_WEB]))
        resources, _, errors, _ = _map(params, scope, resources=[_machine('web')])
        self.assertEqual(errors, [])
        self.assertEqual((resources[0]._extend_tag, resources[0].uid), ('existing', UID_WEB))

    def test_record_shared_only_directly_is_found_and_not_duplicated(self):
        params = _params()
        scope, _ = _scope(params, shares=AppShares(folder_uids=['SHF'], record_uids=[UID_DIRECT]))
        resources, _, errors, new_count = _map(params, scope, resources=[_machine('direct-rec')])
        self.assertEqual(errors, [])
        self.assertEqual((resources[0]._extend_tag, resources[0].uid, new_count), ('existing', UID_DIRECT, 0))

    def test_record_in_an_unshared_child_nsf_still_counts_as_existing(self):
        # extend must not create a duplicate of a record that sits in a child NSF without its own app share
        params = _params()
        params.shared_folder_cache = {}
        params.folder_cache = {}
        params.nested_share_folders = {
            'P': {'name': 'P', 'parent_uid': None, 'folder_key_unencrypted': b'k' * 32},
            'C': {'name': 'C', 'parent_uid': 'P', 'folder_key_unencrypted': b'k' * 32},
        }
        params.subfolder_record_cache = {}
        params.nested_share_folder_records = {'P': [UID_WEB], 'C': [UID_G1]}
        scope, _ = _scope(params, shares=AppShares(folder_uids=['P']),
                          roots=[{'uid': 'P', 'source': 'nested', 'name': 'P'}])
        self.assertFalse(scope.records[UID_G1].shared)
        resources, _, errors, new_count = _map(params, scope, resources=[_machine('in-unshared-child')])
        self.assertEqual(errors, [])
        self.assertEqual((resources[0]._extend_tag, resources[0].uid, new_count), ('existing', UID_G1, 0))
        self.assertIn('NSF "C" (child of "P"', scope.nsf_warnings(ignored=False)[0])

    def test_records_are_loaded_once_not_once_per_json_item(self):
        params = _params()
        scope, calls = _scope(params)
        self.assertLessEqual(len(calls), len(RECORDS))
        before = len(calls)
        _map(params, scope, resources=[_machine(f'new-{i}') for i in range(200)])
        self.assertEqual(len(calls), before)

    def test_scope_is_built_once_and_kept_in_the_project(self):
        params = _params()
        project = {'ksm_app_uid': 'app1', 'ksm_shared_folders': [{'uid': 'SHF', 'name': 'sf', 'source': 'classic'}]}
        with patch.object(ksm_scope, 'get_record_summary', side_effect=lambda p, u: RECORDS.get(u)), \
                patch.object(ksm_scope, 'read_app_shares', return_value=AppShares(folder_uids=['SHF'])) as read:
            first = PAMProjectExtendCommand._get_ksm_scope(params, project)
            second = PAMProjectExtendCommand._get_ksm_scope(params, project)
        self.assertIs(first, second)
        self.assertEqual(read.call_count, 1)


if __name__ == '__main__':
    unittest.main()

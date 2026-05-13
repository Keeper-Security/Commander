"""Tests for --folder-uid scoping on records-export.

The core helper _collect_records_under_folders walks params.folder_cache
+ params.subfolder_record_cache without any network I/O, so these tests
run against a handcrafted fake params without a live session.
"""

import unittest
from types import SimpleNamespace

from keepercommander.commands.keeper_tenant_migrate.commands import _collect_records_under_folders


def _make_params(*, folders: dict, records_in_folder: dict):
    """Build a fake params with folder_cache + subfolder_record_cache.

    `folders` — {uid: {'name': str, 'subfolders': [uid, ...]}}
    `records_in_folder` — {uid: [record_uid, ...]}
    """
    folder_cache = {}
    for uid, meta in folders.items():
        folder_cache[uid] = SimpleNamespace(
            name=meta.get('name', ''),
            subfolders=list(meta.get('subfolders', [])),
            parent_uid=meta.get('parent_uid'),
        )
    return SimpleNamespace(
        folder_cache=folder_cache,
        subfolder_record_cache=records_in_folder,
    )


class CollectRecordsUnderFoldersTests(unittest.TestCase):
    def test_empty_folder_list_returns_empty(self):
        params = _make_params(folders={}, records_in_folder={})
        self.assertEqual(_collect_records_under_folders(params, []), set())

    def test_single_flat_folder(self):
        params = _make_params(
            folders={'F1': {'name': 'Acme', 'subfolders': []}},
            records_in_folder={'F1': ['r1', 'r2']},
        )
        result = _collect_records_under_folders(params, ['F1'])
        self.assertEqual(result, {'r1', 'r2'})

    def test_walks_subfolders_recursively(self):
        params = _make_params(
            folders={
                'F1': {'name': 'Root', 'subfolders': ['F2']},
                'F2': {'name': 'Child', 'subfolders': ['F3']},
                'F3': {'name': 'Grand', 'subfolders': []},
            },
            records_in_folder={
                'F1': ['r1'], 'F2': ['r2'], 'F3': ['r3'],
            },
        )
        self.assertEqual(
            _collect_records_under_folders(params, ['F1']),
            {'r1', 'r2', 'r3'},
        )

    def test_multiple_roots_union(self):
        params = _make_params(
            folders={
                'F1': {'name': 'A', 'subfolders': []},
                'F2': {'name': 'B', 'subfolders': []},
                'F3': {'name': 'C', 'subfolders': []},   # not requested
            },
            records_in_folder={
                'F1': ['r1'], 'F2': ['r2'], 'F3': ['r-should-not-include'],
            },
        )
        result = _collect_records_under_folders(params, ['F1', 'F2'])
        self.assertEqual(result, {'r1', 'r2'})

    def test_missing_folder_uid_logged_not_raised(self):
        params = _make_params(
            folders={'F1': {'name': 'Known', 'subfolders': []}},
            records_in_folder={'F1': ['r1']},
        )
        with self.assertLogs(level='WARNING') as cm:
            result = _collect_records_under_folders(
                params, ['F1', 'UNKNOWN-UID'],
            )
        self.assertEqual(result, {'r1'})
        self.assertTrue(any('UNKNOWN-UID' in msg for msg in cm.output))

    def test_cycle_guard(self):
        """If folder.subfolders contains a back-reference (shouldn't
        happen in practice but defensive), walk terminates."""
        params = _make_params(
            folders={
                'F1': {'name': 'A', 'subfolders': ['F2']},
                'F2': {'name': 'B', 'subfolders': ['F1']},  # back-ref
            },
            records_in_folder={'F1': ['r1'], 'F2': ['r2']},
        )
        result = _collect_records_under_folders(params, ['F1'])
        self.assertEqual(result, {'r1', 'r2'})  # both records, no infinite loop

    def test_folder_with_no_records_still_walked(self):
        """An empty folder on the path should still let the walk
        reach its descendants."""
        params = _make_params(
            folders={
                'F1': {'name': 'EmptyRoot', 'subfolders': ['F2']},
                'F2': {'name': 'HasRecords', 'subfolders': []},
            },
            records_in_folder={'F2': ['r1']},   # F1 intentionally missing
        )
        result = _collect_records_under_folders(params, ['F1'])
        self.assertEqual(result, {'r1'})


class RecordsExportParserTests(unittest.TestCase):
    def test_folder_uid_is_repeatable(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import records_export_parser
        args = records_export_parser.parse_args([
            '--output-dir', '/tmp/x',
            '--folder-uid', 'UID1',
            '--folder-uid', 'UID2',
        ])
        self.assertEqual(args.folder_uids, ['UID1', 'UID2'])

    def test_folder_uid_defaults_to_empty_list(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import records_export_parser
        args = records_export_parser.parse_args(['--output-dir', '/tmp/x'])
        self.assertEqual(args.folder_uids, [])


if __name__ == '__main__':
    unittest.main()

"""Security regressions: file modes on sensitive outputs.

Every output that contains or may contain plaintext credentials must be
written with mode 0600 (owner read/write only) — preventing accidental
world/group readability on a shared box.
"""

import json
import os
import stat
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.inventory import InventoryAssembler
from keepercommander.commands.keeper_tenant_migrate.live_inventory import (
    build_inventory_from_params,
    write_inventory,
)


class _Params:
    """Minimal fake Commander params for the inventory builder."""
    def __init__(self):
        self.user = 'admin@src'
        self.server = 'https://keepersecurity.eu'
        self.enterprise = {
            'enterprise_name': 'X',
            'nodes': [{'node_id': 1, 'data': {'displayname': 'X'}}],
            'teams': [], 'roles': [], 'users': [], 'shared_folders': [],
        }
        self.record_cache = {}


def _mode_bits(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class InventoryWriteSecuresOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_inventory_sets_0600_on_json_and_sidecar(self):
        inv = build_inventory_from_params(_Params())
        path = os.path.join(self.tmp, 'inv.json')
        write_inventory(inv, path)
        self.assertEqual(_mode_bits(path), 0o600)
        self.assertEqual(_mode_bits(path + '.sha256'), 0o600)

    def test_assembler_write_sets_0600(self):
        # Set up a minimal staging dir
        with open(os.path.join(self.tmp, 'nodes.csv'), 'w') as f:
            f.write('1,"X","",false,0,0,0\n')
        with open(os.path.join(self.tmp, 'teams.csv'), 'w') as f:
            f.write('')
        with open(os.path.join(self.tmp, 'users.csv'), 'w') as f:
            f.write('')
        with open(os.path.join(self.tmp, 'shared_folders.json'), 'w') as f:
            f.write('[]')
        os.makedirs(os.path.join(self.tmp, 'roles'))
        os.makedirs(os.path.join(self.tmp, 'records'))

        out = os.path.join(self.tmp, 'inv.json')
        asm = InventoryAssembler(self.tmp, prefix='')
        asm.write(out)
        self.assertEqual(_mode_bits(out), 0o600)
        self.assertEqual(_mode_bits(out + '.sha256'), 0o600)


class ConverterWriteSecuresOutputTests(unittest.TestCase):
    """Phase 2 file-perm gap fix: the import-records bundle emitted
    by Converter.write() / _write_split() / batch-file carries
    plaintext record bodies. Must be 0o600 like inventory.json."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_converter_write_sets_0600_on_bundle(self):
        from keepercommander.commands.keeper_tenant_migrate.converter import RecordConverter
        out = os.path.join(self.tmp, 'import.json')
        RecordConverter(include_sf=False, split_by_type=False).write(
            import_records=[{'$type': 'login', 'title': 'x'}],
            sf_section=None, output_path=out,
        )
        self.assertEqual(_mode_bits(out), 0o600)

    def test_converter_write_split_sets_0600_on_each_file(self):
        from keepercommander.commands.keeper_tenant_migrate.converter import RecordConverter
        out = os.path.join(self.tmp, 'import.json')
        written = RecordConverter(include_sf=False, split_by_type=True).write(
            import_records=[{'$type': 'login', 'title': 'x'},
                             {'$type': 'note', 'title': 'y'}],
            sf_section=None, output_path=out,
        )
        # Each per-type JSON + the .batch driver must all be 0o600.
        self.assertGreater(len(written), 0)
        for path in written:
            self.assertEqual(_mode_bits(path), 0o600,
                              f'{path} should be 0o600, got '
                              f'{oct(_mode_bits(path))}')


class BulkRecordsChunkSecuresOutputTests(unittest.TestCase):
    """Phase 2 file-perm gap fix: chunked records-import writes per-
    chunk JSON bundles to a tmpdir. Each chunk carries plaintext
    record bodies; the parent tmpdir is 0o700 but defense-in-depth
    requires each chunk file itself be 0o600."""

    def test_chunked_bundle_files_are_0o600(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate import bulk_records

        captured_paths = []

        class FakeCmd:
            def execute(self, params, **kw):
                # Record mode at the moment the chunk file exists on
                # disk — before the finally: cleanup wipes it.
                captured_paths.append((kw['name'],
                                        _mode_bits(kw['name'])))

        bundle = {
            'records': [{'$type': 'login', 'title': f'r{i}'}
                        for i in range(5)],
            'shared_folders': [],
        }

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.bulk_records.time.sleep'):
            bulk_records.run_chunked_import(
                cmd=FakeCmd(),
                params=None,
                base_kwargs={'format': 'json'},
                bundle=bundle,
                chunk_size=2,
                chunk_delay=0,
            )

        # 5 records / chunk_size=2 → 3 chunks
        self.assertEqual(len(captured_paths), 3)
        for path, mode in captured_paths:
            self.assertEqual(mode, 0o600,
                              f'{path} should be 0o600, got {oct(mode)}')


class ValidatorNeverEmitsFieldValuesTests(unittest.TestCase):
    """Regression: check messages describe mismatches without revealing the value."""

    def test_password_mismatch_message_has_no_value(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import _compare_field
        check = _compare_field('T', 'password', 'top-secret-original',
                               'top-secret-TARGET')
        self.assertNotIn('top-secret-original', check.message)
        self.assertNotIn('top-secret-TARGET', check.message)
        self.assertIn('mismatch', check.message)

    def test_custom_field_mismatch_message_has_no_value(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import _compare_custom_fields
        checks = list(_compare_custom_fields('T',
                                              {'K': 'original-value'},
                                              {'K': 'DIFFERENT-VALUE'}))
        for c in checks:
            self.assertNotIn('original-value', c.message)
            self.assertNotIn('DIFFERENT-VALUE', c.message)


if __name__ == '__main__':
    unittest.main()

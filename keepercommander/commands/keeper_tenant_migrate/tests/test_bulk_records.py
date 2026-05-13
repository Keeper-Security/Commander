"""B2 — `keepercommander.commands.keeper_tenant_migrate.bulk_records.run_chunked_import` extracted
from `commands._run_chunked_import` (Bug 68, v1.6.2). Tests cover:
  - Chunk slicing — N records / S chunk-size → ceil(N/S) chunks.
  - Shared folders ride only on chunk #1.
  - Per-chunk temp files are written and cleaned.
  - The supplied `cmd.execute` is called once per chunk with the
    expected `name=<temp path>` plus base_kwargs forwarded intact.
  - chunk_size <= 0 raises ValueError; chunk_delay < 0 raises.
  - Backwards-compat `commands._run_chunked_import` shim still works.
"""

import json
import os
import time
import unittest
from unittest.mock import patch

from keepercommander.commands.keeper_tenant_migrate.bulk_records import run_chunked_import


class _FakeCmd:
    """Records every execute call with kwargs + reads the bundle JSON
    from disk so tests can verify chunk content + shared_folders attach."""

    def __init__(self):
        self.calls = []   # list of (params, kwargs, parsed_chunk_bundle)

    def execute(self, params, **kwargs):
        path = kwargs.get('name')
        with open(path) as f:
            chunk_bundle = json.load(f)
        self.calls.append((params, dict(kwargs), chunk_bundle))


class RunChunkedImportTests(unittest.TestCase):

    def setUp(self):
        # Avoid real sleeps during tests.
        self._sleep_patch = patch('keepercommander.commands.keeper_tenant_migrate.bulk_records.time.sleep',
                                   lambda s: None)
        self._sleep_patch.start()

    def tearDown(self):
        self._sleep_patch.stop()

    def test_records_split_into_expected_number_of_chunks(self):
        cmd = _FakeCmd()
        bundle = {'records': [{'title': f'r{i}'} for i in range(10)]}
        run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                           bundle=bundle, chunk_size=3, chunk_delay=0.0)
        # ceil(10 / 3) = 4 chunks
        self.assertEqual(len(cmd.calls), 4)
        sizes = [len(c[2]['records']) for c in cmd.calls]
        self.assertEqual(sizes, [3, 3, 3, 1])

    def test_shared_folders_ride_only_on_first_chunk(self):
        cmd = _FakeCmd()
        bundle = {
            'records': [{'title': f'r{i}'} for i in range(5)],
            'shared_folders': [{'name': 'SF1'}, {'name': 'SF2'}],
        }
        run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                           bundle=bundle, chunk_size=2, chunk_delay=0.0)
        self.assertEqual(len(cmd.calls), 3)
        first_bundle = cmd.calls[0][2]
        self.assertIn('shared_folders', first_bundle)
        self.assertEqual(len(first_bundle['shared_folders']), 2)
        for _params, _kwargs, b in cmd.calls[1:]:
            self.assertNotIn('shared_folders', b)

    def test_no_shared_folders_when_bundle_has_none(self):
        cmd = _FakeCmd()
        bundle = {'records': [{'title': 'r0'}, {'title': 'r1'}]}
        run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                           bundle=bundle, chunk_size=1, chunk_delay=0.0)
        for _params, _kwargs, b in cmd.calls:
            self.assertNotIn('shared_folders', b)

    def test_base_kwargs_forwarded_with_name_overridden(self):
        cmd = _FakeCmd()
        bundle = {'records': [{'title': 'r'}]}
        run_chunked_import(cmd=cmd, params=object(),
                           base_kwargs={'format': 'json',
                                        'shared': True,
                                        'permissions': 'N',
                                        'name': '/will/be/overridden'},
                           bundle=bundle, chunk_size=10, chunk_delay=0.0)
        kwargs = cmd.calls[0][1]
        self.assertEqual(kwargs.get('format'), 'json')
        self.assertIs(kwargs.get('shared'), True)
        self.assertEqual(kwargs.get('permissions'), 'N')
        # The runner overrides `name` with each chunk's temp path.
        self.assertNotEqual(kwargs.get('name'), '/will/be/overridden')
        self.assertTrue(os.path.basename(kwargs['name']).startswith('chunk_'))

    def test_temp_files_cleaned_after_run(self):
        cmd = _FakeCmd()
        bundle = {'records': [{'title': 'r'}]}
        run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                           bundle=bundle, chunk_size=1, chunk_delay=0.0)
        path = cmd.calls[0][1]['name']
        self.assertFalse(os.path.exists(path),
                         f'chunk temp file not cleaned: {path}')
        self.assertFalse(os.path.exists(os.path.dirname(path)),
                         'tmpdir not cleaned')

    def test_temp_files_cleaned_on_exception(self):
        """Partial-run cleanup: if cmd.execute raises mid-stream the
        temp dir is still removed (tested via the finally clause)."""
        class _RaisingCmd:
            calls = 0
            def execute(self, params, **kwargs):
                _RaisingCmd.calls += 1
                if _RaisingCmd.calls == 2:
                    raise RuntimeError('mid-stream boom')
                # Read bundle to confirm it was written.
                with open(kwargs['name']) as f:
                    json.load(f)
        bundle = {'records': [{'title': f'r{i}'} for i in range(5)]}
        cmd = _RaisingCmd()
        with self.assertRaises(RuntimeError):
            run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                               bundle=bundle, chunk_size=2, chunk_delay=0.0)
        # No keeper_records_chunks_* leftovers in /tmp.
        import tempfile, glob
        leaks = glob.glob(os.path.join(tempfile.gettempdir(),
                                        'keeper_records_chunks_*'))
        self.assertEqual(leaks, [],
                         f'tmpdir leaked on exception: {leaks}')

    def test_invalid_chunk_size_rejected(self):
        with self.assertRaises(ValueError):
            run_chunked_import(cmd=_FakeCmd(), params=None, base_kwargs={},
                               bundle={'records': []},
                               chunk_size=0, chunk_delay=1.0)
        with self.assertRaises(ValueError):
            run_chunked_import(cmd=_FakeCmd(), params=None, base_kwargs={},
                               bundle={'records': []},
                               chunk_size=-1, chunk_delay=1.0)

    def test_invalid_chunk_delay_rejected(self):
        with self.assertRaises(ValueError):
            run_chunked_import(cmd=_FakeCmd(), params=None, base_kwargs={},
                               bundle={'records': []},
                               chunk_size=1, chunk_delay=-0.1)

    def test_empty_records_runs_no_chunks(self):
        cmd = _FakeCmd()
        run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                           bundle={'records': []},
                           chunk_size=10, chunk_delay=0.0)
        self.assertEqual(cmd.calls, [])

    def test_sleeps_between_chunks_but_not_after_last(self):
        sleeps = []
        with patch('keepercommander.commands.keeper_tenant_migrate.bulk_records.time.sleep',
                   lambda s: sleeps.append(s)):
            cmd = _FakeCmd()
            bundle = {'records': [{'title': 'r'} for _ in range(5)]}
            run_chunked_import(cmd=cmd, params=object(), base_kwargs={},
                               bundle=bundle, chunk_size=2, chunk_delay=2.5)
        # 3 chunks → 2 inter-chunk sleeps
        self.assertEqual(sleeps, [2.5, 2.5])


class CommandsBackwardsCompatShimTests(unittest.TestCase):
    """`commands._run_chunked_import` is kept as a backwards-compat shim
    around `bulk_records.run_chunked_import`. Anyone importing the
    private name still works."""

    def test_shim_delegates_to_public_runner(self):
        from keepercommander.commands.keeper_tenant_migrate import commands
        cmd = _FakeCmd()
        bundle = {'records': [{'title': 'r0'}, {'title': 'r1'}]}
        with patch('keepercommander.commands.keeper_tenant_migrate.bulk_records.time.sleep',
                   lambda s: None):
            commands._run_chunked_import(cmd, object(), {}, bundle, 1, 0.0)
        self.assertEqual(len(cmd.calls), 2)


if __name__ == '__main__':
    unittest.main()

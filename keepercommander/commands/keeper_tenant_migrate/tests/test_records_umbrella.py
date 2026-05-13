import os
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate.commands import RecordsUmbrellaCommand


class _FakeParams:
    def __init__(self, user='', server='', enterprise=None,
                  session_token='fake'):
        self.user = user
        self.server = server
        self.enterprise = enterprise or {}
        self.session_token = session_token
        self.record_cache = {}


class StageSelectionTests(unittest.TestCase):
    def test_source_role_runs_source_stages(self):
        with tempfile.TemporaryDirectory() as run_dir:
            from keepercommander.commands.keeper_tenant_migrate.wizard import save_migration_yaml
            save_migration_yaml(run_dir, {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
            })
            params = _FakeParams(enterprise={'enterprise_name': 'SourceCo'})

            called = []
            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsExportCommand.execute',
                lambda self, p, **kw: called.append(('export', kw)) or {}
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.ConvertCommand.execute',
                lambda self, p, **kw: called.append(('convert', kw)) or {}
            ):
                result = RecordsUmbrellaCommand().execute(
                    params, run_dir=run_dir, stages='',
                    dry_run=False, staging_dir='', record_type='')

            self.assertEqual(result['role'], 'source')
            self.assertEqual(result['stages'], ['export', 'convert'])
            self.assertEqual([c[0] for c in called], ['export', 'convert'])

    def test_target_role_runs_target_stages(self):
        with tempfile.TemporaryDirectory() as run_dir:
            from keepercommander.commands.keeper_tenant_migrate.wizard import save_migration_yaml
            save_migration_yaml(run_dir, {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
            })
            params = _FakeParams(enterprise={'enterprise_name': 'TargetCo'})

            called = []
            stub = lambda tag: (
                lambda self, p, **kw: called.append((tag, kw)) or {})
            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsManifestCommand.execute',
                stub('manifest')
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsImportCommand.execute',
                stub('import')
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsAttachmentsCommand.execute',
                stub('attachments')
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsSharesCommand.execute',
                stub('shares')
            ):
                result = RecordsUmbrellaCommand().execute(
                    params, run_dir=run_dir, stages='',
                    dry_run=False, staging_dir='', record_type='')

            self.assertEqual(result['role'], 'target')
            self.assertEqual(result['stages'],
                              ['manifest', 'import', 'attachments', 'shares'])
            self.assertEqual([c[0] for c in called],
                              ['manifest', 'import', 'attachments', 'shares'])

    def test_explicit_stages_override_role(self):
        with tempfile.TemporaryDirectory() as run_dir:
            params = _FakeParams()   # unknown role
            called = []
            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.ConvertCommand.execute',
                lambda self, p, **kw: called.append('convert') or {}
            ):
                result = RecordsUmbrellaCommand().execute(
                    params, run_dir=run_dir, stages='convert',
                    dry_run=False, staging_dir='', record_type='')
            self.assertEqual(result['stages'], ['convert'])
            self.assertEqual(called, ['convert'])

    def test_unknown_role_without_stages_errors(self):
        with tempfile.TemporaryDirectory() as run_dir:
            params = _FakeParams()
            result = RecordsUmbrellaCommand().execute(
                params, run_dir=run_dir, stages='',
                dry_run=False, staging_dir='', record_type='')
            self.assertIn('error', result)

    def test_unknown_stage_errors(self):
        with tempfile.TemporaryDirectory() as run_dir:
            params = _FakeParams()
            result = RecordsUmbrellaCommand().execute(
                params, run_dir=run_dir, stages='foo',
                dry_run=False, staging_dir='', record_type='')
            self.assertIn('error', result)
            self.assertIn('foo', result['error'])

    def test_stage_failure_halts_remaining_non_dry_run(self):
        with tempfile.TemporaryDirectory() as run_dir:
            params = _FakeParams()
            called = []

            def fail_import(self, p, **kw):
                called.append('import')
                raise RuntimeError('import blew up')

            def tag(name):
                def _inner(self, p, **kw):
                    called.append(name)
                return _inner

            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsManifestCommand.execute',
                tag('manifest')
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsImportCommand.execute',
                fail_import
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsAttachmentsCommand.execute',
                tag('attachments')
            ), mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsSharesCommand.execute',
                tag('shares')
            ):
                result = RecordsUmbrellaCommand().execute(
                    params, run_dir=run_dir,
                    stages='manifest,import,attachments,shares',
                    dry_run=False, staging_dir='', record_type='')
            self.assertEqual(called, ['manifest', 'import'])   # halted after import
            self.assertIn('error', result['outcomes']['import'])


if __name__ == '__main__':
    unittest.main()

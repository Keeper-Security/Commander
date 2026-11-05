"""Tests for post–Step 2 import tail helpers."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import vault
from keepercommander.commands.pam_import.base import PamScriptObject
from keepercommander.commands.pam_import.batch_attachments import BatchAttachmentSummary
from keepercommander.commands.pam_import.import_tail import (
    apply_domain_admin_tail,
    run_import_tail,
    run_pam_config_scripts_tail,
)

CFG_UID = 'CCCCCCCCCCCCCCCCCCCCCC'
ADMIN_UID = 'AAAAAAAAAAAAAAAAAAAAAA'


class TestRunPamConfigScriptsTail(unittest.TestCase):
    def test_skips_scripts_without_record_refs(self):
        params = MagicMock()
        script = PamScriptObject()
        script.file = __file__
        with patch(
            'keepercommander.commands.pam_import.import_tail.run_import_tail_config_scripts',
        ) as batch:
            summary = run_pam_config_scripts_tail(params, CFG_UID, [script])
        batch.assert_not_called()
        self.assertEqual(summary.uploaded_count, 0)

    def test_syncs_and_batches_cred_scripts(self):
        params = MagicMock()
        script = PamScriptObject()
        script.file = __file__
        script.record_refs = [ADMIN_UID]
        expected = BatchAttachmentSummary(uploaded_count=1)
        with patch('keepercommander.commands.pam_import.import_tail.sync_down_after_batch') as sync, \
             patch(
                 'keepercommander.commands.pam_import.import_tail.run_import_tail_config_scripts',
                 return_value=expected,
             ) as batch:
            summary = run_pam_config_scripts_tail(params, CFG_UID, [script])
        sync.assert_called_once_with(params)
        batch.assert_called_once_with(params, CFG_UID, [script])
        self.assertIs(summary, expected)


class TestApplyDomainAdminTail(unittest.TestCase):
    def test_updates_pam_domain_configuration(self):
        from types import SimpleNamespace

        params = MagicMock()
        tdag = MagicMock()
        pce = MagicMock()
        pce.environment = 'domain'
        pce.admin_credential_ref = ADMIN_UID
        pam_resources = {}
        prf = SimpleNamespace(value=[pam_resources])
        pcrec = MagicMock(spec=vault.TypedRecord)
        pcrec.version = 6
        pcrec.record_type = 'pamDomainConfiguration'
        pcrec.get_typed_field.return_value = prf
        with patch(
            'keepercommander.commands.pam_import.import_tail.vault.KeeperRecord.load',
            return_value=pcrec,
        ), patch(
            'keepercommander.commands.pam_import.import_tail.record_management.update_record',
        ) as upd:
            apply_domain_admin_tail(params, CFG_UID, pce, tdag)
        self.assertEqual(pam_resources['adminCredentialRef'], ADMIN_UID)
        upd.assert_called_once_with(params, pcrec)
        tdag.link_user_to_config_with_options.assert_called_once_with(ADMIN_UID, is_admin='on')


class TestRunImportTail(unittest.TestCase):
    def test_scripts_before_domain_admin(self):
        params = MagicMock()
        tdag = MagicMock()
        pce = MagicMock()
        pce.environment = 'domain'
        pce.admin_credential_ref = ADMIN_UID
        pce.scripts.scripts = []
        calls = []

        def _scripts(*_a, **_k):
            calls.append('scripts')
            return BatchAttachmentSummary()

        def _domain(*_a, **_k):
            calls.append('domain')

        with patch(
            'keepercommander.commands.pam_import.import_tail.run_pam_config_scripts_tail',
            side_effect=_scripts,
        ), patch(
            'keepercommander.commands.pam_import.import_tail.apply_domain_admin_tail',
            side_effect=_domain,
        ), patch('keepercommander.commands.pam_import.import_tail.sync_down_after_batch'):
            run_import_tail(params, CFG_UID, pce, tdag, scripts=[MagicMock(record_refs=['x'])])
        self.assertEqual(calls, ['scripts', 'domain'])

    def test_final_nsf_sync_after_tail_when_nsf(self):
        params = MagicMock()
        params.nested_share_folders = {'NSFUID': {}}
        with patch('keepercommander.commands.pam_import.import_tail.sync_down_after_batch') as sync:
            run_import_tail(params, CFG_UID, None, MagicMock(), project_options={'use_nsf': True})
        sync.assert_called_once()
        self.assertIs(sync.call_args.args[0], params)

    def test_no_final_sync_for_classic_project(self):
        params = MagicMock()
        params.nested_share_folders = {}
        with patch('keepercommander.commands.pam_import.import_tail.sync_down_after_batch') as sync:
            run_import_tail(params, CFG_UID, None, MagicMock(), project_options={})
        sync.assert_not_called()


if __name__ == '__main__':
    unittest.main()

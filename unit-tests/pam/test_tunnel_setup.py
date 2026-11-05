"""Tests for batch tunnel_setup helpers (Phase C — no pte.execute)."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import vault
from keepercommander.commands.pam_import.base import (
    ConnectionSettingsRDP,
    PamMachineObject,
    PamSettingsFieldData,
)
from keepercommander.commands.pam_import.batch_step2 import _run_step2_machine
from keepercommander.commands.pam_import.tunnel_setup import (
    apply_tunnel_setup_batch,
    ensure_traffic_encryption_seed_on_typed_record,
    merge_initial_pam_settings_on_record,
    queue_resource_config_link,
)


MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'


class TestEnsureTrafficEncryptionSeed(unittest.TestCase):
    def test_adds_seed_when_empty(self):
        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        self.assertTrue(ensure_traffic_encryption_seed_on_typed_record(record))
        field = record.get_typed_field('trafficEncryptionSeed')
        self.assertIsNotNone(field)
        self.assertTrue(field.value)

    def test_does_not_overwrite_existing_seed(self):
        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        record.fields.append(vault.TypedField.new_field('trafficEncryptionSeed', 'existing', ''))
        self.assertFalse(ensure_traffic_encryption_seed_on_typed_record(record))
        self.assertEqual(record.get_typed_field('trafficEncryptionSeed').value, ['existing'])


class TestMergeInitialPamSettings(unittest.TestCase):
    def test_coerces_string_port_forward_to_dict(self):
        mach = PamMachineObject()
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        mach.pam_settings.connection = conn
        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        record.custom.append(vault.TypedField.new_field(
            'pamSettings',
            [{'allowSupplyHost': False, 'portForward': '', 'connection': {}}],
            '',
        ))
        self.assertTrue(merge_initial_pam_settings_on_record(record, mach))
        root = record.get_typed_field('pamSettings').value[0]
        self.assertIsInstance(root['portForward'], dict)
        self.assertIsInstance(root['connection'], dict)


class TestApplyTunnelSetupBatch(unittest.TestCase):
    def test_does_not_call_pte_execute(self):
        params = MagicMock()
        tdag = MagicMock()
        tdag.check_tunneling_enabled_config.return_value = True
        tdag.is_tunneling_config_set_up.return_value = True
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.pam_settings = PamSettingsFieldData()
        with patch(
            'keepercommander.commands.pam_import.tunnel_setup.parse_command_options',
            return_value={'enable_tunneling': True},
        ), patch(
            'keepercommander.commands.tunnel_and_connections.PAMTunnelEditCommand.execute',
        ) as pte_exec:
            self.assertTrue(apply_tunnel_setup_batch(params, tdag, mach, 'CFG_UID'))
            pte_exec.assert_not_called()

    def test_queue_resource_config_link_idempotent(self):
        tdag = MagicMock()
        tdag.is_tunneling_config_set_up.return_value = False
        queue_resource_config_link(tdag, MACH_UID)
        tdag.link_resource_to_config.assert_called_once_with(MACH_UID)


class TestBatchStep2UsesTunnelSetupBatch(unittest.TestCase):
    def test_run_step2_machine_calls_apply_tunnel_setup_batch(self):
        params = MagicMock()
        tdag = MagicMock()
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach._extend_tag = 'new'
        mach.pam_settings = PamSettingsFieldData()
        with patch(
            'keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch',
        ) as setup, patch(
            'keepercommander.commands.pam_import.batch_step2.parse_command_options',
            return_value={},
        ), patch(
            'keepercommander.commands.pam_import.batch_step2.is_admin_external',
            return_value=False,
        ):
            _run_step2_machine(params, tdag, mach, 'CFG_UID', 'ADMIN_UID')
            setup.assert_called_once_with(params, tdag, mach, 'CFG_UID')


if __name__ == '__main__':
    unittest.main()

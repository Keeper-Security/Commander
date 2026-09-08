#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Tests for PAM Gateway create/remove enforcement gating.

Regression coverage for: a role with the "Can create, deploy, and manage
Keeper Gateways" enforcement policy disabled could still create and delete
Gateways via `pam gateway new` / `pam gateway remove`, even though the same
role is correctly blocked in the Web Vault UI. Covers both the primary
discoveryrotation module and the legacy discoveryrotation_v1 module
(reachable at runtime via `pam legacy`), which had an identical, separately
implemented gap.
"""

import io
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.discoveryrotation import (
    PAMCreateGatewayCommand,
    PAMGatewayRemoveCommand,
)
from keepercommander.commands import discoveryrotation_v1


def _params_with_enforcement(mode):
    # type: (str) -> MagicMock
    """mode: 'allowed' (key present, True), 'denied_explicit_false' (key
    present, False), 'denied_absent' (booleans non-empty but key missing —
    what Commander's account-summary parser actually produces when a
    checkbox is unchecked, since it drops `:false` entries), or
    'no_enterprise' (no enforcement context at all — personal account)."""
    params = MagicMock()
    if mode == 'no_enterprise':
        params.enforcements = None
        return params
    if mode == 'allowed':
        booleans = [{'key': 'allow_pam_gateway', 'value': True}]
    elif mode == 'denied_explicit_false':
        booleans = [{'key': 'allow_pam_gateway', 'value': False}]
    elif mode == 'denied_absent':
        booleans = [{'key': 'some_other_key', 'value': True}]
    else:
        raise ValueError(f'unknown mode: {mode}')
    params.enforcements = {'booleans': booleans}
    return params


class TestPAMCreateGatewayCommandEnforcement(unittest.TestCase):

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_denied_when_enforcement_absent(self, mock_get_app_record, mock_create_gateway):
        params = _params_with_enforcement('denied_absent')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = PAMCreateGatewayCommand().execute(
                params, gateway_name='pocbyuser', ksm_app='PAM_application')

        self.assertIsNone(result)
        self.assertFalse(mock_get_app_record.called)
        self.assertFalse(mock_create_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_denied_when_enforcement_explicit_false(self, mock_get_app_record, mock_create_gateway):
        params = _params_with_enforcement('denied_explicit_false')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = PAMCreateGatewayCommand().execute(
                params, gateway_name='pocbyuser', ksm_app='PAM_application')

        self.assertIsNone(result)
        self.assertFalse(mock_get_app_record.called)
        self.assertFalse(mock_create_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_ksm_app_display_info')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_allowed_when_enforcement_true(
            self, mock_get_app_record, mock_get_ksm_app_display_info, mock_create_gateway):
        params = _params_with_enforcement('allowed')
        mock_get_app_record.return_value = {'record_uid': 'app_uid'}
        mock_get_ksm_app_display_info.return_value = ('PAM_application', True, 'PAM_application (app_uid)')
        mock_create_gateway.return_value = 'US:one-time-token'

        PAMCreateGatewayCommand().execute(
            params, gateway_name='pocbyuser', ksm_app='PAM_application', return_value=True)

        self.assertTrue(mock_create_gateway.called)

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_ksm_app_display_info')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_allowed_when_no_enforcements(
            self, mock_get_app_record, mock_get_ksm_app_display_info, mock_create_gateway):
        # Personal / non-enterprise account: no enforcement context, fail open.
        params = _params_with_enforcement('no_enterprise')
        mock_get_app_record.return_value = {'record_uid': 'app_uid'}
        mock_get_ksm_app_display_info.return_value = ('PAM_application', True, 'PAM_application (app_uid)')
        mock_create_gateway.return_value = 'US:one-time-token'

        PAMCreateGatewayCommand().execute(
            params, gateway_name='pocbyuser', ksm_app='PAM_application', return_value=True)

        self.assertTrue(mock_create_gateway.called)


class TestPAMGatewayRemoveCommandEnforcement(unittest.TestCase):

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    def test_denied_when_enforcement_absent(self, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('denied_absent')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            PAMGatewayRemoveCommand().execute(params, gateway='some_gateway_uid')

        self.assertFalse(mock_get_all_gateways.called)
        self.assertFalse(mock_remove_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    def test_denied_when_enforcement_explicit_false(self, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('denied_explicit_false')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            PAMGatewayRemoveCommand().execute(params, gateway='some_gateway_uid')

        self.assertFalse(mock_get_all_gateways.called)
        self.assertFalse(mock_remove_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.utils.base64_url_encode')
    def test_allowed_when_enforcement_true(
            self, mock_base64_url_encode, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('allowed')
        gateway = MagicMock(controllerUid=b'controller_uid', controllerName='pocbyuser')
        mock_get_all_gateways.return_value = [gateway]
        mock_base64_url_encode.return_value = 'gateway_uid'

        PAMGatewayRemoveCommand().execute(params, gateway='gateway_uid')

        self.assertTrue(mock_remove_gateway.called)


# --- Legacy discoveryrotation_v1 module (reachable via `pam legacy`) ---
# Same enforcement gate, imported from discoveryrotation and reused, but
# exercised against the v1 command classes to guard the legacy bypass path.

class TestLegacyPAMCreateGatewayCommandEnforcement(unittest.TestCase):

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.create_gateway')
    def test_denied_when_enforcement_absent(self, mock_create_gateway):
        params = _params_with_enforcement('denied_absent')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = discoveryrotation_v1.PAMCreateGatewayCommand().execute(
                params, gateway_name='pocbyuser', ksm_app='PAM_application')

        self.assertIsNone(result)
        self.assertFalse(mock_create_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.create_gateway')
    def test_denied_when_enforcement_explicit_false(self, mock_create_gateway):
        params = _params_with_enforcement('denied_explicit_false')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = discoveryrotation_v1.PAMCreateGatewayCommand().execute(
                params, gateway_name='pocbyuser', ksm_app='PAM_application')

        self.assertIsNone(result)
        self.assertFalse(mock_create_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.create_gateway')
    def test_allowed_when_enforcement_true(self, mock_create_gateway):
        params = _params_with_enforcement('allowed')
        mock_create_gateway.return_value = 'US:one-time-token'

        discoveryrotation_v1.PAMCreateGatewayCommand().execute(
            params, gateway_name='pocbyuser', ksm_app='PAM_application', return_value=True)

        self.assertTrue(mock_create_gateway.called)


class TestLegacyPAMGatewayRemoveCommandEnforcement(unittest.TestCase):

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.get_all_gateways')
    def test_denied_when_enforcement_absent(self, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('denied_absent')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            discoveryrotation_v1.PAMGatewayRemoveCommand().execute(params, gateway='some_gateway_uid')

        self.assertFalse(mock_get_all_gateways.called)
        self.assertFalse(mock_remove_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.get_all_gateways')
    def test_denied_when_enforcement_explicit_false(self, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('denied_explicit_false')
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            discoveryrotation_v1.PAMGatewayRemoveCommand().execute(params, gateway='some_gateway_uid')

        self.assertFalse(mock_get_all_gateways.called)
        self.assertFalse(mock_remove_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation_v1.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation_v1.utils.base64_url_encode')
    def test_allowed_when_enforcement_true(
            self, mock_base64_url_encode, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_enforcement('allowed')
        gateway = MagicMock(controllerUid=b'controller_uid', controllerName='pocbyuser')
        mock_get_all_gateways.return_value = [gateway]
        mock_base64_url_encode.return_value = 'gateway_uid'

        discoveryrotation_v1.PAMGatewayRemoveCommand().execute(params, gateway='gateway_uid')

        self.assertTrue(mock_remove_gateway.called)


if __name__ == '__main__':
    unittest.main()

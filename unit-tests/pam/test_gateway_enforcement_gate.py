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


# A real multi-key `booleans` payload (captured from a live account_summary
# response) — models a role with many unrelated PAM permissions granted,
# to confirm the key lookup isn't fooled by a "some true entries exist"
# shortcut and actually finds/omits allow_pam_gateway specifically.
_MIXED_ROLE_BOOLEANS_TEMPLATE = [
    {'key': 'send_breach_watch_events', 'value': True},
    {'key': 'allow_alternate_passwords', 'value': True},
    {'key': 'allow_pam_discovery', 'value': True},
    {'key': 'allow_pam_rotation', 'value': True},
    {'key': 'allow_configure_pam_cloud_connection_settings', 'value': True},
    {'key': 'restrict_mac_fingerprint', 'value': True},
    {'key': 'allow_launch_pam_on_cloud_connection', 'value': True},
    {'key': 'allow_configure_rbi', 'value': True},
    {'key': 'allow_launch_rbi', 'value': True},
    {'key': 'allow_secrets_manager', 'value': True},
    {'key': 'allow_launch_pam_tunnels', 'value': True},
    {'key': 'allow_configure_workflow_settings', 'value': True},
    {'key': 'allow_configure_uss_settings', 'value': True},
    {'key': 'allow_rotate_credentials', 'value': True},
    {'key': 'allow_view_kcm_recordings', 'value': True},
    {'key': 'allow_view_rbi_recordings', 'value': True},
    {'key': 'allow_configure_rotation_settings', 'value': True},
    {'key': 'allow_configure_pam_tunneling_settings', 'value': True},
    {'key': 'allow_can_edit_external_shares', 'value': True},
]


def _params_with_mixed_role(gateway_allowed):
    # type: (bool) -> MagicMock
    """A role holding ~19 unrelated PAM/vault permissions, with
    allow_pam_gateway either granted or omitted alongside them — the
    real-world "partial permissions" shape, as opposed to a single-key
    toy list."""
    params = MagicMock()
    booleans = list(_MIXED_ROLE_BOOLEANS_TEMPLATE)
    if gateway_allowed:
        booleans = booleans + [{'key': 'allow_pam_gateway', 'value': True}]
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


class TestMixedRolePermissions(unittest.TestCase):
    """Partial-permission / mixed-role coverage: a role holding many other
    PAM permissions must still be gated on allow_pam_gateway specifically,
    neither over-denying (other permissions present) nor over-allowing
    (mistaking "booleans list is non-empty" for "gateway is allowed")."""

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_create_denied_with_many_other_permissions_granted(
            self, mock_get_app_record, mock_create_gateway):
        params = _params_with_mixed_role(gateway_allowed=False)
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            PAMCreateGatewayCommand().execute(
                params, gateway_name='pocbyuser', ksm_app='PAM_application')

        self.assertFalse(mock_get_app_record.called)
        self.assertFalse(mock_create_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.create_gateway')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_ksm_app_display_info')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    def test_create_allowed_with_many_other_permissions_granted(
            self, mock_get_app_record, mock_get_ksm_app_display_info, mock_create_gateway):
        params = _params_with_mixed_role(gateway_allowed=True)
        mock_get_app_record.return_value = {'record_uid': 'app_uid'}
        mock_get_ksm_app_display_info.return_value = ('PAM_application', True, 'PAM_application (app_uid)')
        mock_create_gateway.return_value = 'US:one-time-token'

        PAMCreateGatewayCommand().execute(
            params, gateway_name='pocbyuser', ksm_app='PAM_application', return_value=True)

        self.assertTrue(mock_create_gateway.called)

    @patch('keepercommander.commands.discoveryrotation.gateway_helper.remove_gateway')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    def test_remove_denied_with_many_other_permissions_granted(
            self, mock_get_all_gateways, mock_remove_gateway):
        params = _params_with_mixed_role(gateway_allowed=False)
        with patch('sys.stdout', new_callable=io.StringIO) as stdout:
            PAMGatewayRemoveCommand().execute(params, gateway='some_gateway_uid')

        self.assertFalse(mock_get_all_gateways.called)
        self.assertFalse(mock_remove_gateway.called)
        self.assertIn('gateway management', stdout.getvalue().lower())


if __name__ == '__main__':
    unittest.main()

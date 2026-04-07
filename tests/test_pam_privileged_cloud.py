"""Tests for PAM Identity Provider CLI commands (KPC Track D)."""

import json
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.pam.pam_dto import (
    GatewayActionIdpInputs,
    GatewayActionIdpCreateUser,
    GatewayActionIdpDeleteUser,
    GatewayActionIdpAddUserToGroup,
    GatewayActionIdpRemoveUserFromGroup,
    GatewayActionIdpGroupList,
)

from keepercommander.commands.pam_cloud.pam_privileged_access import (
    resolve_pam_idp_config,
    VALID_CONFIG_TYPES,
    PAMPrivilegedAccessCommand,
    PAMAccessUserCommand,
    PAMAccessGroupCommand,
)

from keepercommander.error import CommandError


class TestGatewayActionIdpInputs(unittest.TestCase):
    """Test GatewayActionIdpInputs serialization."""

    def test_inputs_with_idp_config(self):
        """idpConfigUid included when different from configurationUid."""
        inputs = GatewayActionIdpInputs('config-123', 'azure-456', user='john')
        data = json.loads(inputs.toJSON())
        self.assertEqual(data['configurationUid'], 'config-123')
        self.assertEqual(data['idpConfigUid'], 'azure-456')
        self.assertEqual(data['user'], 'john')

    def test_inputs_self_managing(self):
        """idpConfigUid omitted when matching configurationUid."""
        inputs = GatewayActionIdpInputs('config-123', 'config-123', user='john')
        data = json.loads(inputs.toJSON())
        self.assertEqual(data['configurationUid'], 'config-123')
        self.assertNotIn('idpConfigUid', data)

    def test_inputs_no_idp(self):
        """idpConfigUid omitted when not provided."""
        inputs = GatewayActionIdpInputs('config-123', user='john')
        data = json.loads(inputs.toJSON())
        self.assertEqual(data['configurationUid'], 'config-123')
        self.assertNotIn('idpConfigUid', data)

    def test_inputs_none_values_excluded(self):
        """None kwargs are not included in serialization."""
        inputs = GatewayActionIdpInputs('config-123', user='john', password=None)
        data = json.loads(inputs.toJSON())
        self.assertNotIn('password', data)

    def test_inputs_with_all_fields(self):
        """All fields serialized correctly."""
        inputs = GatewayActionIdpInputs(
            'config-123', 'azure-456',
            user='john@contoso.com',
            displayName='John Doe',
            password='secret123',
            groupId='group-789',
        )
        data = json.loads(inputs.toJSON())
        self.assertEqual(data['user'], 'john@contoso.com')
        self.assertEqual(data['displayName'], 'John Doe')
        self.assertEqual(data['password'], 'secret123')
        self.assertEqual(data['groupId'], 'group-789')


class TestGatewayActionSubclasses(unittest.TestCase):
    """Test GatewayAction subclasses use correct RM action strings."""

    def _get_payload(self, action_class, **input_kwargs):
        inputs = GatewayActionIdpInputs('config-123', 'azure-456', **input_kwargs)
        action = action_class(inputs=inputs)
        return json.loads(action.toJSON())

    def test_create_user_action_string(self):
        payload = self._get_payload(GatewayActionIdpCreateUser, user='john')
        self.assertEqual(payload['action'], 'rm-create-user')

    def test_delete_user_action_string(self):
        payload = self._get_payload(GatewayActionIdpDeleteUser, user='john')
        self.assertEqual(payload['action'], 'rm-delete-user')

    def test_add_user_to_group_action_string(self):
        payload = self._get_payload(GatewayActionIdpAddUserToGroup,
                                    user='john', groupId='grp-1')
        self.assertEqual(payload['action'], 'rm-add-user-to-group')

    def test_remove_user_from_group_action_string(self):
        payload = self._get_payload(GatewayActionIdpRemoveUserFromGroup,
                                    user='john', groupId='grp-1')
        self.assertEqual(payload['action'], 'rm-remove-user-from-group')

    def test_group_list_action_string(self):
        payload = self._get_payload(GatewayActionIdpGroupList)
        self.assertEqual(payload['action'], 'rm-group-list')

    def test_all_actions_not_scheduled(self):
        """All IdP actions should be non-scheduled (synchronous)."""
        for cls in [GatewayActionIdpCreateUser, GatewayActionIdpDeleteUser,
                    GatewayActionIdpAddUserToGroup, GatewayActionIdpRemoveUserFromGroup,
                    GatewayActionIdpGroupList]:
            inputs = GatewayActionIdpInputs('config-123')
            action = cls(inputs=inputs)
            payload = json.loads(action.toJSON())
            self.assertFalse(payload['is_scheduled'],
                             f'{cls.__name__} should not be scheduled')

    def test_idp_config_uid_in_inputs(self):
        """idpConfigUid should be inside the inputs object, not top-level."""
        payload = self._get_payload(GatewayActionIdpCreateUser, user='john')
        self.assertIn('idpConfigUid', payload['inputs'])
        self.assertNotIn('idpConfigUid', payload)


class TestResolveIdpConfig(unittest.TestCase):
    """Test resolve_idp_config() helper."""

    def _make_mock_record(self, record_type, idp_uid=None):
        """Create a mock TypedRecord with an optional identityProviderUid custom field."""
        from keepercommander import vault
        record = MagicMock(spec=vault.TypedRecord)
        record.record_type = record_type

        custom_fields = []
        if idp_uid:
            field = MagicMock()
            field.type = 'text'
            field.label = 'identityProviderUid'
            field.get_external_value.return_value = iter([idp_uid])
            custom_fields.append(field)

        record.custom = custom_fields
        return record

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_self_managing_azure(self, mock_load):
        """Azure config without identityProviderUid returns self."""
        record = self._make_mock_record('pamAzureConfiguration')
        mock_load.return_value = record
        params = MagicMock()

        result = resolve_pam_idp_config(params, 'azure-123')
        self.assertEqual(result, 'azure-123')

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_cross_reference(self, mock_load):
        """Config with identityProviderUid returns the referenced UID."""
        net_record = self._make_mock_record('pamNetworkConfiguration', idp_uid='azure-456')
        azure_record = self._make_mock_record('pamAzureConfiguration')

        def load_side_effect(params, uid):
            if uid == 'net-123':
                return net_record
            elif uid == 'azure-456':
                return azure_record
            return None

        mock_load.side_effect = load_side_effect
        params = MagicMock()

        result = resolve_pam_idp_config(params, 'net-123')
        self.assertEqual(result, 'azure-456')

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_config_not_found(self, mock_load):
        """Raises error when config UID doesn't exist."""
        mock_load.return_value = None
        params = MagicMock()

        with self.assertRaises(CommandError):
            resolve_pam_idp_config(params, 'nonexistent')

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_non_idp_type_without_ref(self, mock_load):
        """Raises error for a non-IdP config type without identityProviderUid."""
        record = self._make_mock_record('pamNetworkConfiguration')
        mock_load.return_value = record
        params = MagicMock()

        with self.assertRaises(CommandError) as ctx:
            resolve_pam_idp_config(params, 'net-123')
        self.assertIn('No Identity Provider available', str(ctx.exception))

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_referenced_config_not_found(self, mock_load):
        """Raises error when referenced IdP config doesn't exist."""
        net_record = self._make_mock_record('pamNetworkConfiguration', idp_uid='missing-456')

        def load_side_effect(params, uid):
            if uid == 'net-123':
                return net_record
            return None

        mock_load.side_effect = load_side_effect
        params = MagicMock()

        with self.assertRaises(CommandError) as ctx:
            resolve_pam_idp_config(params, 'net-123')
        self.assertIn('not found', str(ctx.exception))

    @patch('keepercommander.commands.pam_cloud.pam_idp.vault.KeeperRecord.load')
    def test_referenced_config_invalid_type(self, mock_load):
        """Raises error when a referenced config type doesn't support IdP."""
        net_record = self._make_mock_record('pamNetworkConfiguration', idp_uid='other-456')
        other_record = self._make_mock_record('pamLocalConfiguration')

        def load_side_effect(params, uid):
            if uid == 'net-123':
                return net_record
            elif uid == 'other-456':
                return other_record
            return None

        mock_load.side_effect = load_side_effect
        params = MagicMock()

        with self.assertRaises(CommandError) as ctx:
            resolve_pam_idp_config(params, 'net-123')
        self.assertIn('does not support identity provider', str(ctx.exception))


class TestValidIdpConfigTypes(unittest.TestCase):
    """Test VALID_IDP_CONFIG_TYPES constant."""

    def test_azure_is_valid(self):
        self.assertIn('pamAzureConfiguration', VALID_CONFIG_TYPES)

    def test_okta_is_valid(self):
        self.assertIn('pamOktaConfiguration', VALID_CONFIG_TYPES)

    def test_domain_is_valid(self):
        self.assertIn('pamDomainConfiguration', VALID_CONFIG_TYPES)

    def test_aws_is_valid(self):
        self.assertIn('pamAwsConfiguration', VALID_CONFIG_TYPES)

    def test_gcp_is_valid(self):
        self.assertIn('pamGcpConfiguration', VALID_CONFIG_TYPES)

    def test_network_is_not_valid(self):
        self.assertNotIn('pamNetworkConfiguration', VALID_CONFIG_TYPES)


class TestCommandGroupStructure(unittest.TestCase):
    """Test command group hierarchy."""

    def test_idp_has_user_and_group_subgroups(self):
        cmd = PAMPrivilegedAccessCommand()
        self.assertIn('user', cmd.subcommands)
        self.assertIn('group', cmd.subcommands)

    def test_user_has_provision_deprovision_list(self):
        cmd = PAMAccessUserCommand()
        self.assertIn('provision', cmd.subcommands)
        self.assertIn('deprovision', cmd.subcommands)
        self.assertIn('list', cmd.subcommands)

    def test_group_has_add_remove_list(self):
        cmd = PAMAccessGroupCommand()
        self.assertIn('add-user', cmd.subcommands)
        self.assertIn('remove-user', cmd.subcommands)
        self.assertIn('list', cmd.subcommands)


if __name__ == '__main__':
    unittest.main()
"""
KC-1035: Atlassian Onboarding Project — Test Suite

Test levels:
  Level 1 - Unit tests (no external deps, pure logic)
  Level 2 - Mocked integration tests (mock Gateway + vault APIs)
  Level 3 - E2E tests (real Gateway + AD + vault, requires config)

Run specific levels:
  pytest tests/test_credential_provision_kc1035.py -m unit
  pytest tests/test_credential_provision_kc1035.py -m integration
  pytest tests/test_credential_provision_kc1035.py -m e2e
"""

import json
import os
import pytest
from unittest import TestCase, mock
from unittest.mock import MagicMock, patch, PropertyMock

from keepercommander.commands.credential_provision import (
    CredentialProvisionCommand,
    ProvisioningState,
    resolve_username_template,
)
from keepercommander.commands.pam.pam_dto import (
    GatewayAction,
    GatewayActionRmCreateUser,
    GatewayActionRmCreateUserInputs,
    GatewayActionRmAddUserToGroup,
    GatewayActionRmAddUserToGroupInputs,
    GatewayActionRmDeleteUser,
    GatewayActionRmDeleteUserInputs,
)


# =============================================================================
# Level 1: Unit Tests — Pure logic, no external dependencies
# =============================================================================

@pytest.mark.unit
class TestUsernameTemplate(TestCase):
    """Test the username template engine."""

    def test_basic_template(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        result = resolve_username_template('{first_initial}{last_name}.adm', user)
        self.assertEqual(result, 'fdias.adm')

    def test_first_name(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        self.assertEqual(resolve_username_template('{first_name}', user), 'felipe')

    def test_last_name(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        self.assertEqual(resolve_username_template('{last_name}', user), 'dias')

    def test_initials(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        self.assertEqual(resolve_username_template('{first_initial}', user), 'f')
        self.assertEqual(resolve_username_template('{last_initial}', user), 'd')

    def test_email_prefix(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        self.assertEqual(resolve_username_template('{email_prefix}', user), 'fdias')

    def test_output_is_lowercase(self):
        user = {'first_name': 'FELIPE', 'last_name': 'DIAS', 'personal_email': 'FDIAS@ATLASSIAN.COM'}
        self.assertEqual(resolve_username_template('{first_initial}{last_name}.adm', user), 'fdias.adm')

    def test_dn_template(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        result = resolve_username_template(
            'CN={first_initial}{last_name}.adm,OU=DomainAdmins,DC=atlassian,DC=com', user
        )
        self.assertEqual(result, 'cn=fdias.adm,ou=domainadmins,dc=atlassian,dc=com')

    def test_hyphenated_name(self):
        user = {'first_name': 'Mary-Jane', 'last_name': "O'Brien", 'personal_email': 'mj@test.com'}
        result = resolve_username_template('{first_initial}{last_name}.adm', user)
        self.assertEqual(result, "mo'brien.adm")

    def test_empty_first_name(self):
        user = {'first_name': '', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        result = resolve_username_template('{first_initial}{last_name}.adm', user)
        self.assertEqual(result, 'dias.adm')

    def test_missing_fields(self):
        user = {}
        result = resolve_username_template('{first_initial}{last_name}', user)
        self.assertEqual(result, '')

    def test_no_template_variables(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@atlassian.com'}
        result = resolve_username_template('static-username', user)
        self.assertEqual(result, 'static-username')

    def test_email_without_at(self):
        user = {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias'}
        result = resolve_username_template('{email_prefix}', user)
        self.assertEqual(result, 'fdias')


@pytest.mark.unit
class TestGatewayDTOs(TestCase):
    """Test Gateway action DTO serialization."""

    def test_rm_create_user_json(self):
        inputs = GatewayActionRmCreateUserInputs(
            configuration_uid='config-123',
            user='CN=fdias.adm,OU=DomainAdmins,DC=test,DC=com',
            password='SecureP@ss1',
        )
        action = GatewayActionRmCreateUser(inputs=inputs, gateway_destination='gw-789')
        data = json.loads(action.toJSON())

        self.assertEqual(data['action'], 'rm-create-user')
        self.assertFalse(data['is_scheduled'])
        self.assertEqual(data['inputs']['configurationUid'], 'config-123')
        self.assertEqual(data['inputs']['user'], 'CN=fdias.adm,OU=DomainAdmins,DC=test,DC=com')
        self.assertEqual(data['inputs']['password'], 'SecureP@ss1')

    def test_rm_create_user_optional_fields(self):
        """Optional fields should not be present when not provided."""
        inputs = GatewayActionRmCreateUserInputs(
            configuration_uid='config-123',
            user='fdias.adm',
        )
        data = json.loads(GatewayActionRmCreateUser(inputs=inputs).toJSON())
        self.assertNotIn('password', data['inputs'])
        self.assertNotIn('resourceUid', data['inputs'])
        self.assertNotIn('meta', data['inputs'])

    def test_rm_add_user_to_group_json(self):
        inputs = GatewayActionRmAddUserToGroupInputs(
            configuration_uid='config-123',
            user='fdias.adm',
            group_id='Domain Admins',
        )
        action = GatewayActionRmAddUserToGroup(inputs=inputs, gateway_destination='gw-789')
        data = json.loads(action.toJSON())

        self.assertEqual(data['action'], 'rm-add-user-to-group')
        self.assertEqual(data['inputs']['groupId'], 'Domain Admins')

    def test_rm_delete_user_json(self):
        inputs = GatewayActionRmDeleteUserInputs(
            configuration_uid='config-123',
            user='fdias.adm',
        )
        action = GatewayActionRmDeleteUser(inputs=inputs)
        data = json.loads(action.toJSON())

        self.assertEqual(data['action'], 'rm-delete-user')
        self.assertEqual(data['inputs']['user'], 'fdias.adm')

    def test_conversation_id_generation(self):
        cid = GatewayAction.generate_conversation_id()
        self.assertIsInstance(cid, str)
        self.assertGreater(len(cid), 10)


@pytest.mark.unit
class TestProvisioningState(TestCase):
    """Test ProvisioningState tracks AD creation for rollback."""

    def test_initial_state(self):
        state = ProvisioningState()
        self.assertIsNone(state.pam_user_uid)
        self.assertFalse(state.ad_user_created)
        self.assertIsNone(state.ad_username)
        self.assertIsNone(state.ad_config_uid)
        self.assertIsNone(state.ad_gateway_uid)

    def test_ad_state_tracking(self):
        state = ProvisioningState()
        state.ad_user_created = True
        state.ad_username = 'fdias.adm'
        state.ad_config_uid = 'config-123'
        state.ad_gateway_uid = 'gw-456'
        self.assertTrue(state.ad_user_created)
        self.assertEqual(state.ad_username, 'fdias.adm')


@pytest.mark.unit
class TestValidation(TestCase):
    """Test YAML config validation changes."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = MagicMock()

    def test_delivery_valid(self):
        delivery = {'share_to': 'fdias@atlassian.com'}
        errors = self.cmd._validate_delivery_section(delivery)
        self.assertEqual(errors, [])

    def test_delivery_missing_share_to(self):
        delivery = {}
        errors = self.cmd._validate_delivery_section(delivery)
        self.assertTrue(any('share_to' in e for e in errors))

    def test_delivery_invalid_email(self):
        delivery = {'share_to': 'not-an-email'}
        errors = self.cmd._validate_delivery_section(delivery)
        self.assertTrue(any('valid email' in e for e in errors))

    def test_account_username_template_accepted(self):
        account = {'username_template': '{first_initial}{last_name}.adm', 'pam_config_uid': 'xxx'}
        errors = self.cmd._validate_account_section(account)
        username_errors = [e for e in errors if 'username' in e.lower()]
        self.assertEqual(username_errors, [])

    def test_account_neither_username_nor_template(self):
        account = {'pam_config_uid': 'xxx'}
        errors = self.cmd._validate_account_section(account)
        self.assertTrue(any('username' in e for e in errors))

    def test_email_section_optional_with_delivery(self):
        """Email section should not be required when delivery section is present."""
        config = {
            'user': {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@test.com'},
            'account': {'username': 'fdias.adm', 'pam_config_uid': 'xxx'},
            'rotation': {'schedule': '0 0 3 * * ?', 'password_complexity': '24,4,4,4,4'},
            'delivery': {'share_to': 'fdias@test.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        email_errors = [e for e in errors if e.startswith('email.')]
        self.assertEqual(email_errors, [])

    def test_no_delivery_no_email_valid(self):
        """No delivery and no email should be valid — record created but not shared."""
        config = {
            'user': {'first_name': 'Felipe', 'last_name': 'Dias', 'personal_email': 'fdias@test.com'},
            'account': {'username': 'fdias.adm', 'pam_config_uid': 'xxx'},
            'rotation': {'schedule': '0 0 3 * * ?', 'password_complexity': '24,4,4,4,4'},
        }
        errors = self.cmd._validate_config(self.params, config)
        delivery_errors = [e for e in errors if 'delivery' in e.lower() or 'email' in e.lower()]
        self.assertEqual(delivery_errors, [])


# =============================================================================
# Level 2: Mocked Integration Tests — Mock Gateway + vault APIs
# =============================================================================

@pytest.mark.integration
class TestDirectShare(TestCase):
    """Test direct share delivery with mocked ShareRecordCommand."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    @patch('keepercommander.commands.credential_provision.ShareRecordCommand')
    @patch('keepercommander.commands.credential_provision.api')
    def test_share_directly_success(self, mock_api, mock_share_cmd):
        mock_rq = MagicMock()
        mock_share_cmd.prep_request.return_value = mock_rq

        params = MagicMock()
        config = {
            'delivery': {
                'method': 'direct_share',
                'share_to': 'fdias@atlassian.com',
                'permissions': {'can_edit': False, 'can_share': False},
            }
        }

        result = self.cmd._share_directly('pam-uid-123', config, params)

        self.assertTrue(result)
        mock_api.sync_down.assert_called_once_with(params)
        mock_share_cmd.prep_request.assert_called_once()
        mock_share_cmd.send_requests.assert_called_once()

        # Verify the kwargs passed to prep_request
        call_kwargs = mock_share_cmd.prep_request.call_args[0][1]
        self.assertEqual(call_kwargs['record'], 'pam-uid-123')
        self.assertEqual(call_kwargs['email'], ['fdias@atlassian.com'])
        self.assertEqual(call_kwargs['action'], 'grant')
        self.assertFalse(call_kwargs['can_edit'])
        self.assertFalse(call_kwargs['can_share'])

    @patch('keepercommander.commands.credential_provision.ShareRecordCommand')
    @patch('keepercommander.commands.credential_provision.api')
    def test_share_directly_invitation_sent(self, mock_api, mock_share_cmd):
        """When prep_request returns None, invitation was sent (vault not yet accepted)."""
        mock_share_cmd.prep_request.return_value = None

        params = MagicMock()
        config = {
            'delivery': {
                'method': 'direct_share',
                'share_to': 'newuser@atlassian.com',
            }
        }

        result = self.cmd._share_directly('pam-uid-123', config, params)
        self.assertTrue(result)
        mock_share_cmd.send_requests.assert_not_called()

    @patch('keepercommander.commands.credential_provision.ShareRecordCommand')
    @patch('keepercommander.commands.credential_provision.api')
    def test_share_directly_failure_non_fatal(self, mock_api, mock_share_cmd):
        """Share failure should return False, not raise."""
        mock_share_cmd.prep_request.side_effect = Exception('Public key not found')

        params = MagicMock()
        config = {'delivery': {'share_to': 'bad@test.com'}}

        result = self.cmd._share_directly('pam-uid-123', config, params)
        self.assertFalse(result)


@pytest.mark.integration
class TestADCreationViaGateway(TestCase):
    """Test AD user creation with mocked Gateway communication."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        # Create a fake 32-byte AES key for encryption tests
        self.fake_record_key = os.urandom(32)

    def _mock_params_with_record_cache(self, config_uid='config-123'):
        params = MagicMock()
        params.record_cache = {config_uid: {'record_key_unencrypted': self.fake_record_key}}
        return params

    @patch('keepercommander.commands.credential_provision.get_response_payload')
    @patch('keepercommander.commands.credential_provision.router_send_action_to_gateway')
    def test_create_ad_user_success(self, mock_router_send, mock_get_payload):
        mock_router_send.return_value = {'response': 'ok'}
        mock_get_payload.return_value = {'data': {'success': True, 'configurationUid': 'config-123'}}

        params = self._mock_params_with_record_cache()
        state = ProvisioningState()
        config = {
            'account': {
                'username': 'fdias.adm',
                'pam_config_uid': 'config-123',
                'distinguished_name': 'CN=fdias.adm,OU=DomainAdmins,DC=test,DC=com',
            }
        }

        with patch.object(self.cmd, '_get_gateway_uid_for_config', return_value='gw-456'):
            result = self.cmd._create_ad_user_via_gateway(config, 'P@ssw0rd', params, state)

        self.assertTrue(result)
        self.assertTrue(state.ad_user_created)
        self.assertEqual(state.ad_username, 'fdias.adm')
        self.assertEqual(state.ad_config_uid, 'config-123')
        self.assertEqual(state.ad_gateway_uid, 'gw-456')

    @patch('keepercommander.commands.credential_provision.get_response_payload')
    @patch('keepercommander.commands.credential_provision.router_send_action_to_gateway')
    def test_create_ad_user_already_exists(self, mock_router_send, mock_get_payload):
        mock_router_send.return_value = {'response': 'ok'}
        mock_get_payload.return_value = {'data': {'success': False, 'error': 'User already exists'}}

        params = self._mock_params_with_record_cache()
        state = ProvisioningState()
        config = {
            'account': {
                'username': 'fdias.adm',
                'pam_config_uid': 'config-123',
                'distinguished_name': 'CN=fdias.adm,OU=DomainAdmins,DC=test,DC=com',
            }
        }

        with patch.object(self.cmd, '_get_gateway_uid_for_config', return_value='gw-456'):
            from keepercommander.error import CommandError
            with self.assertRaises(CommandError) as ctx:
                self.cmd._create_ad_user_via_gateway(config, 'P@ssw0rd', params, state)

        self.assertIn('User already exists', str(ctx.exception))
        self.assertFalse(state.ad_user_created)

    @patch('keepercommander.commands.credential_provision.router_send_action_to_gateway')
    def test_create_ad_user_gateway_offline(self, mock_router_send):
        params = MagicMock()
        state = ProvisioningState()
        config = {
            'account': {
                'username': 'fdias.adm',
                'pam_config_uid': 'config-123',
            }
        }

        with patch.object(self.cmd, '_get_gateway_uid_for_config', return_value=None):
            from keepercommander.error import CommandError
            with self.assertRaises(CommandError) as ctx:
                self.cmd._create_ad_user_via_gateway(config, 'P@ssw0rd', params, state)

        self.assertIn('No connected Gateway', str(ctx.exception))


@pytest.mark.integration
class TestRollback(TestCase):
    """Test rollback handles AD + PAM User cleanup in LIFO order."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    @patch('keepercommander.commands.credential_provision.api')
    def test_rollback_pam_user_only(self, mock_api):
        """Rollback with only PAM User created (no AD user)."""
        state = ProvisioningState()
        state.pam_user_uid = 'pam-123'

        params = MagicMock()
        self.cmd._rollback(state, params)

        mock_api.delete_record.assert_called_once_with(params, 'pam-123')

    @patch('keepercommander.commands.credential_provision.api')
    def test_rollback_ad_and_pam_user(self, mock_api):
        """Rollback with both AD user and PAM User created — LIFO order."""
        state = ProvisioningState()
        state.pam_user_uid = 'pam-123'
        state.ad_user_created = True
        state.ad_username = 'fdias.adm'
        state.ad_config_uid = 'config-123'
        state.ad_gateway_uid = 'gw-456'

        params = MagicMock()

        with patch.object(self.cmd, '_delete_ad_user_via_gateway') as mock_ad_delete:
            self.cmd._rollback(state, params)

        # PAM User deleted first (LIFO)
        mock_api.delete_record.assert_called_once_with(params, 'pam-123')
        # AD user deleted second
        mock_ad_delete.assert_called_once_with(state, params)

    @patch('keepercommander.commands.credential_provision.api')
    def test_rollback_ad_only(self, mock_api):
        """Rollback with AD user created but PAM User creation failed."""
        state = ProvisioningState()
        state.ad_user_created = True
        state.ad_username = 'fdias.adm'
        state.ad_config_uid = 'config-123'
        state.ad_gateway_uid = 'gw-456'

        params = MagicMock()

        with patch.object(self.cmd, '_delete_ad_user_via_gateway') as mock_ad_delete:
            self.cmd._rollback(state, params)

        mock_api.delete_record.assert_not_called()
        mock_ad_delete.assert_called_once()

    @patch('keepercommander.commands.credential_provision.api')
    def test_rollback_nothing_created(self, mock_api):
        """Rollback with nothing created — should not fail."""
        state = ProvisioningState()
        params = MagicMock()

        with patch.object(self.cmd, '_delete_ad_user_via_gateway') as mock_ad_delete:
            self.cmd._rollback(state, params)

        mock_api.delete_record.assert_not_called()
        mock_ad_delete.assert_not_called()


# =============================================================================
# Level 3: E2E Tests — Real Gateway + AD + Vault
# Requires: vault.json config, running Gateway, AD access, Okta/SCIM
# =============================================================================

@pytest.mark.e2e
@pytest.mark.skip(reason="Requires real environment — run manually with: pytest -m e2e --no-header -v")
class TestE2EProvisioningFlow(TestCase):
    """
    End-to-end test against real infrastructure.

    Prerequisites:
    - Commander config at tests/vault.json (service vault credentials)
    - PAM Gateway running and connected
    - AD accessible from Gateway
    - Target user vault exists (SCIM provisioned)

    Setup:
    1. Create tests/e2e_config.json with:
       {
         "pam_config_uid": "<your PAM config UID>",
         "target_user_email": "<existing Keeper user email>",
         "ad_base_dn": "OU=TestUsers,DC=yourdomain,DC=com",
         "ad_groups": ["TestGroup1"]
       }
    2. Run: pytest tests/test_credential_provision_kc1035.py -m e2e -v
    """

    params = None
    e2e_config = None
    created_resources = []

    @classmethod
    def setUpClass(cls):
        import os
        from data_config import read_config_file
        from keepercommander.params import KeeperParams
        from keepercommander import api

        cls.params = KeeperParams()
        read_config_file(cls.params, 'vault.json')
        api.login(cls.params)

        config_path = os.path.join(os.path.dirname(__file__), 'e2e_config.json')
        with open(config_path, 'r') as f:
            cls.e2e_config = json.load(f)

    @classmethod
    def tearDownClass(cls):
        from keepercommander import cli
        # Cleanup created resources
        for resource in cls.created_resources:
            try:
                if resource['type'] == 'record':
                    from keepercommander import api
                    api.delete_record(cls.params, resource['uid'])
            except Exception as e:
                print(f"Cleanup failed for {resource}: {e}")
        cli.do_command(cls.params, 'logout')

    def test_01_direct_share_with_ad_creation(self):
        """Full flow: create AD user → PAM User → rotation → direct share."""
        import base64
        import yaml

        config_yaml = {
            'user': {
                'first_name': 'Test',
                'last_name': 'User',
                'personal_email': self.e2e_config['target_user_email'],
            },
            'account': {
                'username_template': '{first_initial}{last_name}.adm.test',
                'pam_config_uid': self.e2e_config['pam_config_uid'],
                'distinguished_name': f'CN={{username}},{self.e2e_config["ad_base_dn"]}',
                'ad_groups': self.e2e_config.get('ad_groups', []),
            },
            'vault': {
                'folder': 'KC-1035-E2E-Test',
            },
            'pam': {
                'rotation': {
                    'schedule': '0 0 3 * * ?',
                    'password_complexity': '24,4,4,4,4',
                },
            },
            'delivery': {
                'method': 'direct_share',
                'share_to': self.e2e_config['target_user_email'],
                'permissions': {'can_edit': False, 'can_share': False},
            },
        }

        yaml_str = yaml.dump(config_yaml)
        b64_config = base64.b64encode(yaml_str.encode()).decode()

        cmd = CredentialProvisionCommand()
        cmd.execute(self.params, config_base64=b64_config, output='json')

    def test_02_dry_run(self):
        """Dry run should validate without creating anything."""
        import base64
        import yaml

        config_yaml = {
            'user': {
                'first_name': 'DryRun',
                'last_name': 'Test',
                'personal_email': self.e2e_config['target_user_email'],
            },
            'account': {
                'username_template': '{first_initial}{last_name}.adm.dryrun',
                'pam_config_uid': self.e2e_config['pam_config_uid'],
                'distinguished_name': f'CN={{username}},{self.e2e_config["ad_base_dn"]}',
            },
            'pam': {
                'rotation': {
                    'schedule': '0 0 3 * * ?',
                    'password_complexity': '24,4,4,4,4',
                },
            },
            'delivery': {
                'method': 'direct_share',
                'share_to': self.e2e_config['target_user_email'],
            },
        }

        yaml_str = yaml.dump(config_yaml)
        b64_config = base64.b64encode(yaml_str.encode()).decode()

        cmd = CredentialProvisionCommand()
        # Should not raise
        cmd.execute(self.params, config_base64=b64_config, dry_run=True, output='json')

    def test_03_duplicate_detection(self):
        """Running the same config twice should fail on duplicate check."""
        # This test depends on test_01 having run first
        pass  # Implement after confirming test_01 works

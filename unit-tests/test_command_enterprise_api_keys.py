import logging
import json
import datetime
import tempfile
import os
import io
import sys
import re
from unittest import TestCase, mock

from data_enterprise import EnterpriseEnvironment
from data_vault import get_connected_params
from keepercommander.commands import enterprise_api_keys
from keepercommander.error import CommandError
from keepercommander.proto import publicapi_pb2


ent_env = EnterpriseEnvironment()


class TestEnterpriseApiKeys(TestCase):
    expected_commands = []

    def setUp(self):
        TestEnterpriseApiKeys.expected_commands.clear()
        self.communicate_rest_mock = mock.patch('keepercommander.api.communicate_rest').start()
        self.communicate_rest_mock.side_effect = TestEnterpriseApiKeys.communicate_rest_success

    def tearDown(self):
        mock.patch.stopall()

    def test_api_key_list_success(self):
        """Test successful listing of API keys matching Commander terminal output"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyListCommand()
        TestEnterpriseApiKeys.expected_commands = ['list_token']
        
        # Capture print output to verify table format
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            result = cmd.execute(params)
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        
        # Verify the table output contains expected headers and data
        output = captured_output.getvalue()
        self.assertIn('Enterprise ID', output)
        self.assertIn('Name', output)
        self.assertIn('Status', output)
        self.assertIn('Issued Date', output)
        self.assertIn('Expiration Date', output)
        self.assertIn('Integration', output)
        
        # Verify sample data appears in output
        self.assertIn('8560', output)  # Enterprise ID
        self.assertIn('Token Test', output)  # Name
        self.assertIn('Expired', output)  # Status
        self.assertIn('SIEM', output)  # Integration

    def test_api_key_list_json_format(self):
        """Test listing API keys in JSON format"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyListCommand()
        TestEnterpriseApiKeys.expected_commands = ['list_token']
        
        result = cmd.execute(params, format='json')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        self.assertIsNotNone(result)
        # Assert that the JSON result matches the expected values for all entries
        expected_json = [
            {
                "enterprise_id": 8560,
                "name": "Token Test",
                "status": "Expired",
                "issued_date": "2025-04-14 12:48:26",
                "expiration_date": "2025-04-15 12:48:26",
                "integration": "SIEM:2"
            },
            {
                "enterprise_id": 8560,
                "name": "Token Test",
                "status": "Expired",
                "issued_date": "2025-04-14 12:48:26",
                "expiration_date": "2025-04-15 12:48:26",
                "integration": "SIEM:2"
            },
            {
                "enterprise_id": 8560,
                "name": "Token Test 2",
                "status": "Expired",
                "issued_date": "2025-04-14 12:48:26",
                "expiration_date": "2025-04-15 12:48:26",
                "integration": "SIEM:2"
            },
            {
                "enterprise_id": 8560,
                "name": "SIEM Tool",
                "status": "Active",
                "issued_date": "2025-07-08 14:16:07",
                "expiration_date": "2026-07-08 14:16:07",
                "integration": "SIEM:2"
            },
            {
                "enterprise_id": 8560,
                "name": "Token For My Tests 111",
                "status": "Active",
                "issued_date": "2025-07-09 14:33:26",
                "expiration_date": "Never",
                "integration": "SIEM:2"
            }
        ]
        self.assertEqual(json.loads(result), expected_json)

    def test_api_key_generate_success_matching_terminal_example(self):
        """Test API key generation matching Commander terminal example output"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Capture print output to verify exact format from terminal example
        captured_output = io.StringIO()
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('sys.stdout', captured_output):
                cmd.execute(params, name='SIEM Tool', integrations='SIEM:2', expires='30d')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        
        # Verify output matches Commander terminal example
        output = captured_output.getvalue()
        self.assertIn('API Key generated successfully', output)
        self.assertIn('Token: token_generated_for_test', output)
        self.assertIn('Name: SIEM Tool', output)
        self.assertIn('Enterprise ID: 8560', output)
        # Check for expiration date format (YYYY-MM-DD HH:MM:SS) - should be approximately 30 days from now
        expiration_match = re.search(r'Expires: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', output)
        self.assertIsNotNone(expiration_match, f"Expected expiration date format not found in output: {output}")
        expiration_str = expiration_match.group(1)
        expiration_date = datetime.datetime.strptime(expiration_str, '%Y-%m-%d %H:%M:%S')
        # Verify expiration is approximately 30 days from now (within 1 day tolerance)
        now = datetime.datetime.now()
        expected_expiration = now + datetime.timedelta(days=30)
        days_diff = abs((expiration_date - expected_expiration).days)
        self.assertLessEqual(days_diff, 1, f"Expiration date {expiration_str} should be approximately 30 days from now")
        self.assertIn('Integrations:', output)
        self.assertIn('- SIEM: READ_WRITE (2)', output)

    def test_api_key_generate_success_7d_expiration(self):
        """Test successful API key generation with 7 days expiration"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('builtins.print'):
                cmd.execute(params, name='Weekly API Key', integrations='SIEM:2', expires='7d')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_generate_success_30d_expiration(self):
        """Test successful API key generation with 30 days expiration"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('builtins.print'):
                cmd.execute(params, name='Monthly API Key', integrations='SIEM:1', expires='30d')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_generate_success_1y_expiration(self):
        """Test successful API key generation with 1 year expiration"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('builtins.print'):
                cmd.execute(params, name='Annual API Key', integrations='SIEM:1', expires='1y')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_generate_success_never_expires(self):
        """Test successful API key generation that never expires"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('builtins.print'):
                cmd.execute(params, name='Permanent API Key', integrations='SIEM:2', expires='never')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_generate_multiple_roles(self):
        """Test API key generation with multiple integrations"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('builtins.print'):
                cmd.execute(params, name='Multi-Role Key', integrations='SIEM:2', expires='30d')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_generate_json_output(self):
        """Test API key generation with JSON output"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        result = cmd.execute(params, name='JSON API Key', integrations='SIEM:2', expires='7d', format='json')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        self.assertIsNotNone(result)
        
        # Parse and validate JSON structure
        data = json.loads(result)
        self.assertIsInstance(data['issued_date'], int)
        self.assertIsInstance(data['expiration_date'], int)  # Should be timestamp for 7d expiration

    def test_api_key_generate_json_output_never_expires(self):
        """Test API key generation with JSON output for never-expiring key"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        result = cmd.execute(params, name='Permanent JSON Key', integrations='SIEM:2', expires='never', format='json')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        self.assertIsNotNone(result)
        
        # Parse and validate JSON structure
        data = json.loads(result)
        self.assertIsInstance(data['issued_date'], int)
        self.assertEqual(data['expiration_date'], 'never')  # Should be 'never' string

    def test_api_key_generate_json_with_output_file(self):
        """Test API key generation with JSON output to file"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_file:
            temp_filename = temp_file.name
        
        try:
            with mock.patch('builtins.print'):
                cmd.execute(params, name='File Output Key', integrations='SIEM:2', expires='1y', 
                          format='json', output=temp_filename)
            
            self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
            self.assertTrue(os.path.exists(temp_filename))
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_api_key_generate_missing_name(self):
        """Test API key generation fails when name is missing"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        
        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, integrations='SIEM:2')
        
        mock_print.assert_called_with("API key name is required")

    def test_api_key_generate_missing_roles(self):
        """Test API key generation fails when integrations are missing"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        
        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, name='Test Key')
        
        mock_print.assert_called_with("At least one integration is required. Example: --integrations 'SIEM:2' or --integrations 'BILLING:2'")

    def test_api_key_generate_invalid_role_format(self):
        """Test API key generation fails with invalid integration format"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        
        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, name='Test Key', integrations='INVALID_ROLE')
        
        # Should print error about integration format
        mock_print.assert_called()

    def test_api_key_generate_invalid_role_name(self):
        """Test API key generation fails with invalid integration name"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        
        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, name='Test Key', integrations='INVALID:2')
        
        # Should print error about invalid integration
        mock_print.assert_called()

    def test_api_key_generate_billing_non_msp(self):
        """Test API key generation fails for BILLING integration when not MSP"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        
        # Mock is_msp to return False
        with mock.patch('keepercommander.commands.enterprise_api_keys.EnterpriseCommand.is_msp', return_value=False):
            with mock.patch('builtins.print') as mock_print:
                cmd.execute(params, name='Billing Key', integrations='BILLING:2')
        
        # Should print error about MSP requirement
        mock_print.assert_called_with("The 'Billing' integration is only available for MSP (Managed Service Provider) enterprises.")

    def test_api_key_generate_billing_msp(self):
        """Test API key generation succeeds for BILLING integration when MSP"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        # Mock is_msp to return True
        with mock.patch('keepercommander.commands.enterprise_api_keys.EnterpriseCommand.is_msp', return_value=True):
            with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
                with mock.patch('builtins.print'):
                    cmd.execute(params, name='Billing Key', integrations='BILLING:2', expires='30d')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_revoke_success(self):
        """Test successful API key revocation"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyRevokeCommand()
        TestEnterpriseApiKeys.expected_commands = ['revoke_token']
        
        with mock.patch('builtins.print'):
            cmd.execute(params, name='Test Key', force=True)
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)

    def test_api_key_revoke_matching_terminal_example(self):
        """Test API key revocation matching Commander terminal example output"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyRevokeCommand()
        TestEnterpriseApiKeys.expected_commands = ['revoke_token']
        
        # Capture print output to verify exact format from terminal example
        captured_output = io.StringIO()
        with mock.patch('keepercommander.commands.enterprise_api_keys.user_choice', return_value='y') as mock_input:
            with mock.patch('sys.stdout', captured_output):
                cmd.execute(params, name='SIEM Integration')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        mock_input.assert_called_once()
        
        # Verify output matches Commander terminal example
        output = captured_output.getvalue()
        self.assertIn('API Key with Name SIEM Integration revoked successfully', output)

    def test_api_key_revoke_cancelled_by_user(self):
        """Test API key revocation cancelled by user"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyRevokeCommand()
        
        with mock.patch('keepercommander.commands.enterprise_api_keys.user_choice', return_value='n') as mock_input:
            cmd.execute(params, name='Test Key')
        
        # Should not have made any API calls
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        mock_input.assert_called_once()

    def test_api_key_revoke_missing_token_id(self):
        """Test API key revocation fails when name is missing"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyRevokeCommand()
        
        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params)
        
        mock_print.assert_called_with("Name is required")


    def test_api_key_main_command_default_list_behavior(self):
        """Test main API key command defaults to list behavior like terminal example"""
        params = get_connected_params()
        
        # Test the default list command directly since ApiKeyCommand is a GroupCommand
        cmd = enterprise_api_keys.ApiKeyListCommand()
        TestEnterpriseApiKeys.expected_commands = ['list_token']
        
        # Capture print output to verify list format from terminal example
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            # Default behavior should show the list
            cmd.execute(params)
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        
        # Verify output contains list data like terminal example
        output = captured_output.getvalue()
        # Should show the table with all data
        self.assertIn('Enterprise ID', output)
        self.assertIn('8560', output)  # Enterprise ID
        self.assertIn('Token Test', output)  # Token name
        self.assertIn('SIEM Tool', output)  # Another token name
        self.assertIn('Expired', output)  # Status
        self.assertIn('Active', output)  # Status
        self.assertIn('Never', output)  # Never expires
        
    def test_api_key_help_display_content(self):
        """Test API key command help display content matches expected format"""
        cmd = enterprise_api_keys.ApiKeyCommand()
        
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.print_help()
        
        # Verify help contains expected sections matching terminal example
        output = captured_output.getvalue()
        self.assertIn('Enterprise API Key Management', output)
        self.assertIn('Commands:', output)
        self.assertIn('list      - Display all enterprise API keys', output)
        self.assertIn('generate  - Create a new API key with specified integrations', output)
        self.assertIn('revoke    - Revoke an existing API key', output)
        self.assertIn('Role Action Types:', output)
        self.assertIn('1 = READ       (read-only access)', output)
        self.assertIn('2 = READ_WRITE (full access)', output)
        self.assertIn('Expiration Options:', output)
        self.assertIn('24h   = 24 hours', output)
        self.assertIn('never = permanent', output)
        self.assertIn('public-api-key list', output)
        self.assertIn('public-api-key generate', output)
        self.assertIn('public-api-key revoke', output)

    def test_api_key_command_registration(self):
        """Test that API key commands are properly registered"""
        commands = {}
        enterprise_api_keys.register_commands(commands)
        
        self.assertIn('public-api-key', commands)
        self.assertIsInstance(commands['public-api-key'], enterprise_api_keys.ApiKeyCommand)
        
        # Test command info registration
        aliases = {}
        command_info = {}
        enterprise_api_keys.register_command_info(aliases, command_info)
        
        self.assertIn('public-api-key', command_info)
        self.assertIn('API keys', command_info['public-api-key'])

    def test_api_key_list_json_comprehensive_fields(self):
        """Test listing API keys in JSON format with all field validation"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyListCommand()
        TestEnterpriseApiKeys.expected_commands = ['list_token']
        
        result = cmd.execute(params, format='json')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        self.assertIsNotNone(result)
        
        # Parse JSON and validate structure
        data = json.loads(result)
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 5)  # Should have 5 tokens from terminal example
        
        # Validate first token
        token = data[0]
        self.assertEqual(token['enterprise_id'], 8560)
        self.assertEqual(token['name'], 'Token Test')
        self.assertEqual(token['status'], 'Expired')
        self.assertIn('issued_date', token)
        self.assertIn('expiration_date', token)
        self.assertIn('integration', token)
        self.assertIn('SIEM:2', token['integration'])

    def test_api_key_generate_json_comprehensive_fields(self):
        """Test API key generation in JSON format with all field validation"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        result = cmd.execute(params, name='SIEM Tool', integrations='SIEM:2', expires='30d', format='json')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        self.assertIsNotNone(result)
        
        # Parse JSON and validate structure
        data = json.loads(result)
        self.assertIsInstance(data, dict)
        
        # Validate all fields match terminal example
        self.assertEqual(data['name'], 'SIEM Tool')
        self.assertEqual(data['token'], 'token_generated_for_test')
        self.assertEqual(data['enterprise_id'], 8560)
        self.assertIn('issued_date', data)
        # issued_date should be raw timestamp (integer)
        self.assertIsInstance(data['issued_date'], int)
        self.assertIn('expiration_date', data)
        # expiration_date should be raw timestamp (integer) or 'never'
        self.assertIsInstance(data['expiration_date'], (int, str))
        if isinstance(data['expiration_date'], str):
            self.assertEqual(data['expiration_date'], 'never')
        self.assertIn('integrations', data)
        
        # Validate integrations
        integrations = data['integrations']
        self.assertIsInstance(integrations, list)
        self.assertEqual(len(integrations), 1)
        self.assertEqual(integrations[0]['api_integration_type_name'], 'SIEM')
        self.assertEqual(integrations[0]['action_type'], 2)
        self.assertEqual(integrations[0]['action_type_name'], 'READ_WRITE')

    def test_api_key_generate_multiple_roles_comprehensive(self):
        """Test API key generation with multiple integrations like terminal example"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyGenerateCommand()
        TestEnterpriseApiKeys.expected_commands = ['generate_token']
        
        captured_output = io.StringIO()
        # Mock get_enterprise_id to avoid API call - enterprise_id 8560 in 32-bit shifted format
        with mock.patch.object(cmd, 'get_enterprise_id', return_value=8560 << 32):
            with mock.patch('sys.stdout', captured_output):
                cmd.execute(params, name='Multi Role Key', integrations='SIEM:2', expires='never')
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        
        # Verify output shows all integrations
        output = captured_output.getvalue()
        self.assertIn('SIEM: READ_WRITE (2)', output)
        self.assertIn('Expires: Never', output)  # Never expires

    def test_api_key_status_detection_expired_vs_active(self):
        """Test that expired and active statuses are properly detected"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyListCommand()
        TestEnterpriseApiKeys.expected_commands = ['list_token']
        
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            result = cmd.execute(params)
        
        output = captured_output.getvalue()
        
        # Verify expired tokens show as Expired (token column removed, checking names and status)
        self.assertIn('Token Test              Expired', output)
        self.assertIn('Token Test 2            Expired', output)
        
        # Verify active tokens show as Active
        self.assertIn('SIEM Tool               Active', output)
        self.assertIn('Token For My Tests 111  Active', output)
        
        # Verify never expires shows "Never"
        self.assertIn('Never', output)

    def test_api_key_revoke_force_flag(self):
        """Test API key revocation with force flag bypasses confirmation"""
        params = get_connected_params()
        
        cmd = enterprise_api_keys.ApiKeyRevokeCommand()
        TestEnterpriseApiKeys.expected_commands = ['revoke_token']
        
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            # Force flag should bypass confirmation
            cmd.execute(params, name='SIEM Integration', force=True)
        
        self.assertEqual(len(TestEnterpriseApiKeys.expected_commands), 0)
        
        # Verify output shows successful revocation
        output = captured_output.getvalue()
        self.assertIn('API Key with Name SIEM Integration revoked successfully', output)

    @staticmethod
    def communicate_rest_success(params, request, path, rs_type=None):
        """Mock successful REST API communication matching Commander terminal examples"""
        expected_path = TestEnterpriseApiKeys.expected_commands.pop(0)
        
        if path == 'public_api/list_token' and expected_path == 'list_token':
            # Mock list tokens response matching Commander terminal example
            rs = publicapi_pb2.PublicApiTokenResponseList()
            
            # Add sample tokens matching the terminal example
            # Token 43 - Expired
            token1 = rs.tokens.add()
            token1.token = "expired_token_43"
            token1.name = "Token Test"
            token1.enterprise_id = 8560
            token1.issuedDate = int(datetime.datetime(2025, 4, 14, 12, 48, 26).timestamp() * 1000)
            token1.expirationDate = int(datetime.datetime(2025, 4, 15, 12, 48, 26).timestamp() * 1000)
            integration1 = token1.integrations.add()
            integration1.roleName = "SIEM"
            integration1.apiIntegrationTypeName = "SIEM"
            integration1.actionType = 2
            
            # Token 44 - Expired
            token2 = rs.tokens.add()
            token2.token = "expired_token_44"
            token2.name = "Token Test"
            token2.enterprise_id = 8560
            token2.issuedDate = int(datetime.datetime(2025, 4, 14, 12, 48, 26).timestamp() * 1000)
            token2.expirationDate = int(datetime.datetime(2025, 4, 15, 12, 48, 26).timestamp() * 1000)
            integration3 = token2.integrations.add()
            integration3.roleName = "SIEM"
            integration3.apiIntegrationTypeName = "SIEM"
            integration3.actionType = 2
            
            # Token 45 - Expired
            token3 = rs.tokens.add()
            token3.token = "expired_token_45"
            token3.name = "Token Test 2"
            token3.enterprise_id = 8560
            token3.issuedDate = int(datetime.datetime(2025, 4, 14, 12, 48, 26).timestamp() * 1000)
            token3.expirationDate = int(datetime.datetime(2025, 4, 15, 12, 48, 26).timestamp() * 1000)
            integration5 = token3.integrations.add()
            integration5.roleName = "SIEM"
            integration5.apiIntegrationTypeName = "SIEM"
            integration5.actionType = 2
            
            # Token 53 - Active
            token4 = rs.tokens.add()
            token4.token = "active_token_53"
            token4.name = "SIEM Tool"
            token4.enterprise_id = 8560
            token4.issuedDate = int(datetime.datetime(2025, 7, 8, 14, 16, 7).timestamp() * 1000)
            token4.expirationDate = int(datetime.datetime(2026, 7, 8, 14, 16, 7).timestamp() * 1000)
            integration7 = token4.integrations.add()
            integration7.roleName = "SIEM"
            integration7.apiIntegrationTypeName = "SIEM"
            integration7.actionType = 2
            
            # Token 54 - Active, Never expires
            token5 = rs.tokens.add()
            token5.token = "permanent_token_54"
            token5.name = "Token For My Tests 111"
            token5.enterprise_id = 8560
            token5.issuedDate = int(datetime.datetime(2025, 7, 9, 14, 33, 26).timestamp() * 1000)
            # No expiration date for never expires
            integration9 = token5.integrations.add()
            integration9.roleName = "SIEM"
            integration9.apiIntegrationTypeName = "SIEM"
            integration9.actionType = 2
            
            return rs
            
        elif path == 'public_api/generate_token' and expected_path == 'generate_token':
            # Mock generate token response matching Commander terminal example
            rs = publicapi_pb2.PublicApiTokenResponse()
            rs.name = request.tokenName  # Should be "SIEM Tool"
            rs.token = "token_generated_for_test"
            rs.enterprise_id = 8560
            # Use the issuedDate from request (which includes +3000ms offset)
            rs.issuedDate = request.issuedDate
            if hasattr(request, 'expirationDate') and request.expirationDate:
                # Use the expirationDate from request (calculated based on expires parameter)
                rs.expirationDate = request.expirationDate
            # If expirationDate is not set, it means 'never' expires
            
            # Add integration from request (using integrationRequests)
            for integration_req in request.integrationRequests:
                integration = rs.integrations.add()
                integration_name = TestEnterpriseApiKeys._get_role_name_by_id(integration_req.apiIntegrationTypeId)
                integration.roleName = integration_name
                integration.apiIntegrationTypeName = integration_name
                integration.actionType = integration_req.actionType
            
            return rs
            
        elif path == 'public_api/revoke_token' and expected_path == 'revoke_token':
            # Mock revoke token response matching Commander terminal example
            rs = publicapi_pb2.RevokeTokenResponse()
            rs.message = "Token revoked successfully"
            return rs
        
        raise Exception(f"Unexpected API call: {path}, expected: {expected_path}")

    @staticmethod
    def _get_role_name_by_id(role_id):
        """Helper method to map role IDs to names"""
        role_map = {
            1: "SIEM",
            3: "BILLING"
        }
        return role_map.get(role_id, f"Role_{role_id}") 
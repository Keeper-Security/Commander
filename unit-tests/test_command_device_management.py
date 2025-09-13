import unittest
from unittest import TestCase, mock
from unittest.mock import Mock, MagicMock, patch, call
import json

from data_vault import get_synced_params, VaultEnvironment
from helper import KeeperApiHelper
from keepercommander.commands.device_management import (
    DeviceUserListCommand,
    DeviceUserActionCommand,
    DeviceUserRenameCommand,
    DeviceAdminListCommand,
    DeviceAdminActionCommand,
    ValidationError
)
from keepercommander.proto import DeviceManagement_pb2, APIRequest_pb2
from keepercommander.error import KeeperApiError


class MockDevice:
    """Mock device object for testing."""
    
    def __init__(self, device_name="Test Device", device_id=1, 
                 client_type=DeviceManagement_pb2.CHROME_EXTENSION,
                 client_type_category=DeviceManagement_pb2.CAT_EXTENSION,
                 client_form_factor=APIRequest_pb2.FF_EMPTY,
                 login_state=APIRequest_pb2.LOGGED_IN,
                 device_status=APIRequest_pb2.DEVICE_OK,
                 last_modified_time=1640995200000,
                 encrypted_device_token=None):
        self.deviceName = device_name
        self.clientType = client_type
        self.clientTypeCategory = client_type_category
        self.clientFormFactor = client_form_factor
        self.loginState = login_state
        self.deviceStatus = device_status
        self.lastModifiedTime = last_modified_time
        self.encryptedDeviceToken = encrypted_device_token or f'token_{device_id}'.encode()


class MockDeviceGroup:
    """Mock device group for testing."""
    
    def __init__(self, devices):
        self.devices = devices


class MockDeviceUserGroup:
    """Mock device user group for testing."""
    
    def __init__(self, enterprise_user_id, device_groups):
        self.enterpriseUserId = enterprise_user_id
        self.deviceGroups = device_groups


class MockDeviceResponse:
    """Mock device response for testing."""
    
    def __init__(self, device_groups):
        self.deviceGroups = device_groups


class MockAdminDeviceResponse:
    """Mock admin device response for testing."""
    
    def __init__(self, device_user_list):
        self.deviceUserList = device_user_list


class TestDeviceUserListCommand(TestCase):
    """Test cases for DeviceUserListCommand."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = DeviceUserListCommand()
        self.params = get_synced_params()
        
        self.device1 = MockDevice("Test Device 1", 1, encrypted_device_token=b'token1')
        self.device2 = MockDevice("Test Device 2", 2, encrypted_device_token=b'token2')
        
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        """Clean up after tests."""
        mock.patch.stopall()

    def test_execute_success_table_format(self):
        """Test successful execution with table format."""
        device_group = MockDeviceGroup([self.device1, self.device2])
        mock_response = MockDeviceResponse([device_group])
        self.communicate_mock.return_value = mock_response
        
        with patch.object(self.command, '_display_table') as mock_display:
            self.command.execute(self.params, format='table')
            
            self.communicate_mock.assert_called_once_with(
                self.params, None, 'dm/device_user_list', rs_type=DeviceManagement_pb2.DeviceUserResponse
            )
            
            mock_display.assert_called_once()
            devices = mock_display.call_args[0][0]
            self.assertEqual(len(devices), 2)

    def test_execute_success_json_format(self):
        """Test successful execution with JSON format."""
        device_group = MockDeviceGroup([self.device1])
        mock_response = MockDeviceResponse([device_group])
        self.communicate_mock.return_value = mock_response
        
        with patch.object(self.command, '_display_json') as mock_display:
            self.command.execute(self.params, format='json')
            
            mock_display.assert_called_once()

    def test_execute_no_devices(self):
        """Test execution when no devices are found."""
        mock_response = MockDeviceResponse([])
        self.communicate_mock.return_value = mock_response
        
        with patch('builtins.print') as mock_print:
            self.command.execute(self.params)
            
            mock_print.assert_called_with("No devices found.")

    def test_execute_api_error_handled_gracefully(self):
        """Test execution when API error is handled gracefully."""
        self.communicate_mock.return_value = None  
        
        result = self.command.execute(self.params)
        self.assertIsNone(result)

    def test_display_table_format(self):
        """Test table display format."""
        devices = [self.device1, self.device2]
        
        with patch('builtins.print'):  
            self.command._display_table(devices)
        
        

    def test_display_json_format(self):
        """Test JSON display format."""
        devices = [self.device1, self.device2]
        
        with patch('builtins.print') as mock_print:
            self.command._display_json(devices)
            
            mock_print.assert_called_once()
            
            printed_json = mock_print.call_args[0][0]
            data = json.loads(printed_json)
            
            self.assertIn('devices', data)
            self.assertEqual(len(data['devices']), 2)
            self.assertEqual(data['devices'][0]['deviceName'], "Test Device 1")


class TestDeviceUserActionCommand(TestCase):
    """Test cases for DeviceUserActionCommand."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = DeviceUserActionCommand()
        self.params = get_synced_params()
        
        self.device1 = MockDevice("Test Device 1", 1, encrypted_device_token=b'token1')
        self.device2 = MockDevice("Test Device 2", 2, encrypted_device_token=b'token2')
        
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        """Clean up after tests."""
        mock.patch.stopall()

    def test_validate_inputs_success(self):
        """Test successful input validation."""
        kwargs = {
            'action': 'logout',
            'devices': ['1', '2']
        }
        
        self.command._validate_inputs(**kwargs)
        
        self.assertEqual(kwargs['devices'], ['1', '2'])

    def test_validate_inputs_invalid_action(self):
        """Test validation with invalid action."""
        kwargs = {
            'action': 'invalid_action',
            'devices': ['1']
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Invalid action", str(cm.exception))

    def test_validate_inputs_no_devices(self):
        """Test validation with no devices."""
        kwargs = {
            'action': 'logout',
            'devices': []
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("At least one device must be specified", str(cm.exception))

    def test_validate_inputs_link_minimum_devices(self):
        """Test validation for link action requiring minimum 2 devices."""
        kwargs = {
            'action': 'link',
            'devices': ['1']  
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("requires at least 2 devices", str(cm.exception))

    def test_validate_inputs_unlink_minimum_devices(self):
        """Test validation for unlink action requiring minimum 2 devices."""
        kwargs = {
            'action': 'unlink',
            'devices': ['1']  
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("requires at least 2 devices", str(cm.exception))

    def test_execute_success(self):
        """Test successful execution of device action."""
        device_group = MockDeviceGroup([self.device1, self.device2])
        list_response = MockDeviceResponse([device_group])
        
        action_result = Mock()
        action_result.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        action_result.encryptedDeviceToken = [b'token1']
        
        action_response = Mock()
        action_response.deviceActionResult = [action_result]
        
        updated_list_response = MockDeviceResponse([device_group])
        
        self.communicate_mock.side_effect = [list_response, action_response, updated_list_response]
        
        kwargs = {
            'action': 'logout',
            'devices': ['1']
        }
        
        with patch.object(self.command, '_display_results') as mock_display, \
             patch.object(self.command, '_show_updated_device_list') as mock_show_list:
            
            self.command.execute(self.params, **kwargs)
            
            self.assertGreaterEqual(self.communicate_mock.call_count, 2)
            
            mock_display.assert_called_once()

    def test_execute_validation_error(self):
        """Test execution with validation error."""
        kwargs = {
            'action': 'invalid',
            'devices': ['1']
        }
        
        with patch('logging.error') as mock_log:
            result = self.command.execute(self.params, **kwargs)
            
            self.assertIsNone(result)

    def test_execute_no_matching_devices(self):
        """Test execution when no devices match identifiers."""
        device_group = MockDeviceGroup([self.device1])
        list_response = MockDeviceResponse([device_group])
        self.communicate_mock.return_value = list_response
        
        kwargs = {
            'action': 'logout',
            'devices': ['999']  
        }
        
        with patch('builtins.print') as mock_print:
            self.command.execute(self.params, **kwargs)
            
            mock_print.assert_called_with("No matching devices found.")

    def test_get_action_parser(self):
        """Test getting action-specific parser."""
        logout_parser = self.command.get_action_parser('logout')
        self.assertIsNotNone(logout_parser)
        self.assertEqual(logout_parser.prog, 'device-action logout')
        
        invalid_parser = self.command.get_action_parser('invalid_action')
        self.assertIsNone(invalid_parser)

    def test_get_action_verb(self):
        """Test action verb mapping."""
        test_cases = [
            ('logout', 'logged out'),
            ('remove', 'removed'),
            ('lock', 'locked'),
            ('unlock', 'unlocked'),
            ('account-lock', 'account locked'),
            ('account-unlock', 'account unlocked'),
            ('link', 'linked'),
            ('unlink', 'unlinked'),
            ('unknown_action', 'unknown_actioned')
        ]
        
        for action, expected_verb in test_cases:
            with self.subTest(action=action):
                result = self.command._get_action_verb(action)
                self.assertEqual(result, expected_verb)


class TestDeviceUserRenameCommand(TestCase):
    """Test cases for DeviceUserRenameCommand."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = DeviceUserRenameCommand()
        self.params = get_synced_params()
        
        self.device1 = MockDevice("Old Device Name", 1, encrypted_device_token=b'token1')
        
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        """Clean up after tests."""
        mock.patch.stopall()

    def test_validate_inputs_success(self):
        """Test successful input validation."""
        kwargs = {
            'device': 'device1',
            'new_name': 'New Device Name'
        }
        
        self.command._validate_inputs(**kwargs)
        
        self.assertEqual(kwargs['new_name'], 'New Device Name')

    def test_validate_inputs_sanitize_name(self):
        """Test input validation with name sanitization."""
        kwargs = {
            'device': 'device1',
            'new_name': 'Device<script>alert("xss")</script>Name'
        }
        
       
        try:
            self.command._validate_inputs(**kwargs)
            self.assertTrue(True)
        except ValidationError:
            self.fail("Validation should not fail for sanitizable input")

    def test_validate_inputs_invalid_device(self):
        """Test validation with invalid device identifier."""
        kwargs = {
            'device': '',  
            'new_name': 'New Name'
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Device identifier is required", str(cm.exception))

    def test_validate_inputs_empty_name(self):
        """Test validation with empty name."""
        kwargs = {
            'device': 'device1',
            'new_name': ''
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("New device name is required", str(cm.exception))

    def test_validate_inputs_name_only_invalid_chars(self):
        """Test validation with name containing only invalid characters."""
        kwargs = {
            'device': 'device1',
            'new_name': '<>"\'<>'  
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("contains only invalid characters", str(cm.exception))

    def test_execute_success(self):
        """Test successful device rename."""
        device_group = MockDeviceGroup([self.device1])
        list_response = MockDeviceResponse([device_group])
        
        rename_result = Mock()
        rename_result.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        rename_result.encryptedDeviceToken = [b'token1']
        
        rename_response = Mock()
        rename_response.deviceRenameResult = [rename_result]
        
        updated_list_response = MockDeviceResponse([device_group])
        
        self.communicate_mock.side_effect = [list_response, rename_response, updated_list_response]
        
        kwargs = {
            'device': '1',
            'new_name': 'New Device Name'
        }
        
        with patch.object(self.command, '_display_results') as mock_display, \
             patch.object(self.command, '_show_updated_device_list') as mock_show_list:
            
            self.command.execute(self.params, **kwargs)
            
            self.assertGreaterEqual(self.communicate_mock.call_count, 2)
            
            mock_display.assert_called_once()

    def test_execute_validation_error(self):
        """Test execution with validation error."""
        kwargs = {
            'device': '',  
            'new_name': 'New Name'
        }
        
        with patch('logging.error') as mock_log:
            result = self.command.execute(self.params, **kwargs)
            
            self.assertIsNone(result)
            mock_log.assert_called()

    def test_execute_no_matching_device(self):
        """Test execution when device is not found."""
        device_group = MockDeviceGroup([self.device1])
        list_response = MockDeviceResponse([device_group])
        self.communicate_mock.return_value = list_response
        
        kwargs = {
            'device': '999',  
            'new_name': 'New Name'
        }
        
        with patch('builtins.print') as mock_print:
            self.command.execute(self.params, **kwargs)
            
            mock_print.assert_called_with("No matching device found.")


class TestDeviceAdminListCommand(TestCase):
    """Test cases for DeviceAdminListCommand."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = DeviceAdminListCommand()
        self.params = get_synced_params()
        
        # Mock devices
        self.device1 = MockDevice("User 1 Device", 1, encrypted_device_token=b'token1')
        self.device2 = MockDevice("User 2 Device", 2, encrypted_device_token=b'token2')
        
        # Mock API communication
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        """Clean up after tests."""
        mock.patch.stopall()

    def test_validate_inputs_success(self):
        """Test successful input validation."""
        kwargs = {
            'enterprise_user_ids': [123, 456]
        }
        
        self.command._validate_inputs(**kwargs)

    def test_validate_inputs_no_user_ids(self):
        """Test validation with no user IDs."""
        kwargs = {
            'enterprise_user_ids': []
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Enterprise User ID is required", str(cm.exception))
        self.assertIn("ei --users", str(cm.exception))

    def test_validate_inputs_invalid_user_id(self):
        """Test validation with invalid user ID."""
        kwargs = {
            'enterprise_user_ids': [123, -1]  # -1 is invalid
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Invalid enterprise user ID: -1", str(cm.exception))


    def test_execute_success(self):
        """Test successful execution of admin device list."""
        device_group1 = MockDeviceGroup([self.device1])
        device_user_group1 = MockDeviceUserGroup(123, [device_group1])
        
        device_group2 = MockDeviceGroup([self.device2])
        device_user_group2 = MockDeviceUserGroup(456, [device_group2])
        
        mock_response = MockAdminDeviceResponse([device_user_group1, device_user_group2])
        self.communicate_mock.return_value = mock_response
        
        kwargs = {
            'enterprise_user_ids': [123, 456]
        }
        
        with patch.object(self.command, '_display_results') as mock_display:
            self.command.execute(self.params, **kwargs)
            
            self.communicate_mock.assert_called_once()
            
            mock_display.assert_called_once()
            devices = mock_display.call_args[0][0]
            self.assertEqual(len(devices), 2)  

    def test_execute_validation_error(self):
        """Test execution with validation error."""
        kwargs = {
            'enterprise_user_ids': [] 
        }
        
        with patch('logging.error') as mock_log:
            result = self.command.execute(self.params, **kwargs)
            
            self.assertIsNone(result)
            mock_log.assert_called()

    def test_execute_no_devices(self):
        """Test execution when no devices are found."""
        mock_response = MockAdminDeviceResponse([])
        self.communicate_mock.return_value = mock_response
        
        kwargs = {
            'enterprise_user_ids': [123]
        }
        
        with patch('builtins.print') as mock_print:
            self.command.execute(self.params, **kwargs)
            
            mock_print.assert_called_with("No devices found.")


class TestDeviceAdminActionCommand(TestCase):
    """Test cases for DeviceAdminActionCommand."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = DeviceAdminActionCommand()
        self.params = get_synced_params()
        
        self.device1 = MockDevice("User Device", 1, encrypted_device_token=b'token1')
        
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        """Clean up after tests."""
        mock.patch.stopall()

    def test_validate_inputs_success(self):
        """Test successful input validation."""
        kwargs = {
            'action': 'logout',
            'enterprise_user_id': 123,
            'devices': ['1', '2']
        }
        
        self.command._validate_inputs(**kwargs)
        
        self.assertEqual(kwargs['devices'], ['1', '2'])

    def test_validate_inputs_invalid_action(self):
        """Test validation with invalid action."""
        kwargs = {
            'action': 'invalid_action',
            'enterprise_user_id': 123,
            'devices': ['1']
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Invalid action", str(cm.exception))

    def test_validate_inputs_invalid_user_id(self):
        """Test validation with invalid enterprise user ID."""
        kwargs = {
            'action': 'logout',
            'enterprise_user_id': -1,  
            'devices': ['1']
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("Invalid enterprise user ID", str(cm.exception))

    def test_validate_inputs_no_devices(self):
        """Test validation with no devices."""
        kwargs = {
            'action': 'logout',
            'enterprise_user_id': 123,
            'devices': []
        }
        
        with self.assertRaises(ValidationError) as cm:
            self.command._validate_inputs(**kwargs)
        
        self.assertIn("At least one device must be specified", str(cm.exception))

    def test_execute_success(self):
        """Test successful execution of admin device action."""
        device_group = MockDeviceGroup([self.device1])
        device_user_group = MockDeviceUserGroup(123, [device_group])
        list_response = MockAdminDeviceResponse([device_user_group])
        
        action_result = Mock()
        action_result.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        action_result.encryptedDeviceToken = [b'token1']
        
        action_response = Mock()
        action_response.deviceAdminActionResults = [action_result]
        
        updated_list_response = MockAdminDeviceResponse([device_user_group])
        
        self.communicate_mock.side_effect = [list_response, action_response, updated_list_response]
        
        kwargs = {
            'action': 'logout',
            'enterprise_user_id': 123,
            'devices': ['1']
        }
        
        with patch.object(self.command, '_display_results') as mock_display, \
             patch.object(self.command, '_show_updated_device_list') as mock_show_list:
            
            self.command.execute(self.params, **kwargs)
            
            self.assertGreaterEqual(self.communicate_mock.call_count, 2)
            
            mock_display.assert_called_once()

    def test_execute_validation_error(self):
        """Test execution with validation error."""
        kwargs = {
            'action': 'invalid',
            'enterprise_user_id': 123,
            'devices': ['1']
        }
        
        with patch('logging.error') as mock_log:
            result = self.command.execute(self.params, **kwargs)
            
            self.assertIsNone(result)

    def test_execute_no_matching_devices(self):
        """Test execution when no devices match identifiers."""
        device_group = MockDeviceGroup([self.device1])
        device_user_group = MockDeviceUserGroup(123, [device_group])
        list_response = MockAdminDeviceResponse([device_user_group])
        self.communicate_mock.return_value = list_response
        
        kwargs = {
            'action': 'logout',
            'enterprise_user_id': 123,
            'devices': ['999']  
        }
        
        with patch('builtins.print') as mock_print:
            self.command.execute(self.params, **kwargs)
            
            mock_print.assert_called_with("No matching devices found.")

    def test_get_action_parser(self):
        """Test getting action-specific parser."""
        logout_parser = self.command.get_action_parser('logout')
        self.assertIsNotNone(logout_parser)
        self.assertEqual(logout_parser.prog, 'device-admin-action logout')
        
        # Test non-existent action
        invalid_parser = self.command.get_action_parser('invalid_action')
        self.assertIsNone(invalid_parser)

    def test_get_action_verb(self):
        """Test action verb mapping for admin actions."""
        test_cases = [
            ('logout', 'logged out'),
            ('remove', 'removed'),
            ('lock', 'locked'),
            ('unlock', 'unlocked'),
            ('account-lock', 'account locked'),
            ('account-unlock', 'account unlocked'),
            ('unknown_action', 'unknown_actioned')
        ]
        
        for action, expected_verb in test_cases:
            with self.subTest(action=action):
                result = self.command._get_action_verb(action)
                self.assertEqual(result, expected_verb)




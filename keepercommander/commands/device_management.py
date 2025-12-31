#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Any, List, Tuple

from .. import api, utils
from ..proto import DeviceManagement_pb2, APIRequest_pb2
from .base import Command, dump_report_data
from ..display import bcolors
from ..params import KeeperParams
from ..error import KeeperApiError


class DeviceManagementError(Exception):
    """Base exception for device management operations."""
    pass


class InvalidDeviceIdentifierError(DeviceManagementError):
    """Raised when a device identifier is invalid or malformed."""
    pass


class DeviceNotFoundError(DeviceManagementError):
    """Raised when a specified device cannot be found."""
    pass


class ValidationError(DeviceManagementError):
    """Raised when input validation fails."""
    pass


class DeviceInputValidator:
    """Centralized input validation and sanitization for device management."""
    
    @staticmethod
    def validate_device_identifier(identifier: str) -> bool:
        """Validate device identifier for security and format."""
        if not isinstance(identifier, str):
            return False
        if not identifier or not identifier.strip():
            return False
        if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', identifier):
            return False
        return True
    
    @staticmethod
    def sanitize_device_name(name: str) -> str:
        """Sanitize device name by removing dangerous characters."""
        if not isinstance(name, str):
            return ""
        sanitized = re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', name)
        return sanitized.strip()
    
    @staticmethod
    def validate_enterprise_user_id(user_id: Any) -> bool:
        """Validate enterprise user ID."""
        if not isinstance(user_id, int):
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                return False
        return user_id >= 1
    
    @staticmethod
    def validate_action(action: str) -> bool:
        """Validate action name."""
        if not isinstance(action, str):
            return False
        if not action or not action.strip():
            return False
        return bool(re.match(r'^[a-z0-9-]+$', action.strip().lower()))
    
    @staticmethod
    def validate_device_identifiers_list(identifiers: List[str]) -> List[str]:
        """Validate and filter a list of device identifiers."""
        if not isinstance(identifiers, list):
            raise ValidationError("Device identifiers must be provided as a list")
        
        valid_identifiers = []
        for identifier in identifiers:
            if DeviceInputValidator.validate_device_identifier(identifier):
                valid_identifiers.append(identifier.strip())
            else:
                logging.warning(f"Invalid device identifier skipped: '{identifier}'")
        
        if not valid_identifiers:
            raise ValidationError("No valid device identifiers provided")
        
        return valid_identifiers


class StatusMapper:
    """Centralized status mapping utility."""
    
    LOGIN_STATUS_MAP = {
        APIRequest_pb2.LoginState.LOGGED_IN: "LOGGED_IN",
        APIRequest_pb2.LoginState.LOGGED_OUT: "LOGGED_OUT", 
        APIRequest_pb2.LoginState.DEVICE_LOCKED: "DEVICE_LOCKED",
        APIRequest_pb2.LoginState.DEVICE_ACCOUNT_LOCKED: "DEVICE_ACCOUNT_LOCKED",
        APIRequest_pb2.LoginState.ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
        APIRequest_pb2.LoginState.LICENSE_EXPIRED: "LICENSE_EXPIRED",
    }
    
    DEVICE_STATUS_MAP = {
        APIRequest_pb2.DEVICE_NEEDS_APPROVAL: "NEEDS_APPROVAL",
        APIRequest_pb2.DEVICE_OK: "OK",
        APIRequest_pb2.DEVICE_DISABLED_BY_USER: "DISABLED_BY_USER", 
        APIRequest_pb2.DEVICE_LOCKED_BY_ADMIN: "LOCKED_BY_ADMIN",
    }
    
    ACTION_TYPE_MAP = {
        'logout': DeviceManagement_pb2.DA_LOGOUT,
        'remove': DeviceManagement_pb2.DA_REMOVE,
        'lock': DeviceManagement_pb2.DA_LOCK,
        'unlock': DeviceManagement_pb2.DA_UNLOCK,
        'account-lock': DeviceManagement_pb2.DA_DEVICE_ACCOUNT_LOCK,
        'account-unlock': DeviceManagement_pb2.DA_DEVICE_ACCOUNT_UNLOCK,
        'link': DeviceManagement_pb2.DA_LINK,
        'unlink': DeviceManagement_pb2.DA_UNLINK,
    }
    
    ACTION_DESCRIPTIONS = {
        'logout': 'Logout the user from the device',
        'remove': 'Logout & Remove the user from that device',
        'lock': 'Lock the device for all users on the devices and the associated auto linked devices. Logout all users from the device',
        'unlock': 'Unlock the devices and the associated auto linked devices for the calling user',
        'account-lock': 'Lock the device for the user only. If user is logged in, logout',
        'account-unlock': 'Unlock the device for the user',
    }
    
    @classmethod
    def get_login_status_display(cls, login_state: int) -> str:
        return cls.LOGIN_STATUS_MAP.get(login_state, f"UNKNOWN_STATE_{login_state}")
    
    @classmethod
    def get_device_status_display(cls, device_status: int) -> str:
        return cls.DEVICE_STATUS_MAP.get(device_status, f"UNKNOWN_STATUS_{device_status}")
    
    @classmethod
    def get_action_type(cls, action: str) -> int:
        if action not in cls.ACTION_TYPE_MAP:
            raise ValueError(f"Unknown action: {action}")
        return cls.ACTION_TYPE_MAP[action]
    
    @classmethod
    def get_action_description(cls, action: str) -> str:
        return cls.ACTION_DESCRIPTIONS.get(action, 'Unknown action')


class TimestampFormatter:
    """Utility for formatting timestamps consistently."""
    
    @staticmethod
    def format_timestamp(timestamp: Optional[int]) -> str:
        if not timestamp:
            return 'N/A'
        try:
            if timestamp > 10000000000:  
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError, TypeError):
            return f'Invalid timestamp: {timestamp}'


class UICategory:
    """Utility for determining UI categories based on device properties."""
    
    CATEGORY_RULES = [
        (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_EXTENSION, "Browser Extension"),
        (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_DESKTOP, "Desktop"),
        (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_WEB_VAULT, "Web Vault"),
        (lambda d: (d.clientType == DeviceManagement_pb2.ENTERPRISE_MANAGEMENT_CONSOLE and 
                   d.clientTypeCategory == DeviceManagement_pb2.CAT_ADMIN), "Admin Console"),
        (lambda d: (d.clientType == DeviceManagement_pb2.COMMANDER and 
                   d.clientTypeCategory == DeviceManagement_pb2.CAT_ADMIN), "Commander CLI"),
        (lambda d: (d.clientType == DeviceManagement_pb2.IOS and 
                   d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE), "iOS App"),
        (lambda d: (d.clientType == DeviceManagement_pb2.ANDROID and 
                   d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE), "Android App"),
        (lambda d: (d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE and 
                   d.clientFormFactor == APIRequest_pb2.FF_PHONE), "Mobile"),
        (lambda d: (d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE and 
                   d.clientFormFactor == APIRequest_pb2.FF_TABLET), "Tablet"),
        (lambda d: (d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE and 
                   d.clientFormFactor == APIRequest_pb2.FF_WATCH), "Wear OS"),
    ]
    
    @staticmethod
    def get_ui_category(device) -> str:
        """Determine UI category based on device properties using rule-based mapping."""
        try:
            for rule_check, category_name in UICategory.CATEGORY_RULES:
                if rule_check(device):
                    return category_name
            return "Unknown Device"
        except (AttributeError, TypeError) as e:
            logging.debug(f"Error determining UI category for device: {e}")
            return "Unknown Device"


class DeviceResolver:
    """Service for resolving device identifiers to device tokens."""
    
    @staticmethod
    def _safe_int_conversion(value: str) -> Optional[int]:
        """Safely convert string to integer with validation."""
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            result = int(value.strip())
            if result < 1:  
                return None
            return result
        except ValueError:
            return None
    
    @staticmethod
    def extract_devices_from_response(devices_response, enterprise_user_id: Optional[int] = None) -> List:
        """Extract and sort devices from API response."""
        all_devices = []
        
        if hasattr(devices_response, 'deviceGroups'):  # User response
            for device_group in devices_response.deviceGroups:
                for device in device_group.devices:
                    all_devices.append(device)
        elif hasattr(devices_response, 'deviceUserList'):  # Admin response
            for device_user_group in devices_response.deviceUserList:
                if enterprise_user_id is None or device_user_group.enterpriseUserId == enterprise_user_id:
                    for device_group in device_user_group.deviceGroups:
                        for device in device_group.devices:
                            all_devices.append(device)
        
        return sorted(all_devices, key=lambda x: x.lastModifiedTime or 0, reverse=True)
    
    @staticmethod
    def _resolve_single_identifier(all_devices: List, identifier: str, allow_multiple: bool, 
                                 enterprise_user_id: Optional[int]) -> Optional[Any]:
        """Resolve a single device identifier and handle multiple matches."""
        matched_devices = DeviceResolver._find_matching_devices(all_devices, identifier)
        
        if not matched_devices:
            user_context = f" for user {enterprise_user_id}" if enterprise_user_id else ""
            logging.warning(f"Warning: No device found matching '{identifier}'{user_context}")
            return None
        elif len(matched_devices) > 1 and not allow_multiple:
            DeviceResolver._handle_multiple_matches(matched_devices, all_devices, identifier, enterprise_user_id)
            return None
        elif len(matched_devices) > 1:
            logging.warning(f"Warning: Multiple devices found matching '{identifier}'. Using first match.")
            return matched_devices[0]
        else:
            return matched_devices[0]
    
    @staticmethod
    def resolve_device_identifiers(all_devices: List, device_identifiers: List[str], 
                                 allow_multiple: bool = True, enterprise_user_id: Optional[int] = None) -> List[bytes]:
        """Resolve device identifiers to device tokens."""
        resolved_tokens = []
        
        for identifier in device_identifiers:
            device = DeviceResolver._resolve_single_identifier(all_devices, identifier, allow_multiple, enterprise_user_id)
            if device:
                resolved_tokens.append(device.encryptedDeviceToken)
                
        return resolved_tokens
    
    @staticmethod
    def resolve_device_identifiers_with_info(all_devices: List, device_identifiers: List[str], 
                                           allow_multiple: bool = True, enterprise_user_id: Optional[int] = None) -> List[Tuple[bytes, Any]]:
        """Resolve device identifiers to device tokens and return device info for success messages."""
        resolved_devices = []
        
        for identifier in device_identifiers:
            device = DeviceResolver._resolve_single_identifier(all_devices, identifier, allow_multiple, enterprise_user_id)
            if device:
                resolved_devices.append((device.encryptedDeviceToken, device))
                
        return resolved_devices
    
    @staticmethod
    def get_device_by_token(all_devices: List, device_token: bytes):
        """Get device object by its encrypted token."""
        for device in all_devices:
            if device.encryptedDeviceToken == device_token:
                return device
        return None
    
    @staticmethod
    def _find_matching_devices(all_devices: List, identifier: str) -> List:
        """Find devices matching the given identifier."""
        matched_devices = []
        
        device_id = DeviceResolver._safe_int_conversion(identifier)
        if device_id is not None:
            if 1 <= device_id <= len(all_devices):
                return [all_devices[device_id - 1]]
            else:
                logging.warning(f"Device ID {device_id} is out of range (1-{len(all_devices)})")
                return []
        
        for device in all_devices:
            try:
                decoded_token = utils.base64_url_decode(identifier)
                if device.encryptedDeviceToken == decoded_token:
                    return [device]
            except (ValueError, TypeError, AttributeError) as e:
                logging.debug(f"Failed to decode device token '{identifier}': {e}")
                continue
                
            if device.deviceName and identifier.lower() in device.deviceName.lower():
                matched_devices.append(device)
        
        return matched_devices
    
    @staticmethod
    def _handle_multiple_matches(matched_devices: List, all_devices: List, identifier: str, 
                               enterprise_user_id: Optional[int] = None):
        """Handle case where multiple devices match an identifier."""
        user_context = f" for user {enterprise_user_id}" if enterprise_user_id else ""
        logging.warning(f"Warning: Multiple devices found matching '{identifier}'{user_context}:")
        
        for device in matched_devices:
            device_id = next((idx + 1 for idx, d in enumerate(all_devices) 
                            if d.encryptedDeviceToken == device.encryptedDeviceToken), "?")
            logging.info(f"  - ID {device_id}: {device.deviceName}")
        logging.info("Please be more specific or use the device ID. Skipping this identifier.")


class ErrorHandler:
    """Centralized error handling for device management commands."""
    
    @staticmethod
    def handle_api_error(error: KeeperApiError, operation: str) -> bool:
        """Handle KeeperApiError with consistent messaging.
        
        Returns:
            bool: True if error was handled gracefully and should not be re-raised, False otherwise
        """
        if error.result_code == 'forbidden':
            logging.error(f"{bcolors.FAIL}Error: {error.message}{bcolors.ENDC}")
            if operation == 'device_admin_action':
                logging.info("This error typically occurs when:")
                logging.info("- The device tokens are invalid or not owned by the specified user")
                logging.info("- The admin doesn't have permission to perform actions on this user's devices")
                logging.info("- The target devices are not accessible")
            return False
        elif error.result_code == 'bad_request':
            logging.error(f"{bcolors.FAIL}Bad Request: {error.message}{bcolors.ENDC}")
            return False
        elif error.result_code == 404 or error.result_code == '404' or error.result_code == 'invalid_path_or_method':
            logging.info(f"{bcolors.WARNING}Notice: This feature is not in production yet. It will be available soon.{bcolors.ENDC}")
            return True  
        else:
            return False
    
    @staticmethod
    def handle_general_error(error: Exception, operation: str):
        """Handle general exceptions."""
        logging.error(f"Failed to {operation}: {error}")


class DisplayMixin:
    """Mixin providing common display functionality."""
    
    def _display_results(self, data: Any, **kwargs):
        """Generic method to display results in table or JSON format."""
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        if fmt == 'json':
            self._display_json(data, output)
        else:
            self._display_table(data, output)
    
    def _display_json(self, data: Any, output_file: Optional[str] = None):
        """Display data in JSON format."""
        json_output = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Results saved to {output_file}")
        else:
            print(json_output)
    
    @abstractmethod
    def _display_table(self, data: Any, output_file: Optional[str] = None):
        """Display data in table format - must be implemented by subclasses."""
        pass


class BaseDeviceCommand(Command, DisplayMixin, ABC):
    """Base class for all device management commands."""
    
    def _validate_inputs(self, **kwargs):
        """Validate command inputs - can be overridden by subclasses."""
        pass
    
    def _show_updated_device_list(self, params: KeeperParams, enterprise_user_id: Optional[int] = None):
        """Show updated device list after an action."""
        print()  # Add a blank line for better readability
        
        if enterprise_user_id is not None:
            print(f"Updated device list for user {enterprise_user_id}:")
            list_request = DeviceManagement_pb2.DeviceAdminRequest()
            list_request.enterpriseUserIds.append(enterprise_user_id)
            
            response = self._make_api_call(
                params, list_request, 'dm/device_admin_list', DeviceManagement_pb2.DeviceAdminResponse
            )
            
            if response is None:
                return
            
            user_devices = []
            for device_user_group in response.deviceUserList:
                if device_user_group.enterpriseUserId == enterprise_user_id:
                    for device_group in device_user_group.deviceGroups:
                        for device in device_group.devices:
                            device_info = {
                                'enterprise_user_id': enterprise_user_id,
                                'device': device
                            }
                            user_devices.append(device_info)
            
            if user_devices:
                self._display_admin_device_table(user_devices)
            else:
                print("No devices found for this user.")
        else:
            # Show user device list
            print("Updated device list:")
            response = self._make_api_call(
                params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
            )
            
            if response is None:
                return
            
            devices = DeviceResolver.extract_devices_from_response(response)
            
            if devices:
                self._display_user_device_table(devices)
            else:
                print("No devices found.")
    
    def _display_user_device_table(self, devices: List):
        """Display user devices in a compact table format."""
        headers = ['ID', 'Device Name', 'Client Type', 'Login Status', 'Last Accessed']
        
        device_data = []
        for device in devices:
            device_data.append({
                'name': device.deviceName or 'N/A',
                'client_type': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'login_status': StatusMapper.get_login_status_display(device.loginState),
                'last_accessed': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            table_data.append([
                str(i),
                device['name'],
                device['client_type'],
                device['login_status'],
                device['last_accessed']
            ])
        
        dump_report_data(table_data, headers=headers, fmt='table', title=f'Your Devices ({len(table_data)} found)')
    
    def _display_admin_device_table(self, devices: List):
        """Display admin devices in a compact table format."""
        headers = ['ID', 'Device Name', 'UI Category', 'Device Status', 'Login Status', 'Last Accessed']
        
        device_data = []
        for device_info in devices:
            device = device_info['device']
            
            device_data.append({
                'name': device.deviceName or 'N/A',
                'ui_category': UICategory.get_ui_category(device),
                'device_status': StatusMapper.get_device_status_display(device.deviceStatus),
                'login_status': StatusMapper.get_login_status_display(device.loginState),
                'last_accessed': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            table_data.append([
                str(i),
                device['name'],
                device['ui_category'],
                device['device_status'],
                device['login_status'],
                device['last_accessed']
            ])
        
        dump_report_data(table_data, headers=headers, fmt='table', title=f'User Devices ({len(table_data)} found)')
    
    def _has_successful_operations(self, results: List) -> bool:
        """Check if any operations were successful."""
        if not results:
            return False
        
        for result in results:
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                return True
        return False
    
    def _make_api_call(self, params: KeeperParams, request: Any, endpoint: str, response_type: Any) -> Any:
        """Make API call with consistent error handling."""
        try:
            return api.communicate_rest(params, request, endpoint, rs_type=response_type)
        except KeeperApiError as kae:
            handled_gracefully = ErrorHandler.handle_api_error(kae, endpoint.split('/')[-1])
            if not handled_gracefully:
                raise
            return None  # Return None for gracefully handled errors
        except Exception as e:
            ErrorHandler.handle_general_error(e, endpoint.split('/')[-1])
            raise


device_user_list_parser = argparse.ArgumentParser(prog='device-list', description='List all active devices for the current user')
device_user_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                     default='table', help='output format')
device_user_list_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

# Action definitions for device-action command
DEVICE_ACTION_DEFINITIONS = {
    'logout': {
        'description': 'Logout the user from the device',
        'help': 'Device IDs (1, 2, 3...) or device names to logout from',
        'min_devices': 1
    },
    'remove': {
        'description': 'Logout & Remove the user from that device',
        'help': 'Device IDs (1, 2, 3...) or device names to remove user from',
        'min_devices': 1
    },
    'lock': {
        'description': 'Lock the device for all users on the devices and the associated auto linked devices. Logout all users from the device',
        'help': 'Device IDs (1, 2, 3...) or device names to lock',
        'min_devices': 1
    },
    'unlock': {
        'description': 'Unlock the devices and the associated auto linked devices for the calling user',
        'help': 'Device IDs (1, 2, 3...) or device names to unlock',
        'min_devices': 1
    },
    'account-lock': {
        'description': 'Lock the device for the calling user only. If calling user is logged in, logout the calling user.',
        'help': 'Device IDs (1, 2, 3...) or device names to account-lock',
        'min_devices': 1
    },
    'account-unlock': {
        'description': 'Unlock the device for the calling user.',
        'help': 'Device IDs (1, 2, 3...) or device names to account-unlock',
        'min_devices': 1
    },
    'link': {
        'description': 'Link the devices and the associated auto linked devices for the calling user',
        'help': 'Device IDs (1, 2, 3...) or device names to link (minimum 2 devices required)',
        'min_devices': 2
    },
    'unlink': {
        'description': 'Unlink the devices and the associated auto linked devices for the calling user',
        'help': 'Device IDs (1, 2, 3...) or device names to unlink (minimum 2 devices required)',
        'min_devices': 2
    }
}

# Generate action-specific parsers dynamically
device_action_parsers = {}
for action, config in DEVICE_ACTION_DEFINITIONS.items():
    parser = argparse.ArgumentParser(
        prog=f'device-action {action}', 
        description=config['description']
    )
    parser.add_argument('devices', nargs='+', help=config['help'])
    device_action_parsers[action] = parser

# Main device-action parser
device_user_action_parser = argparse.ArgumentParser(prog='device-action', description='Perform actions on user devices')
device_user_action_parser.add_argument('action', choices=list(DEVICE_ACTION_DEFINITIONS.keys()), 
                                       help='Action to perform on devices')
device_user_action_parser.add_argument('devices', nargs='+', 
                                       help='Device IDs (1, 2, 3...) or device names ')

device_user_rename_parser = argparse.ArgumentParser(prog='device-rename', description='Rename user devices')
device_user_rename_parser.add_argument('device', help='Device ID (1, 2, 3...), device token, or device name')
device_user_rename_parser.add_argument('new_name', help='New name for the device')


device_admin_list_parser = argparse.ArgumentParser(prog='device-admin-list', description='List all devices across users that the Admin has control of')
device_admin_list_parser.add_argument('enterprise_user_ids', nargs='+', type=int, 
                                     help='List of Enterprise User IDs (required). You can get enterprise user IDs by running "ei --users" command')
device_admin_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                     default='table', help='output format')
device_admin_list_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

# Action definitions for device-admin-action command
DEVICE_ADMIN_ACTION_DEFINITIONS = {
    'logout': {
        'description': 'Logout the user from the device',
        'help': 'Device IDs (1, 2, 3...) or device names to logout from',
        'min_devices': 1
    },
    'remove': {
        'description': 'Logout & Remove the user from that device',
        'help': 'Device IDs (1, 2, 3...) or device names to remove user from',
        'min_devices': 1
    },
    'lock': {
        'description': 'Lock the device for all users on the devices and the associated auto linked devices. Logout all users from the device',
        'help': 'Device IDs (1, 2, 3...) or device names to lock',
        'min_devices': 1
    },
    'unlock': {
        'description': 'Unlock the devices and the associated auto linked devices for the calling user',
        'help': 'Device IDs (1, 2, 3...) or device names to unlock',
        'min_devices': 1
    },
    'account-lock': {
        'description': 'Lock the device for the user only. If user is logged in, logout',
        'help': 'Device IDs (1, 2, 3...) or device names to account-lock',
        'min_devices': 1
    },
    'account-unlock': {
        'description': 'Unlock the device for the user',
        'help': 'Device IDs (1, 2, 3...) or device names to account-unlock',
        'min_devices': 1
    }
}

# Generate admin action-specific parsers dynamically
device_admin_action_parsers = {}
for action, config in DEVICE_ADMIN_ACTION_DEFINITIONS.items():
    parser = argparse.ArgumentParser(
        prog=f'device-admin-action {action}', 
        description=config['description']
    )
    parser.add_argument('enterprise_user_id', type=int,
                       help='Enterprise User ID whose devices to act on')
    parser.add_argument('devices', nargs='+', help=config['help'])
    device_admin_action_parsers[action] = parser

# Main device-admin-action parser
device_admin_action_parser = argparse.ArgumentParser(prog='device-admin-action', description='Perform various action on one or more devices that the Admin has control of.')
device_admin_action_parser.add_argument('action', choices=list(DEVICE_ADMIN_ACTION_DEFINITIONS.keys()), 
                                        help='Action to perform on devices')
device_admin_action_parser.add_argument('enterprise_user_id', type=int,
                                        help='Enterprise User ID whose devices to act on')
device_admin_action_parser.add_argument('devices', nargs='+', 
                                        help='Device IDs or devicenames')



def register_commands(commands):
    commands['device-list'] = DeviceUserListCommand()
    commands['device-action'] = DeviceUserActionCommand()
    commands['device-rename'] = DeviceUserRenameCommand()

def register_enterprise_commands(commands):
    commands['device-admin-list'] = DeviceAdminListCommand()
    commands['device-admin-action'] = DeviceAdminActionCommand()

def register_command_info(aliases, command_info):
    command_info['device-list'] = 'List all active devices for the current user'
    command_info['device-action'] = 'Perform actions on user devices'
    command_info['device-rename'] = 'Rename user devices'

def register_enterprise_command_info(aliases, command_info):
    command_info['device-admin-list'] = 'List all devices across users that the Admin has control of'
    command_info['device-admin-action'] = 'Perform actions on devices across enterprise users'


class DeviceUserListCommand(BaseDeviceCommand):
    """Command to list all active devices for the current user."""
    
    def get_parser(self):
        return device_user_list_parser

    def execute(self, params: KeeperParams, **kwargs):
        response = self._make_api_call(
            params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
        )
        
        if response is None:
            return
        
        devices = DeviceResolver.extract_devices_from_response(response)
        
        if not devices:
            print("No devices found.")
            return
        
        self._display_results(devices, **kwargs)

    def _display_table(self, devices: List, output_file: Optional[str] = None):
        """Display devices in table format."""
        headers = ['ID', 'Device Name', 'Client Type', 'Login Status', 'Last Accessed']
        
        device_data = []
        for device in devices:
            device_data.append({
                'name': device.deviceName or 'N/A',
                'client_type': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'login_status': StatusMapper.get_login_status_display(device.loginState),
                'last_accessed': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            table_data.append([
                str(i),
                device['name'],
                device['client_type'],
                device['login_status'],
                device['last_accessed']
            ])
        
        title = f'User Devices ({len(table_data)} found)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_json(self, devices: List, output_file: Optional[str] = None):
        """Display devices in JSON format."""
        device_list = []
        for i, device in enumerate(devices, 1):
            device_info = {
                'id': i,
                'deviceName': device.deviceName,
                'clientType': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'loginStatus': StatusMapper.get_login_status_display(device.loginState),
                'lastAccessedTimestamp': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            }
            device_list.append(device_info)
        
        device_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        for i, device in enumerate(device_list, 1):
            device['id'] = i
            del device['timestamp']
        
        result = {'devices': device_list}
        super()._display_json(result, output_file)


class DeviceUserActionCommand(BaseDeviceCommand):
    """Command to perform actions on user devices."""

    def get_parser(self):
        return device_user_action_parser
    
    def get_action_parser(self, action):
        """Get action-specific parser for detailed help."""
        return device_action_parsers.get(action)

    def execute_args(self, params: KeeperParams, args, **kwargs):
        """Override to handle action-specific help."""
        import shlex
        from .base import expand_cmd_args, normalize_output_param, ParseError
        
        try:
            # Parse arguments to check for action-specific help
            args = '' if args is None else args
            args = expand_cmd_args(args, params.environment_variables)
            args = normalize_output_param(args)
            
            parsed_args = shlex.split(args)
            
            if len(parsed_args) >= 2 and parsed_args[1] in ['--help', '-h']:
                action = parsed_args[0]
                action_parser = self.get_action_parser(action)
                if action_parser:
                    action_parser.print_help()
                    return
            
            return super().execute_args(params, args, **kwargs)
        except ParseError as e:
            logging.error(e)

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        action = kwargs.get('action')
        devices = kwargs.get('devices', [])
        
        # Validate action
        if not action:
            raise ValidationError("Action is required")
        if not DeviceInputValidator.validate_action(action):
            raise ValidationError(f"Invalid action: '{action}'")
        
        # Validate and sanitize device identifiers
        if not devices:
            raise ValidationError("At least one device must be specified")
        
        try:
            validated_devices = DeviceInputValidator.validate_device_identifiers_list(devices)
        except ValidationError as e:
            raise ValidationError(f"Device validation failed: {e}")
        
        if action in DEVICE_ACTION_DEFINITIONS:
            min_devices = DEVICE_ACTION_DEFINITIONS[action]['min_devices']
            if len(validated_devices) < min_devices:
                if min_devices == 1:
                    raise ValidationError(f"At least {min_devices} device must be specified")
                else:
                    raise ValidationError(f"{action.capitalize()} action requires at least {min_devices} devices. Please provide {min_devices} or more device IDs or device names.")
        
        kwargs['devices'] = validated_devices

    def execute(self, params: KeeperParams, **kwargs):
        try:
            self._validate_inputs(**kwargs)
        except ValidationError as e:
            logging.error(f"{e}")
            return
        
        action = kwargs.get('action')
        device_identifiers = kwargs.get('devices', [])
        
        devices_response = self._make_api_call(
            params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
        )
        
        if devices_response is None:
            return  
        
        all_devices = DeviceResolver.extract_devices_from_response(devices_response)
        resolved_devices = DeviceResolver.resolve_device_identifiers_with_info(
            all_devices, device_identifiers, allow_multiple=False
        )
        
        if not resolved_devices:
            print("No matching devices found.")
            return
        
        device_tokens = [token for token, _ in resolved_devices]
        
        action_type = StatusMapper.get_action_type(action)
        request = DeviceManagement_pb2.DeviceActionRequest()
        device_action = request.deviceAction.add()
        device_action.deviceActionType = action_type
        device_action.encryptedDeviceToken.extend(device_tokens)
        
        response = self._make_api_call(
            params, request, 'dm/device_user_action', DeviceManagement_pb2.DeviceActionResponse
        )
        
        if response is None:
            return  
        
        self._device_info = {token: device for token, device in resolved_devices}
        self._action = action
        
        self._display_results(response.deviceActionResult, **kwargs)
        
        if self._has_successful_operations(response.deviceActionResult):
            self._show_updated_device_list(params)

    def _display_table(self, results: List, output_file: Optional[str] = None):
        """Display action results - only show success messages."""
        if not results:
            print("No results returned.")
            return
        
        self._show_success_messages(results)
        
        self._show_error_messages(results)
    
    def _show_success_messages(self, results: List):
        """Show user-friendly success messages for device actions."""
        if not hasattr(self, '_device_info') or not hasattr(self, '_action'):
            return
            
        for result in results:
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                for token in result.encryptedDeviceToken:
                    if token in self._device_info:
                        device = self._device_info[token]
                        device_name = device.deviceName or "Unknown Device"
                        action_verb = self._get_action_verb(self._action)
                        print(f"{bcolors.OKGREEN}✓{bcolors.ENDC} Device '{device_name}' successfully {action_verb}")
    
    def _get_action_verb(self, action: str) -> str:
        """Get the past tense verb for the action."""
        action_verbs = {
            'logout': 'logged out',
            'remove': 'removed',
            'lock': 'locked',
            'unlock': 'unlocked',
            'account-lock': 'account locked',
            'account-unlock': 'account unlocked',
            'link': 'linked',
            'unlink': 'unlinked',
        }
        return action_verbs.get(action, f'{action}ed')
    
    def _show_error_messages(self, results: List):
        """Show error messages for failed device actions."""
        if not hasattr(self, '_device_info') or not hasattr(self, '_action'):
            return
            
        for result in results:
            if result.deviceActionStatus != DeviceManagement_pb2.SUCCESS:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
                if result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                    error_msg = "Operation not allowed"
                else:
                    error_msg = f"Action failed ({status_name})"
                
                for token in result.encryptedDeviceToken:
                    if token in self._device_info:
                        device = self._device_info[token]
                        device_name = device.deviceName or "Unknown Device"
                        print(f"{bcolors.FAIL}✗{bcolors.ENDC} Device '{device_name}': {error_msg}")



class DeviceUserRenameCommand(BaseDeviceCommand):
    """Command to rename user devices."""
    
    def get_parser(self):
        return device_user_rename_parser

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        device_identifier = kwargs.get('device')
        new_name = kwargs.get('new_name')
        
        # Validate device identifier
        if not device_identifier:
            raise ValidationError("Device identifier is required")
        if not DeviceInputValidator.validate_device_identifier(device_identifier):
            raise ValidationError(f"Invalid device identifier: '{device_identifier}'")
        
        # Validate and sanitize new device name
        if not new_name:
            raise ValidationError("New device name is required")
        
        sanitized_name = DeviceInputValidator.sanitize_device_name(new_name)
        if not sanitized_name:
            raise ValidationError("Device name contains only invalid characters")
        
        # Update kwargs with sanitized name
        kwargs['new_name'] = sanitized_name

    def execute(self, params: KeeperParams, **kwargs):
        try:
            self._validate_inputs(**kwargs)
        except ValidationError as e:
            logging.error(f"Input validation failed: {e}")
            return
        
        device_identifier = kwargs.get('device')
        new_name = kwargs.get('new_name')
        
        # Get all devices for the user
        devices_response = self._make_api_call(
            params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
        )
        
        if devices_response is None:
            return  
        
        all_devices = DeviceResolver.extract_devices_from_response(devices_response)
        resolved_devices = DeviceResolver.resolve_device_identifiers_with_info(
            all_devices, [device_identifier], allow_multiple=False
        )
        
        if not resolved_devices:
            print("No matching device found.")
            return
        
        device_token, device = resolved_devices[0]
        old_name = device.deviceName or "Unknown Device"
        
        # Create and execute the rename request
        request = DeviceManagement_pb2.DeviceRenameRequest()
        device_rename = request.deviceRename.add()
        device_rename.encryptedDeviceToken = device_token
        device_rename.deviceNewName = new_name
        
        response = self._make_api_call(
            params, request, 'dm/device_user_rename', DeviceManagement_pb2.DeviceRenameResponse
        )
        
        if response is None:
            return  # Error was handled gracefully
        
        # Store device info for success messages
        self._old_name = old_name
        self._new_name = new_name
        
        self._display_results(response.deviceRenameResult, **kwargs)
        
        # Show updated device list after rename (only if there were successful operations)
        if self._has_successful_operations(response.deviceRenameResult):
            self._show_updated_device_list(params)

    def _display_table(self, results: List, output_file: Optional[str] = None):
        """Display rename results - only show success messages."""
        if not results:
            print("No results returned.")
            return
        
        # Only show success messages, no detailed table
        self._show_success_messages(results)
        
        # Show errors if any
        self._show_error_messages(results)
    
    def _show_success_messages(self, results: List):
        """Show user-friendly success messages for device rename."""
        if not hasattr(self, '_old_name') or not hasattr(self, '_new_name'):
            return
            
        for result in results:
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                print(f"{bcolors.OKGREEN}✓{bcolors.ENDC} Device name updated from '{self._old_name}' to '{self._new_name}'")
    
    def _show_error_messages(self, results: List):
        """Show error messages for failed device rename."""
        if not hasattr(self, '_old_name'):
            return
            
        for result in results:
            if result.deviceActionStatus != DeviceManagement_pb2.SUCCESS:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
                if result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                    error_msg = "Operation not allowed"
                else:
                    error_msg = f"Rename failed ({status_name})"
                
                print(f"{bcolors.FAIL}✗{bcolors.ENDC} Device '{self._old_name}': {error_msg}")



class DeviceAdminListCommand(BaseDeviceCommand):
    """Command to list all devices across users that the Admin has control of."""
    
    def get_parser(self):
        return device_admin_list_parser

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        enterprise_user_ids = kwargs.get('enterprise_user_ids', [])
        
        if not enterprise_user_ids:
            raise ValidationError("Enterprise User ID is required. You can get enterprise user IDs by running: ei --users")
        
        # Validate each enterprise user ID
        for user_id in enterprise_user_ids:
            if not DeviceInputValidator.validate_enterprise_user_id(user_id):
                raise ValidationError(f"Invalid enterprise user ID: {user_id}")

    def execute(self, params: KeeperParams, **kwargs):
        try:
            self._validate_inputs(**kwargs)
        except ValidationError as e:
            logging.error(f"Input validation failed: {e}")
            return
        
        enterprise_user_ids = kwargs.get('enterprise_user_ids', [])
        
        request = DeviceManagement_pb2.DeviceAdminRequest()
        request.enterpriseUserIds.extend(enterprise_user_ids)
        
        response = self._make_api_call(
            params, request, 'dm/device_admin_list', DeviceManagement_pb2.DeviceAdminResponse
        )
        
        if response is None:
            return  # Error was handled gracefully
        
        # Flatten the device data structure
        all_devices = []
        for device_user_group in response.deviceUserList:
            enterprise_user_id = device_user_group.enterpriseUserId
            for device_group in device_user_group.deviceGroups:
                for device in device_group.devices:
                    device_info = {
                        'enterprise_user_id': enterprise_user_id,
                        'device': device
                    }
                    all_devices.append(device_info)
        
        if not all_devices:
            print("No devices found.")
            return
        
        self._display_results(all_devices, **kwargs)

    def _display_table(self, devices: List, output_file: Optional[str] = None):
        """Display admin devices in table format."""
        headers = [
            'ID', 'Enterprise User ID', 'Device Name', 'UI Category',
            'Device Status', 'Login Status', 'Last Accessed'
        ]
        
        device_data = []
        for device_info in devices:
            device = device_info['device']
            enterprise_user_id = device_info['enterprise_user_id']
            
            device_data.append({
                'enterprise_user_id': enterprise_user_id,
                'name': device.deviceName or 'N/A',
                'ui_category': UICategory.get_ui_category(device),
                'device_status': StatusMapper.get_device_status_display(device.deviceStatus),
                'login_status': StatusMapper.get_login_status_display(device.loginState),
                'last_accessed': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            table_data.append([
                str(i),
                str(device['enterprise_user_id']),
                device['name'],
                device['ui_category'],
                device['device_status'],
                device['login_status'],
                device['last_accessed']
            ])
        
        title = f'Admin Device List ({len(table_data)} devices found)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_json(self, devices: List, output_file: Optional[str] = None):
        """Display admin devices in JSON format."""
        device_list = []
        for i, device_info in enumerate(devices, 1):
            device = device_info['device']
            enterprise_user_id = device_info['enterprise_user_id']
            
            device_info_json = {
                'id': i,
                'enterpriseUserId': enterprise_user_id,
                'deviceName': device.deviceName,
                'uiCategory': UICategory.get_ui_category(device),
                'deviceStatus': StatusMapper.get_device_status_display(device.deviceStatus),
                'loginStatus': StatusMapper.get_login_status_display(device.loginState),
                'lastAccessedTimestamp': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            }
            device_list.append(device_info_json)
        
        device_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        for i, device in enumerate(device_list, 1):
            device['id'] = i
            del device['timestamp']
        
        result = {
            'devices': device_list,
        }
        
        super()._display_json(result, output_file)


class DeviceAdminActionCommand(BaseDeviceCommand):
    """Command to perform actions on devices across enterprise users."""
    
    def get_parser(self):
        return device_admin_action_parser
    
    def get_action_parser(self, action):
        """Get action-specific parser for detailed help."""
        return device_admin_action_parsers.get(action)

    def execute_args(self, params: KeeperParams, args, **kwargs):
        """Override to handle action-specific help."""
        import shlex
        from .base import expand_cmd_args, normalize_output_param, ParseError
        
        try:
            # Parse arguments to check for action-specific help
            args = '' if args is None else args
            if params and hasattr(params, 'environment_variables'):
                args = expand_cmd_args(args, params.environment_variables)
            args = normalize_output_param(args)
            
            parsed_args = shlex.split(args)
            
            # Check for action-specific help in different positions:
            # "logout --help" (help in 2nd position)
            # "logout 123456 --help" (help in 3rd position)
            if len(parsed_args) >= 2 and parsed_args[1] in ['--help', '-h']:
                action = parsed_args[0]
                action_parser = self.get_action_parser(action)
                if action_parser:
                    action_parser.print_help()
                    return
            elif len(parsed_args) >= 3 and parsed_args[2] in ['--help', '-h']:
                action = parsed_args[0]
                action_parser = self.get_action_parser(action)
                if action_parser:
                    action_parser.print_help()
                    return
            
            # Fall back to default parsing
            return super().execute_args(params, args, **kwargs)
        except ParseError as e:
            logging.error(e)

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        devices = kwargs.get('devices', [])
        
        # Validate action
        if not action:
            raise ValidationError("Action is required")
        if not DeviceInputValidator.validate_action(action):
            raise ValidationError(f"Invalid action: '{action}'")
        
        # Validate enterprise user ID
        if not enterprise_user_id:
            raise ValidationError("Enterprise User ID is required")
        if not DeviceInputValidator.validate_enterprise_user_id(enterprise_user_id):
            raise ValidationError(f"Invalid enterprise user ID: {enterprise_user_id}")
        
        # Validate and sanitize device identifiers
        if not devices:
            raise ValidationError("At least one device must be specified")
        
        try:
            validated_devices = DeviceInputValidator.validate_device_identifiers_list(devices)
        except ValidationError as e:
            raise ValidationError(f"Device validation failed: {e}")
        
        # Update kwargs with validated devices
        kwargs['devices'] = validated_devices

    def execute(self, params: KeeperParams, **kwargs):
        try:
            self._validate_inputs(**kwargs)
        except ValidationError as e:
            logging.error(f"Input validation failed: {e}")
            return
        
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        device_identifiers = kwargs.get('devices', [])
        
        # Get the list of devices for the specified enterprise user
        list_request = DeviceManagement_pb2.DeviceAdminRequest()
        list_request.enterpriseUserIds.append(enterprise_user_id)
        
        devices_response = self._make_api_call(
            params, list_request, 'dm/device_admin_list', DeviceManagement_pb2.DeviceAdminResponse
        )
        
        if devices_response is None:
            return  # Error was handled gracefully
        
        # Resolve device identifiers to device tokens and keep device info for success messages
        all_devices = DeviceResolver.extract_devices_from_response(devices_response, enterprise_user_id)
        resolved_devices = DeviceResolver.resolve_device_identifiers_with_info(
            all_devices, device_identifiers, allow_multiple=False, enterprise_user_id=enterprise_user_id
        )
        
        if not resolved_devices:
            print("No matching devices found.")
            return
        
        device_tokens = [token for token, _ in resolved_devices]
        action_type = StatusMapper.get_action_type(action)
        

        
        # Create and execute the device admin action request
        request = DeviceManagement_pb2.DeviceAdminActionRequest()
        admin_action = request.deviceAdminAction.add()
        admin_action.deviceActionType = action_type
        admin_action.enterpriseUserId = enterprise_user_id
        admin_action.encryptedDeviceToken.extend(device_tokens)
        
        response = self._make_api_call(
            params, request, 'dm/device_admin_action', DeviceManagement_pb2.DeviceAdminActionResponse
        )
        
        if response is None:
            return  # Error was handled gracefully
        
        self._device_info = {token: device for token, device in resolved_devices}
        self._action = action
        self._enterprise_user_id = enterprise_user_id
        
        self._display_results(response.deviceAdminActionResults, **kwargs)
        
        # Show updated device list after admin action (only if there were successful operations)
        if self._has_successful_operations(response.deviceAdminActionResults):
            self._show_updated_device_list(params, enterprise_user_id)


    def _display_table(self, results: List, output_file: Optional[str] = None):
        """Display admin action results - only show success messages."""
        if not results:
            print("No results returned.")
            return
        
        self._show_success_messages(results)
        
        self._show_error_messages(results)
    
    def _show_success_messages(self, results: List):
        """Show user-friendly success messages for device admin actions."""
        if not hasattr(self, '_device_info') or not hasattr(self, '_action') or not hasattr(self, '_enterprise_user_id'):
            return
            
        for result in results:
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                action_verb = self._get_action_verb(self._action)
                device_count = len(result.encryptedDeviceToken)
                
                if device_count == 1:
                    # Show specific device name for single device
                    for token in result.encryptedDeviceToken:
                        if token in self._device_info:
                            device = self._device_info[token]
                            device_name = device.deviceName or "Unknown Device"
                            print(f"{bcolors.OKGREEN}✓{bcolors.ENDC} Device action successfully completed: '{device_name}' {action_verb} for user {self._enterprise_user_id}")
                            break
                else:
                    # Show count for multiple devices
                    print(f"{bcolors.OKGREEN}✓{bcolors.ENDC} Device action successfully completed: {device_count} devices {action_verb} for user {self._enterprise_user_id}")
    
    def _get_action_verb(self, action: str) -> str:
        """Get the past tense verb for the action."""
        action_verbs = {
            'logout': 'logged out',
            'remove': 'removed',
            'lock': 'locked',
            'unlock': 'unlocked',
            'account-lock': 'account locked',
            'account-unlock': 'account unlocked',
        }
        return action_verbs.get(action, f'{action}ed')
    
    def _show_error_messages(self, results: List):
        """Show error messages for failed device admin actions."""
        if not hasattr(self, '_device_info') or not hasattr(self, '_enterprise_user_id'):
            return
            
        for result in results:
            if result.deviceActionStatus != DeviceManagement_pb2.SUCCESS:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
                if result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                    error_msg = "Operation not allowed"
                else:
                    error_msg = f"Action failed ({status_name})"
                
                device_count = len(result.encryptedDeviceToken)
                
                if device_count == 1:
                    # Show specific device name for single device
                    for token in result.encryptedDeviceToken:
                        if token in self._device_info:
                            device = self._device_info[token]
                            device_name = device.deviceName or "Unknown Device"
                            print(f"{bcolors.FAIL}✗{bcolors.ENDC} Device '{device_name}' for user {self._enterprise_user_id}: {error_msg}")
                            break
                else:
                    print(f"{bcolors.FAIL}✗{bcolors.ENDC} {device_count} devices for user {self._enterprise_user_id}: {error_msg}")

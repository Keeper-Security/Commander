#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Any, List, Dict, Union, Tuple

from .. import api, utils
from ..proto import DeviceManagement_pb2, APIRequest_pb2
from .base import Command, dump_report_data
from ..display import bcolors
from ..params import KeeperParams
from ..error import KeeperApiError


# ============================================================================
# Utility Classes and Mixins
# ============================================================================

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
        'logout': 'Logout the enterprise user from the device',
        'remove': 'Logout & Remove the enterprise user from that device',
        'lock': 'Lock the device for all users and auto linked devices. Logout all users',
        'unlock': 'Unlock the devices and auto linked devices for the enterprise user',
        'account-lock': 'Lock the device for the enterprise user only. If user is logged in, logout',
        'account-unlock': 'Unlock the device for the enterprise user',
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
    
    @staticmethod
    def get_ui_category(device) -> str:
        """Determine UI category based on client type, client type category, and client form factor."""
        client_type = device.clientType
        client_type_category = device.clientTypeCategory
        client_form_factor = device.clientFormFactor
        
        # Browser Extension
        if client_type_category == DeviceManagement_pb2.CAT_EXTENSION:
            return "Browser Extension"
        
        # Mobile
        if (client_type_category == DeviceManagement_pb2.CAT_MOBILE and 
            client_form_factor == APIRequest_pb2.FF_PHONE):
            return "Mobile"
        
        # Tablet
        if (client_type_category == DeviceManagement_pb2.CAT_MOBILE and 
            client_form_factor == APIRequest_pb2.FF_TABLET):
            return "Tablet"
        
        # Desktop
        if client_type_category == DeviceManagement_pb2.CAT_DESKTOP:
            return "Desktop"
        
        # Web Vault
        if client_type_category == DeviceManagement_pb2.CAT_WEB_VAULT:
            return "Web Vault"
        
        # Admin Console
        if (client_type == DeviceManagement_pb2.ENTERPRISE_MANAGEMENT_CONSOLE and 
            client_type_category == DeviceManagement_pb2.CAT_ADMIN):
            return "Admin Console"
        
        # Wear OS
        if (client_type_category == DeviceManagement_pb2.CAT_MOBILE and 
            client_form_factor == APIRequest_pb2.FF_WATCH):
            return "Wear OS"
        
        # iOS App
        if client_type == DeviceManagement_pb2.IOS and client_type_category == DeviceManagement_pb2.CAT_MOBILE:
            return "iOS App"
        
        # Android App
        if client_type == DeviceManagement_pb2.ANDROID and client_type_category == DeviceManagement_pb2.CAT_MOBILE:
            return "Android App"
        
        # Commander CLI
        if client_type == DeviceManagement_pb2.COMMANDER and client_type_category == DeviceManagement_pb2.CAT_ADMIN:
            return "Commander CLI"
        
        return "Unknown Device"


class DeviceResolver:
    """Service for resolving device identifiers to device tokens."""
    
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
    def resolve_device_identifiers(all_devices: List, device_identifiers: List[str], 
                                 allow_multiple: bool = True, enterprise_user_id: Optional[int] = None) -> List[bytes]:
        """Resolve device identifiers to device tokens."""
        resolved_tokens = []
        
        for identifier in device_identifiers:
            matched_devices = DeviceResolver._find_matching_devices(all_devices, identifier)
            
            if not matched_devices:
                user_context = f" for user {enterprise_user_id}" if enterprise_user_id else ""
                logging.warning(f"Warning: No device found matching '{identifier}'{user_context}")
                continue
            elif len(matched_devices) > 1 and not allow_multiple:
                DeviceResolver._handle_multiple_matches(matched_devices, all_devices, identifier, enterprise_user_id)
                continue
            elif len(matched_devices) > 1:
                logging.warning(f"Warning: Multiple devices found matching '{identifier}'. Using first match.")
                resolved_tokens.append(matched_devices[0].encryptedDeviceToken)
            else:
                resolved_tokens.append(matched_devices[0].encryptedDeviceToken)
                
        return resolved_tokens
    
    @staticmethod
    def resolve_device_identifiers_with_info(all_devices: List, device_identifiers: List[str], 
                                           allow_multiple: bool = True, enterprise_user_id: Optional[int] = None) -> List[Tuple[bytes, Any]]:
        """Resolve device identifiers to device tokens and return device info for success messages."""
        resolved_devices = []
        
        for identifier in device_identifiers:
            matched_devices = DeviceResolver._find_matching_devices(all_devices, identifier)
            
            if not matched_devices:
                user_context = f" for user {enterprise_user_id}" if enterprise_user_id else ""
                logging.warning(f"Warning: No device found matching '{identifier}'{user_context}")
                continue
            elif len(matched_devices) > 1 and not allow_multiple:
                DeviceResolver._handle_multiple_matches(matched_devices, all_devices, identifier, enterprise_user_id)
                continue
            elif len(matched_devices) > 1:
                logging.warning(f"Warning: Multiple devices found matching '{identifier}'. Using first match.")
                resolved_devices.append((matched_devices[0].encryptedDeviceToken, matched_devices[0]))
            else:
                resolved_devices.append((matched_devices[0].encryptedDeviceToken, matched_devices[0]))
                
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
        
        # Try to match by device ID (numeric index)
        try:
            device_id = int(identifier)
            if 1 <= device_id <= len(all_devices):
                return [all_devices[device_id - 1]]
            else:
                logging.warning(f"Device ID {device_id} is out of range (1-{len(all_devices)})")
                return []
        except ValueError:
            pass
        
        # Try other matching methods
        for device in all_devices:
            # Check if it's a direct token match (base64 encoded)
            try:
                decoded_token = utils.base64_url_decode(identifier)
                if device.encryptedDeviceToken == decoded_token:
                    return [device]
            except:
                pass
                
            # Check for name match (case insensitive, partial match)
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
    def handle_api_error(error: KeeperApiError, operation: str):
        """Handle KeeperApiError with consistent messaging."""
        if error.result_code == 'forbidden':
            logging.error(f"{bcolors.FAIL}Error: {error.message}{bcolors.ENDC}")
            if operation == 'device_admin_action':
                print("This error typically occurs when:")
                print("- The device tokens are invalid or not owned by the specified user")
                print("- The admin doesn't have permission to perform actions on this user's devices")
                print("- The target devices are not accessible")
        elif error.result_code == 'bad_request':
            logging.error(f"{bcolors.FAIL}Bad Request: {error.message}{bcolors.ENDC}")
        else:
            logging.error(f"{bcolors.FAIL}API Error: {error.message} (Code: {error.result_code}){bcolors.ENDC}")
    
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
    
    def _make_api_call(self, params: KeeperParams, request: Any, endpoint: str, response_type: Any) -> Any:
        """Make API call with consistent error handling."""
        try:
            return api.communicate_rest(params, request, endpoint, rs_type=response_type)
        except KeeperApiError as kae:
            ErrorHandler.handle_api_error(kae, endpoint.split('/')[-1])
            raise
        except Exception as e:
            ErrorHandler.handle_general_error(e, endpoint.split('/')[-1])
            raise


# ============================================================================
# Argument Parsers
# ============================================================================

device_user_list_parser = argparse.ArgumentParser(prog='device-list', description='List all active devices for the current user')
device_user_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                     default='table', help='output format')
device_user_list_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

device_user_action_parser = argparse.ArgumentParser(prog='device-action', description='Perform actions on user devices')
device_user_action_parser.add_argument('action', choices=['logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock', 'link', 'unlink'], 
                                       help='Action to perform on devices')
device_user_action_parser.add_argument('devices', nargs='+', 
                                       help='Device IDs (1, 2, 3...), device tokens, or device names (supports partial matches)')

device_user_rename_parser = argparse.ArgumentParser(prog='device-rename', description='Rename user devices')
device_user_rename_parser.add_argument('device', help='Device ID (1, 2, 3...), device token, or device name')
device_user_rename_parser.add_argument('new_name', help='New name for the device')


device_admin_list_parser = argparse.ArgumentParser(prog='device-admin-list', description='List all devices across users that the Admin has control of')
device_admin_list_parser.add_argument('enterprise_user_ids', nargs='*', type=int, 
                                      help='List of Enterprise User IDs (optional - if not provided, lists all users)')
device_admin_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                     default='table', help='output format')
device_admin_list_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

device_admin_action_parser = argparse.ArgumentParser(prog='device-admin-action', description='Perform actions on devices across enterprise users')
device_admin_action_parser.add_argument('action', choices=['logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock'], 
                                        help='Action to perform on devices')
device_admin_action_parser.add_argument('enterprise_user_id', type=int,
                                        help='Enterprise User ID whose devices to act on')
device_admin_action_parser.add_argument('devices', nargs='+', 
                                        help='Device IDs, tokens, or names (supports partial matches)')
device_admin_action_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                        default='table', help='output format')
device_admin_action_parser.add_argument('--output', dest='output', action='store',
                                        help='output file name. (ignored for table format)')



def register_commands(commands):
    commands['device-list'] = DeviceUserListCommand()
    commands['device-action'] = DeviceUserActionCommand()
    commands['device-rename'] = DeviceUserRenameCommand()
    commands['device-admin-list'] = DeviceAdminListCommand()
    commands['device-admin-action'] = DeviceAdminActionCommand()


def register_command_info(aliases, command_info):
    command_info['device-list'] = 'List all active devices for the current user'
    command_info['device-action'] = 'Perform actions on user devices'
    command_info['device-rename'] = 'Rename user devices'
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
        for device in devices:
            device_info = {
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
        self._display_json(result, output_file)


class DeviceUserActionCommand(BaseDeviceCommand):
    """Command to perform actions on user devices."""

    def get_parser(self):
        return device_user_action_parser

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        action = kwargs.get('action')
        devices = kwargs.get('devices', [])
        
        if not action:
            raise ValueError("Action is required")
        if not devices:
            raise ValueError("At least one device must be specified")

    def execute(self, params: KeeperParams, **kwargs):
        self._validate_inputs(**kwargs)
        
        action = kwargs.get('action')
        device_identifiers = kwargs.get('devices', [])
        
        # Get all devices for the user
        devices_response = self._make_api_call(
            params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
        )
        
        # Resolve device identifiers to tokens and keep device info for success messages
        all_devices = DeviceResolver.extract_devices_from_response(devices_response)
        resolved_devices = DeviceResolver.resolve_device_identifiers_with_info(
            all_devices, device_identifiers, allow_multiple=False
        )
        
        if not resolved_devices:
            print("No matching devices found.")
            return
        
        device_tokens = [token for token, _ in resolved_devices]
        
        # Create and execute the action request
        action_type = StatusMapper.get_action_type(action)
        request = DeviceManagement_pb2.DeviceActionRequest()
        device_action = request.deviceAction.add()
        device_action.deviceActionType = action_type
        device_action.encryptedDeviceToken.extend(device_tokens)
        
        response = self._make_api_call(
            params, request, 'dm/device_user_action', DeviceManagement_pb2.DeviceActionResponse
        )
        
        # Store device info for success messages
        self._device_info = {token: device for token, device in resolved_devices}
        self._action = action
        
        self._display_results(response.deviceActionResult, **kwargs)

    def _display_table(self, results: List, output_file: Optional[str] = None):
        """Display action results - only show success messages."""
        if not results:
            print("No results returned.")
            return
        
        # Only show success messages, no detailed table
        self._show_success_messages(results)
        
        # Show errors if any
        self._show_error_messages(results)
    
    def _show_success_messages(self, results: List):
        """Show user-friendly success messages for device actions."""
        if not hasattr(self, '_device_info') or not hasattr(self, '_action'):
            return
            
        for result in results:
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                # Find the device info for each successful token
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
                
                # Find the device info for each failed token
                for token in result.encryptedDeviceToken:
                    if token in self._device_info:
                        device = self._device_info[token]
                        device_name = device.deviceName or "Unknown Device"
                        print(f"{bcolors.FAIL}✗{bcolors.ENDC} Device '{device_name}': {error_msg}")

    def _display_json(self, results: List, output_file: Optional[str] = None):
        """Display action results in JSON format."""
        result_list = []
        for result in results:
            result_info = {
                'actionType': DeviceManagement_pb2.DeviceActionType.Name(result.deviceActionType),
                'status': DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus),
                'success': result.deviceActionStatus == DeviceManagement_pb2.SUCCESS,
            }
            result_list.append(result_info)
        
        output_data = {
            'deviceActionResults': result_list,
            'totalActions': len(result_list)
        }
        
        super()._display_json(output_data, output_file)


class DeviceUserRenameCommand(BaseDeviceCommand):
    """Command to rename user devices."""
    
    def get_parser(self):
        return device_user_rename_parser

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        device_identifier = kwargs.get('device')
        new_name = kwargs.get('new_name')
        
        if not device_identifier:
            raise ValueError("Device identifier is required")
        if not new_name:
            raise ValueError("New device name is required")

    def execute(self, params: KeeperParams, **kwargs):
        self._validate_inputs(**kwargs)
        
        device_identifier = kwargs.get('device')
        new_name = kwargs.get('new_name')
        
        # Get all devices for the user
        devices_response = self._make_api_call(
            params, None, 'dm/device_user_list', DeviceManagement_pb2.DeviceUserResponse
        )
        
        # Resolve device identifier to token and keep device info for success messages
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
        
        # Store device info for success messages
        self._old_name = old_name
        self._new_name = new_name
        
        self._display_results(response.deviceRenameResult, **kwargs)

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

    def _display_json(self, results: List, output_file: Optional[str] = None):
        """Display rename results in JSON format."""
        result_list = []
        for result in results:
            result_info = {
                'status': DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus),
                'success': result.deviceActionStatus == DeviceManagement_pb2.SUCCESS,
                'newDeviceName': result.deviceNewName,
                'encryptedDeviceToken': result.encryptedDeviceToken.hex() if result.encryptedDeviceToken else None
            }
            result_list.append(result_info)
        
        output_data = {
            'deviceRenameResults': result_list,
            'totalOperations': len(result_list)
        }
        
        super()._display_json(output_data, output_file)

class DeviceAdminListCommand(BaseDeviceCommand):
    """Command to list all devices across users that the Admin has control of."""
    
    def get_parser(self):
        return device_admin_list_parser

    def execute(self, params: KeeperParams, **kwargs):
        enterprise_user_ids = kwargs.get('enterprise_user_ids', [])
        
        request = None
        if enterprise_user_ids:
            request = DeviceManagement_pb2.DeviceAdminRequest()
            request.enterpriseUserIds.extend(enterprise_user_ids)
        
        response = self._make_api_call(
            params, request, 'dm/device_admin_list', DeviceManagement_pb2.DeviceAdminResponse
        )
        
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
        for device_info in devices:
            device = device_info['device']
            enterprise_user_id = device_info['enterprise_user_id']
            
            device_info_json = {
                'enterpriseUserId': enterprise_user_id,
                'deviceName': device.deviceName,
                'uiCategory': UICategory.get_ui_category(device),
                'deviceStatus': StatusMapper.get_device_status_display(device.deviceStatus),
                'loginStatus': StatusMapper.get_login_status_display(device.loginState),
                'clientType': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'clientTypeCategory': DeviceManagement_pb2.ClientTypeCategory.Name(device.clientTypeCategory) if device.clientTypeCategory else None,
                'clientFormFactor': APIRequest_pb2.ClientFormFactor.Name(device.clientFormFactor) if device.clientFormFactor else None,
                'clientVersion': device.clientVersion,
                'devicePlatform': device.devicePlatform,
                'lastModifiedTime': TimestampFormatter.format_timestamp(device.lastModifiedTime),
                'timestamp': device.lastModifiedTime or 0
            }
            device_list.append(device_info_json)
        
        device_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        for i, device in enumerate(device_list, 1):
            device['id'] = i
            del device['timestamp']
        
        result = {
            'devices': device_list,
            'totalDevices': len(device_list)
        }
        
        super()._display_json(result, output_file)


class DeviceAdminActionCommand(BaseDeviceCommand):
    """Command to perform actions on devices across enterprise users."""
    
    def get_parser(self):
        return device_admin_action_parser

    def _validate_inputs(self, **kwargs):
        """Validate required inputs."""
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        devices = kwargs.get('devices', [])
        
        if not action:
            raise ValueError("Action is required")
        if not enterprise_user_id:
            raise ValueError("Enterprise User ID is required")
        if not devices:
            raise ValueError("At least one device must be specified")

    def execute(self, params: KeeperParams, **kwargs):
        self._validate_inputs(**kwargs)
        
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        device_identifiers = kwargs.get('devices', [])
        
        # Get the list of devices for the specified enterprise user
        list_request = DeviceManagement_pb2.DeviceAdminRequest()
        list_request.enterpriseUserIds.append(enterprise_user_id)
        
        devices_response = self._make_api_call(
            params, list_request, 'dm/device_admin_list', DeviceManagement_pb2.DeviceAdminResponse
        )
        
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
        
        # Store device info for success messages
        self._device_info = {token: device for token, device in resolved_devices}
        self._action = action
        self._enterprise_user_id = enterprise_user_id
        
        self._display_results(response.deviceAdminActionResults, **kwargs)


    def _display_table(self, results: List, output_file: Optional[str] = None):
        """Display admin action results - only show success messages."""
        if not results:
            print("No results returned.")
            return
        
        # Only show success messages, no detailed table
        self._show_success_messages(results)
        
        # Show errors if any
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
                    # Show count for multiple devices
                    print(f"{bcolors.FAIL}✗{bcolors.ENDC} {device_count} devices for user {self._enterprise_user_id}: {error_msg}")

    def _display_json(self, results: List, output_file: Optional[str] = None):
        """Display admin action results in JSON format."""
        result_list = []
        for result in results:
            result_info = {
                'enterpriseUserId': result.enterpriseUserId,
                'actionType': DeviceManagement_pb2.DeviceActionType.Name(result.deviceActionType),
                'status': DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus),
                'success': result.deviceActionStatus == DeviceManagement_pb2.SUCCESS,
                'deviceTokens': [
                    {'encryptedToken': token.hex()} for token in result.encryptedDeviceToken
                ],
                'deviceCount': len(result.encryptedDeviceToken)
            }
            result_list.append(result_info)
        
        output_data = {
            'deviceAdminActionResults': result_list,
            'totalActions': len(result_list)
        }
        
        super()._display_json(output_data, output_file)
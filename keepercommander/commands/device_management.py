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
import logging
from typing import Optional, Any

from .. import api, utils
from ..proto import DeviceManagement_pb2, APIRequest_pb2
from .base import Command, dump_report_data
from ..display import bcolors
from ..params import KeeperParams
from ..error import KeeperApiError


device_user_list_parser = argparse.ArgumentParser(prog='device-list', description='List all active devices for the current user')
device_user_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                     default='table', help='output format')
device_user_list_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

device_user_action_parser = argparse.ArgumentParser(prog='device-action', description='Perform actions on user devices')
device_user_action_parser.add_argument('action', choices=['logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock', 'link', 'unlink'], 
                                       help='Action to perform on devices')
device_user_action_parser.add_argument('devices', nargs='+', 
                                       help='Device tokens or device names (supports partial matches)')
device_user_action_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], 
                                       default='table', help='output format')
device_user_action_parser.add_argument('--output', dest='output', action='store',
                                       help='output file name. (ignored for table format)')
device_user_action_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                       help='Show what would be done without executing the action')
device_user_action_parser.add_argument('--list-with-indices', dest='list_with_indices', action='store_true',
                                       help='List devices with numeric indices that can be used as device identifiers')


def register_commands(commands):
    commands['device-list'] = DeviceUserListCommand()
    commands['device-action'] = DeviceUserActionCommand()


def register_command_info(aliases, command_info):
    command_info['device-list'] = 'List all active devices for the current user'
    command_info['device-action'] = 'Perform actions on user devices'


class DeviceUserListCommand(Command):
    """
    Command to list all approved/active devices of the user across all platforms.
    Uses the device_user_list REST API endpoint.
    """
    
    def get_parser(self):
        return device_user_list_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
        """
        Execute the device-list command.
        
        This command calls the @https://keepersecurity.com/api/rest/dm/device_user_list endpoint
        which returns a DeviceUserResponse containing device groups and devices.
        """
        try:
            # The device_user_list endpoint requires no request payload
            # Call the REST API endpoint
            rs = api.communicate_rest(
                params, 
                None,  # No request payload needed
                'dm/device_user_list',
                rs_type=DeviceManagement_pb2.DeviceUserResponse
            )
            
            # Process and display the response
            self._display_devices(rs, **kwargs)
            
        except Exception as e:
            logging.error(f"Failed to retrieve device list: {e}")
            raise

    def _display_devices(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceUserResponse, Any) -> None
        """
        Display the device information in the requested format.
        """
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        # Collect all devices from all groups
        all_devices = []
        for device_group in response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        if not all_devices:
            print("No devices found.")
            return
        
        if fmt == 'json':
            self._display_json(all_devices, output)
        else:
            self._display_table(all_devices, output)

    def _display_table(self, devices, output_file=None):
        # type: (list, Optional[str]) -> None
        """Display devices in table format."""
        
        headers = [
            'Device Name', 
            'Client Type',
            'Login Status',
            'Last Accessed'
        ]
        
        # Create list with devices and their timestamps for proper sorting
        device_data = []
        for device in devices:
            # Get client type name for better readability
            client_type_name = DeviceManagement_pb2.ClientType.Name(device.clientType)
            
            # Convert epoch timestamp to readable format
            last_accessed = self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else 'N/A'
            
            # Determine if this is the current device (logged in)
            is_current_device = "Logged IN" if device.loginState == APIRequest_pb2.LoginState.LOGGED_IN else "Logged OUT"
            
            device_data.append({
                'name': device.deviceName or 'N/A',
                'client_type': client_type_name,
                'is_current': is_current_device,
                'last_accessed': last_accessed,
                'timestamp': device.lastModifiedTime or 0
            })
        
        # Sort by timestamp (most recent first)
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Build table data
        table_data = []
        for device in device_data:
            row = [
                device['name'],
                device['client_type'],
                device['is_current'],
                device['last_accessed']
            ]
            table_data.append(row)
        
        title = f'User Devices ({len(table_data)} found)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_json(self, devices, output_file=None):
        # type: (list, Optional[str]) -> None
        """Display devices in JSON format."""
        import json
        
        device_list = []
        for device in devices:
            device_info = {
                'deviceName': device.deviceName,
                'clientType': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'isCurrentDevice': device.loginState == APIRequest_pb2.LoginState.LOGGED_IN,
                'lastAccessedTimestamp': self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else None
            }
            device_list.append(device_info)
        
        # Sort by timestamp (most recent first)
        device_list.sort(key=lambda x: x['lastAccessedTimestamp'] or 0, reverse=True)
        
        result = {
            'devices': device_list,
        }
        
        json_output = json.dumps(result, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Device list saved to {output_file}")
        else:
            print(json_output)

    def _get_ui_category(self, client_type, client_type_category, client_form_factor):
        # type: (int, int, int) -> str
        """
        Apply UI categorization logic as specified in the API documentation.
        """
        # Map based on the specification logic
        if client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_EXTENSION:
            return 'Browser Extension'
        elif client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_MOBILE and client_form_factor == APIRequest_pb2.ClientFormFactor.FF_PHONE:
            if client_type == DeviceManagement_pb2.ClientType.IOS:
                return 'iOS App'
            elif client_type == DeviceManagement_pb2.ClientType.ANDROID:
                return 'Android App'
            else:
                return 'Mobile'
        elif client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_MOBILE and client_form_factor == APIRequest_pb2.ClientFormFactor.FF_TABLET:
            return 'Tablet'
        elif client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_DESKTOP:
            return 'Desktop'
        elif client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_WEB_VAULT:
            return 'Web Vault'
        elif client_type == DeviceManagement_pb2.ClientType.ENTERPRISE_MANAGEMENT_CONSOLE and client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_ADMIN:
            return 'Admin Console'
        elif client_type_category == DeviceManagement_pb2.ClientTypeCategory.CAT_MOBILE and client_form_factor == APIRequest_pb2.ClientFormFactor.FF_WATCH:
            return 'Wear OS'
        else:
            return 'Unknown Device'

    def _format_timestamp(self, timestamp):
        # type: (int) -> str
        """Convert Unix timestamp to readable format."""
        try:
            from datetime import datetime
            # Convert milliseconds to seconds if needed
            if timestamp > 10000000000:  # If timestamp is in milliseconds
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError, TypeError):
            return f'Invalid timestamp: {timestamp}'


class DeviceUserActionCommand(Command):
    """
    Command to perform actions on user devices.
    Uses the device_user_action REST API endpoint.
    """

    def get_parser(self):
        return device_user_action_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
        """
        Execute the device-action command.
        
        This command calls the @https://keepersecurity.com/api/rest/dm/device_user_action endpoint
        to perform various actions on devices.
        """
        action = kwargs.get('action')
        devices = kwargs.get('devices', [])
        dry_run = kwargs.get('dry_run', False)
        list_with_indices = kwargs.get('list_with_indices', False)
        
        # First, get the list of all devices
        all_devices_response = api.communicate_rest(
            params, 
            None,
            'dm/device_user_list',
            rs_type=DeviceManagement_pb2.DeviceUserResponse
        )
        
        # If list_with_indices is requested, show the list and exit
        if list_with_indices:
            self._show_devices_with_indices(all_devices_response)
            return
        
        if not action:
            raise ValueError("Action is required")
        if not devices:
            raise ValueError("At least one device must be specified")

        try:
            
            # Resolve device identifiers to device tokens
            device_tokens = self._resolve_devices(all_devices_response, devices)
            
            if not device_tokens:
                print("No matching devices found.")
                return
            
            # Map action string to protobuf enum
            action_type = self._get_action_type(action)
            
            # Show what will be done if dry run
            if dry_run:
                self._show_dry_run(all_devices_response, device_tokens, action, action_type)
                return
            
            # Create the device action request
            request = DeviceManagement_pb2.DeviceActionRequest()
            device_action = request.deviceAction.add()
            device_action.deviceActionType = action_type
            device_action.encryptedDeviceToken.extend(device_tokens)
            
            # Execute the action
            response = api.communicate_rest(
                params, 
                request,
                'dm/device_user_action',
                rs_type=DeviceManagement_pb2.DeviceActionResponse
            )
            
            # Display the results
            self._display_action_results(response, **kwargs)
            
        except KeeperApiError as kae:
            if kae.result_code == 'forbidden':
                print(f"{bcolors.FAIL}Error: {kae.message}{bcolors.ENDC}")
                print("This error typically occurs when:")
                print("- The device tokens are invalid or not owned by the user")
                print("- The user doesn't have permission to perform this action")
                print("- The target devices are not accessible")
            else:
                print(f"{bcolors.FAIL}API Error: {kae.message} (Code: {kae.result_code}){bcolors.ENDC}")
            raise
        except Exception as e:
            logging.error(f"Failed to perform device action: {e}")
            print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            raise

    def _resolve_devices(self, devices_response, device_identifiers):
        # type: (DeviceManagement_pb2.DeviceUserResponse, list) -> list
        """
        Resolve device identifiers (names or tokens) to device tokens.
        """
        all_devices = []
        for device_group in devices_response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        resolved_tokens = []
        
        for identifier in device_identifiers:
            # Try to match by device name (partial match supported)
            matched_devices = []
            # Try to match by index first (if it's a number)
            try:
                device_index = int(identifier)
                if 0 <= device_index < len(all_devices):
                    matched_devices = [all_devices[device_index]]
                else:
                    print(f"Warning: Device index {device_index} is out of range (0-{len(all_devices)-1})")
                    continue
            except ValueError:
                # Not a number, try other matching methods
                for device in all_devices:
                    # Check if it's a direct token match (base64 encoded)
                    try:
                        decoded_token = utils.base64_url_decode(identifier)
                        if device.encryptedDeviceToken == decoded_token:
                            matched_devices = [device]
                            break
                    except:
                        pass
                        
                    # Check for name match (case insensitive, partial match)
                    if device.deviceName and identifier.lower() in device.deviceName.lower():
                        matched_devices.append(device)
            
            if not matched_devices:
                print(f"Warning: No device found matching '{identifier}'")
                continue
            elif len(matched_devices) > 1:
                print(f"Warning: Multiple devices found matching '{identifier}':")
                for device in matched_devices:
                    print(f"  - {device.deviceName}")
                print("Please be more specific. Skipping this identifier.")
                continue
            else:
                resolved_tokens.append(matched_devices[0].encryptedDeviceToken)
                
        return resolved_tokens

    def _get_action_type(self, action):
        # type: (str) -> int
        """Map action string to DeviceActionType enum value."""
        action_map = {
            'logout': DeviceManagement_pb2.DA_LOGOUT,
            'remove': DeviceManagement_pb2.DA_REMOVE,
            'lock': DeviceManagement_pb2.DA_LOCK,
            'unlock': DeviceManagement_pb2.DA_UNLOCK,
            'account-lock': DeviceManagement_pb2.DA_DEVICE_ACCOUNT_LOCK,
            'account-unlock': DeviceManagement_pb2.DA_DEVICE_ACCOUNT_UNLOCK,
            'link': DeviceManagement_pb2.DA_LINK,
            'unlink': DeviceManagement_pb2.DA_UNLINK,
        }
        
        if action not in action_map:
            raise ValueError(f"Unknown action: {action}")
            
        return action_map[action]

    def _show_dry_run(self, devices_response, device_tokens, action, action_type):
        # type: (DeviceManagement_pb2.DeviceUserResponse, list, str, int) -> None
        """Show what would be done in a dry run."""
        print(f"DRY RUN: Would perform action '{action}' on the following devices:")
        print()
        
        # Find the devices that match the tokens
        all_devices = []
        for device_group in devices_response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        for token in device_tokens:
            for device in all_devices:
                if device.encryptedDeviceToken == token:
                    client_type_name = DeviceManagement_pb2.ClientType.Name(device.clientType)
                    print(f"  - {device.deviceName} ({client_type_name})")
                    break
        
        print()
        print(f"Action: {DeviceManagement_pb2.DeviceActionType.Name(action_type)}")
        print(f"Description: {self._get_action_description(action)}")

    def _get_action_description(self, action):
        # type: (str) -> str
        """Get human-readable description of the action."""
        descriptions = {
            'logout': 'Logout the calling user from the device',
            'remove': 'Logout & Remove only the calling user from that device',
            'lock': 'Lock the device for all users on the devices and the associated auto linked devices. Logout all users from the device',
            'unlock': 'Unlock the devices and the associated auto linked devices for the calling user',
            'account-lock': 'Lock the device for the calling user only. If calling user is logged in, logout the calling user',
            'account-unlock': 'Unlock the device for the calling user',
            'link': 'Link the devices and the associated auto linked for the calling user',
            'unlink': 'Unlink devices and the associated auto linked devices for the calling user',
        }
        return descriptions.get(action, 'Unknown action')

    def _show_devices_with_indices(self, devices_response):
        # type: (DeviceManagement_pb2.DeviceUserResponse) -> None
        """Show devices with numeric indices for easy selection."""
        all_devices = []
        for device_group in devices_response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        if not all_devices:
            print("No devices found.")
            return
        
        print("Available devices:")
        print()
        headers = ['Index', 'Device Name', 'Client Type', 'Login Status']
        table_data = []
        
        for i, device in enumerate(all_devices):
            client_type_name = DeviceManagement_pb2.ClientType.Name(device.clientType)
            is_current_device = "Logged IN" if device.loginState == APIRequest_pb2.LoginState.LOGGED_IN else "Logged OUT"
            
            table_data.append([
                str(i),
                device.deviceName or 'N/A',
                client_type_name,
                is_current_device
            ])
        
        dump_report_data(table_data, headers=headers, fmt='table', title='Devices with Indices')
        print()
        print("You can use the index number as a device identifier in device-action commands.")
        print("Example: device-action logout 0 1 2")
        print("         device-action remove \"My iPhone\"")
        print("         device-action lock 0")

    def _display_action_results(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceActionResponse, Any) -> None
        """Display the action results."""
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        if not response.deviceActionResult:
            print("No results returned.")
            return
        
        if fmt == 'json':
            self._display_results_json(response, output)
        else:
            self._display_results_table(response, output)

    def _display_results_table(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceActionResponse, Optional[str]) -> None
        """Display action results in table format."""
        
        headers = ['Action', 'Status', 'Description']
        table_data = []
        
        for result in response.deviceActionResult:
            action_name = DeviceManagement_pb2.DeviceActionType.Name(result.deviceActionType)
            status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
            
            # Get description based on status
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                description = "Success"
                status_display = f"{bcolors.OKGREEN}{status_name}{bcolors.ENDC}"
            elif result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                description = "Operation Not Allowed"
                status_display = f"{bcolors.FAIL}{status_name}{bcolors.ENDC}"
            else:
                description = "Invalid Action Type"
                status_display = f"{bcolors.WARNING}{status_name}{bcolors.ENDC}"
            
            table_data.append([action_name, status_display, description])
        
        title = f'Device Action Results ({len(table_data)} actions)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_results_json(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceActionResponse, Optional[str]) -> None
        """Display action results in JSON format."""
        import json
        
        results = []
        for result in response.deviceActionResult:
            result_info = {
                'actionType': DeviceManagement_pb2.DeviceActionType.Name(result.deviceActionType),
                'status': DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus),
                'success': result.deviceActionStatus == DeviceManagement_pb2.SUCCESS,
                'deviceTokens': [
                    {'encryptedToken': token.hex()} for token in result.encryptedDeviceToken
                ]
            }
            results.append(result_info)
        
        output_data = {
            'deviceActionResults': results,
            'totalActions': len(results)
        }
        
        json_output = json.dumps(output_data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Device action results saved to {output_file}")
        else:
            print(json_output)

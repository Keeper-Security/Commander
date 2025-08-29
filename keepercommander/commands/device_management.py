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
device_admin_action_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                        help='Show what would be done without executing the action')


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


class DeviceUserListCommand(Command):
   
    
    def get_parser(self):
        return device_user_list_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
       
        try:
            
            rs = api.communicate_rest(
                params, 
                None,  
                'dm/device_user_list',
                rs_type=DeviceManagement_pb2.DeviceUserResponse
            )
            
            
            self._display_devices(rs, **kwargs)
            
        except Exception as e:
            logging.error(f"Failed to retrieve device list: {e}")
            raise

    def _display_devices(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceUserResponse, Any) -> None
       
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
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
        
        headers = [
            'ID',
            'Device Name', 
            'Client Type',
            'Login Status',
            'Last Accessed'
        ]
        
        device_data = []
        for device in devices:
            client_type_name = DeviceManagement_pb2.ClientType.Name(device.clientType)
            
            last_accessed = self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else 'N/A'
            
            login_status = self._get_login_status_display(device.loginState)
            
            device_data.append({
                'name': device.deviceName or 'N/A',
                'client_type': client_type_name,
                'login_status': login_status,
                'last_accessed': last_accessed,
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            row = [
                str(i),
                device['name'],
                device['client_type'],
                device['login_status'],
                device['last_accessed']
            ]
            table_data.append(row)
        
        title = f'User Devices ({len(table_data)} found)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_json(self, devices, output_file=None):
        # type: (list, Optional[str]) -> None
        import json
        
        device_list = []
        for device in devices:
            device_info = {
                'deviceName': device.deviceName,
                'clientType': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'loginStatus': self._get_login_status_display(device.loginState),
                'lastAccessedTimestamp': self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else None,
                'timestamp': device.lastModifiedTime or 0
            }
            device_list.append(device_info)
        
        device_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        for i, device in enumerate(device_list, 1):
            device['id'] = i
            del device['timestamp']
        
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


    def _get_login_status_display(self, login_state):
        # type: (int) -> str
        status_map = {
            APIRequest_pb2.LoginState.LOGGED_IN: "LOGGED_IN",
            APIRequest_pb2.LoginState.LOGGED_OUT: "LOGGED_OUT", 
            APIRequest_pb2.LoginState.DEVICE_LOCKED: "DEVICE_LOCKED",
            APIRequest_pb2.LoginState.DEVICE_ACCOUNT_LOCKED: "DEVICE_ACCOUNT_LOCKED",
            APIRequest_pb2.LoginState.ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
            APIRequest_pb2.LoginState.LICENSE_EXPIRED: "LICENSE_EXPIRED",
        }
        
        return status_map.get(login_state, f"UNKNOWN_STATE_{login_state}")

    def _format_timestamp(self, timestamp):
        # type: (int) -> str
        try:
            from datetime import datetime
            if timestamp > 10000000000:  
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError, TypeError):
            return f'Invalid timestamp: {timestamp}'


class DeviceUserActionCommand(Command):
   

    def get_parser(self):
        return device_user_action_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
       
        action = kwargs.get('action')
        devices = kwargs.get('devices', [])
        
        all_devices_response = api.communicate_rest(
            params, 
            None,
            'dm/device_user_list',
            rs_type=DeviceManagement_pb2.DeviceUserResponse
        )
        
       
        
        if not action:
            raise ValueError("Action is required")
        if not devices:
            raise ValueError("At least one device must be specified")

        try:
            
            device_tokens = self._resolve_devices(all_devices_response, devices)
            
            if not device_tokens:
                print("No matching devices found.")
                return
            
            action_type = self._get_action_type(action)
            
           
            
            request = DeviceManagement_pb2.DeviceActionRequest()
            device_action = request.deviceAction.add()
            device_action.deviceActionType = action_type
            device_action.encryptedDeviceToken.extend(device_tokens)
            
            response = api.communicate_rest(
                params, 
                request,
                'dm/device_user_action',
                rs_type=DeviceManagement_pb2.DeviceActionResponse
            )
            
            self._display_action_results(response, **kwargs)
            
        except KeeperApiError as kae:
            if kae.result_code == 'forbidden':
                logging.error(f"{bcolors.FAIL}Error: {kae.message}{bcolors.ENDC}")
                
            else:
                logging.error(f"{bcolors.FAIL}API Error: {kae.message} (Code: {kae.result_code}){bcolors.ENDC}")
            raise
        except Exception as e:
            logging.error(f"Failed to perform device action: {e}")
            raise

    def _resolve_devices(self, devices_response, device_identifiers):
        # type: (DeviceManagement_pb2.DeviceUserResponse, list) -> list
      
        all_devices = []
        for device_group in devices_response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        all_devices.sort(key=lambda x: x.lastModifiedTime or 0, reverse=True)
        
        resolved_tokens = []
        
        for identifier in device_identifiers:
            matched_devices = []
            
            try:
                device_id = int(identifier)
                if 1 <= device_id <= len(all_devices):
                    matched_devices = [all_devices[device_id - 1]]
                else:
                    logging.warning(f"Warning: Device ID {device_id} is out of range (1-{len(all_devices)})")
                    continue
            except ValueError:
                for device in all_devices:
                    try:
                        decoded_token = utils.base64_url_decode(identifier)
                        if device.encryptedDeviceToken == decoded_token:
                            matched_devices = [device]
                            break
                    except:
                        pass
                        
                    if device.deviceName and identifier.lower() in device.deviceName.lower():
                        matched_devices.append(device)
            
            if not matched_devices:
                logging.warning(f"Warning: No device found matching '{identifier}'")
                continue
            elif len(matched_devices) > 1:
                logging.warning(f"Warning: Multiple devices found matching '{identifier}':")
                for i, device in enumerate(matched_devices):
                    device_id = next((idx + 1 for idx, d in enumerate(all_devices) if d.encryptedDeviceToken == device.encryptedDeviceToken), "?")
                    logging.info(f"  - ID {device_id}: {device.deviceName}")
                logging.info("Please be more specific or use the device ID. Skipping this identifier.")
                continue
            else:
                resolved_tokens.append(matched_devices[0].encryptedDeviceToken)
                
        return resolved_tokens

    def _get_action_type(self, action):
        # type: (str) -> int
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

    def _display_action_results(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceActionResponse, Any) -> None
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        if not response.deviceActionResult:
            logging.info("No results returned.")
            return
        
        if fmt == 'json':
            self._display_results_json(response, output)
        else:
            self._display_results_table(response, output)

    def _display_results_table(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceActionResponse, Optional[str]) -> None
        
        headers = ['Action', 'Status', 'Description']
        table_data = []
        
        for result in response.deviceActionResult:
            action_name = DeviceManagement_pb2.DeviceActionType.Name(result.deviceActionType)
            status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
            
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


class DeviceUserRenameCommand(Command):
    
    def get_parser(self):
        return device_user_rename_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
        
        device_identifier = kwargs.get('device')
        new_name = kwargs.get('new_name')
        
        if not device_identifier:
            raise ValueError("Device identifier is required")
        if not new_name:
            raise ValueError("New device name is required")

        try:
            all_devices_response = api.communicate_rest(
                params, 
                None,
                'dm/device_user_list',
                rs_type=DeviceManagement_pb2.DeviceUserResponse
            )
            
            device_tokens = self._resolve_device(all_devices_response, device_identifier)
            
            if not device_tokens:
                logging.info("No matching device found.")
                return
            
            request = DeviceManagement_pb2.DeviceRenameRequest()
            device_rename = request.deviceRename.add()
            device_rename.encryptedDeviceToken = device_tokens[0]
            device_rename.deviceNewName = new_name
            
            response = api.communicate_rest(
                params, 
                request,
                'dm/device_user_rename',
                rs_type=DeviceManagement_pb2.DeviceRenameResponse
            )
            
            self._display_rename_results(response, **kwargs)
            
        except KeeperApiError as kae:
            if kae.result_code == 'forbidden':
                logging.error(f"{bcolors.FAIL}Error: {kae.message}{bcolors.ENDC}")
            elif kae.result_code == 'bad_request':
                logging.error(f"{bcolors.FAIL}Bad Request: {kae.message}{bcolors.ENDC}")
            else:
                logging.error(f"{bcolors.FAIL}API Error: {kae.message} (Code: {kae.result_code}){bcolors.ENDC}")
            raise
        except Exception as e:
            logging.error(f"Failed to rename device: {e}")
            raise

    def _resolve_device(self, devices_response, device_identifier):
        # type: (DeviceManagement_pb2.DeviceUserResponse, str) -> list
        
        all_devices = []
        for device_group in devices_response.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        all_devices.sort(key=lambda x: x.lastModifiedTime or 0, reverse=True)
        
        matched_devices = []
        
        try:
            device_id = int(device_identifier)
            if 1 <= device_id <= len(all_devices):
                matched_devices = [all_devices[device_id - 1]]
            else:
                logging.warning(f"Device ID {device_id} is out of range (1-{len(all_devices)})")
                return []
        except ValueError:
            for device in all_devices:
                try:
                    decoded_token = utils.base64_url_decode(device_identifier)
                    if device.encryptedDeviceToken == decoded_token:
                        matched_devices = [device]
                        break
                except:
                    pass
                    
                if device.deviceName and device_identifier.lower() in device.deviceName.lower():
                    matched_devices.append(device)
        
        if not matched_devices:
            logging.warning(f"No device found matching '{device_identifier}'")
            return []
        elif len(matched_devices) > 1:
            logging.warning(f"Multiple devices found matching '{device_identifier}':")
            for device in matched_devices:
                device_id = next((idx + 1 for idx, d in enumerate(all_devices) if d.encryptedDeviceToken == device.encryptedDeviceToken), "?")
                logging.info(f"  - ID {device_id}: {device.deviceName}")
            logging.info("Please be more specific or use the device ID.")
            return []
        else:
            return [matched_devices[0].encryptedDeviceToken]

    def _display_rename_results(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceRenameResponse, Any) -> None
        
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        if not response.deviceRenameResult:
            logging.info("No results returned.")
            return
        
        if fmt == 'json':
            self._display_results_json(response, output)
        else:
            self._display_results_table(response, output)

    def _display_results_table(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceRenameResponse, Optional[str]) -> None
        
        headers = ['Status', 'New Device Name', 'Description']
        table_data = []
        
        for result in response.deviceRenameResult:
            status_name = DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus)
            
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                description = "Success"
                status_display = f"{bcolors.OKGREEN}{status_name}{bcolors.ENDC}"
            elif result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                description = "Operation Not Allowed"
                status_display = f"{bcolors.FAIL}{status_name}{bcolors.ENDC}"
            else:
                description = "Invalid"
                status_display = f"{bcolors.WARNING}{status_name}{bcolors.ENDC}"
            
            table_data.append([status_display, result.deviceNewName or 'N/A', description])
        
        title = f'Device Rename Results ({len(table_data)} operations)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_results_json(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceRenameResponse, Optional[str]) -> None
        
        import json
        
        results = []
        for result in response.deviceRenameResult:
            result_info = {
                'status': DeviceManagement_pb2.DeviceActionStatus.Name(result.deviceActionStatus),
                'success': result.deviceActionStatus == DeviceManagement_pb2.SUCCESS,
                'newDeviceName': result.deviceNewName,
                'encryptedDeviceToken': result.encryptedDeviceToken.hex() if result.encryptedDeviceToken else None
            }
            results.append(result_info)
        
        output_data = {
            'deviceRenameResults': results,
            'totalOperations': len(results)
        }
        
        json_output = json.dumps(output_data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Device rename results saved to {output_file}")
        else:
            print(json_output)

class DeviceAdminListCommand(Command):
    """
    Command to list all devices across users that the Admin has control of.
    Uses the device_admin_list REST API endpoint.
    """
    
    def get_parser(self):
        return device_admin_list_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
        
        enterprise_user_ids = kwargs.get('enterprise_user_ids', [])
        
        try:
            request = DeviceManagement_pb2.DeviceAdminRequest()
            if enterprise_user_ids:
                request.enterpriseUserIds.extend(enterprise_user_ids)
            
            rs = api.communicate_rest(
                params, 
                request if enterprise_user_ids else None,
                'dm/device_admin_list',
                rs_type=DeviceManagement_pb2.DeviceAdminResponse
            )
            
            self._display_devices(rs, **kwargs)
            
        except Exception as e:
            logging.error(f"Failed to retrieve admin device list: {e}")
            raise

    def _display_devices(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceAdminResponse, Any) -> None
        
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
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
        
        if fmt == 'json':
            self._display_json(all_devices, output)
        else:
            self._display_table(all_devices, output)

    def _display_table(self, devices, output_file=None):
        # type: (list, Optional[str]) -> None
        
        headers = [
            'ID',
            'Enterprise User ID',
            'Device Name', 
            'UI Category',
            'Device Status',
            'Login Status',
            'Last Accessed'
        ]
        
        device_data = []
        for device_info in devices:
            device = device_info['device']
            enterprise_user_id = device_info['enterprise_user_id']
            
            ui_category = self._get_ui_category(device)
            device_status = self._get_device_status_display(device.deviceStatus)
            login_status = self._get_login_status_display(device.loginState)
            last_accessed = self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else 'N/A'
            
            device_data.append({
                'enterprise_user_id': enterprise_user_id,
                'name': device.deviceName or 'N/A',
                'ui_category': ui_category,
                'device_status': device_status,
                'login_status': login_status,
                'last_accessed': last_accessed,
                'timestamp': device.lastModifiedTime or 0
            })
        
        device_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        table_data = []
        for i, device in enumerate(device_data, 1):
            row = [
                str(i),
                str(device['enterprise_user_id']),
                device['name'],
                device['ui_category'],
                device['device_status'],
                device['login_status'],
                device['last_accessed']
            ]
            table_data.append(row)
        
        title = f'Admin Device List ({len(table_data)} devices found)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_json(self, devices, output_file=None):
        # type: (list, Optional[str]) -> None
        import json
        
        device_list = []
        for device_info in devices:
            device = device_info['device']
            enterprise_user_id = device_info['enterprise_user_id']
            
            ui_category = self._get_ui_category(device)
            device_status = self._get_device_status_display(device.deviceStatus)
            login_status = self._get_login_status_display(device.loginState)
            
            device_info_json = {
                'enterpriseUserId': enterprise_user_id,
                'deviceName': device.deviceName,
                'uiCategory': ui_category,
                'deviceStatus': device_status,
                'loginStatus': login_status,
                'clientType': DeviceManagement_pb2.ClientType.Name(device.clientType),
                'clientTypeCategory': DeviceManagement_pb2.ClientTypeCategory.Name(device.clientTypeCategory) if device.clientTypeCategory else None,
                'clientFormFactor': APIRequest_pb2.ClientFormFactor.Name(device.clientFormFactor) if device.clientFormFactor else None,
                'clientVersion': device.clientVersion,
                'devicePlatform': device.devicePlatform,
                'lastModifiedTime': self._format_timestamp(device.lastModifiedTime) if device.lastModifiedTime else None,
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
        
        json_output = json.dumps(result, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Admin device list saved to {output_file}")
        else:
            print(json_output)

    def _get_ui_category(self, device):
        # type: (DeviceManagement_pb2.Device) -> str
        """
        Determine UI category based on client type, client type category, and client form factor
        according to the API documentation logic.
        """
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

        if client_type == DeviceManagement_pb2.COMMANDER and client_type_category == DeviceManagement_pb2.CAT_ADMIN:
            return "Commander CLI"
        
        # If none of the above match, mark as Unknown Device
        return "Unknown Device"

    def _get_device_status_display(self, device_status):
        # type: (int) -> str
        status_map = {
            APIRequest_pb2.DEVICE_NEEDS_APPROVAL: "NEEDS_APPROVAL",
            APIRequest_pb2.DEVICE_OK: "OK",
            APIRequest_pb2.DEVICE_DISABLED_BY_USER: "DISABLED_BY_USER", 
            APIRequest_pb2.DEVICE_LOCKED_BY_ADMIN: "LOCKED_BY_ADMIN",
        }
        
        return status_map.get(device_status, f"UNKNOWN_STATUS_{device_status}")

    def _get_login_status_display(self, login_state):
        # type: (int) -> str
        status_map = {
            APIRequest_pb2.LoginState.LOGGED_IN: "LOGGED_IN",
            APIRequest_pb2.LoginState.LOGGED_OUT: "LOGGED_OUT", 
            APIRequest_pb2.LoginState.DEVICE_LOCKED: "DEVICE_LOCKED",
            APIRequest_pb2.LoginState.DEVICE_ACCOUNT_LOCKED: "DEVICE_ACCOUNT_LOCKED",
            APIRequest_pb2.LoginState.ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
            APIRequest_pb2.LoginState.LICENSE_EXPIRED: "LICENSE_EXPIRED",
        }
        
        return status_map.get(login_state, f"UNKNOWN_STATE_{login_state}")

    def _format_timestamp(self, timestamp):
        # type: (int) -> str
        try:
            from datetime import datetime
            if timestamp > 10000000000:  
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError, TypeError):
            return f'Invalid timestamp: {timestamp}'


class DeviceAdminActionCommand(Command):
    """
    Command to perform actions on devices across enterprise users.
    Uses the device_admin_action REST API endpoint.
    """
    
    def get_parser(self):
        return device_admin_action_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, Any) -> Any
        
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        devices = kwargs.get('devices', [])
        dry_run = kwargs.get('dry_run', False)
        
        if not action:
            raise ValueError("Action is required")
        if not enterprise_user_id:
            raise ValueError("Enterprise User ID is required")
        if not devices:
            raise ValueError("At least one device must be specified")

        try:
            # First, get the list of devices for the specified enterprise user
            list_request = DeviceManagement_pb2.DeviceAdminRequest()
            list_request.enterpriseUserIds.append(enterprise_user_id)
            
            devices_response = api.communicate_rest(
                params, 
                list_request,
                'dm/device_admin_list',
                rs_type=DeviceManagement_pb2.DeviceAdminResponse
            )
            
            # Resolve device identifiers to device tokens
            device_tokens = self._resolve_devices(devices_response, enterprise_user_id, devices)
            
            if not device_tokens:
                print("No matching devices found.")
                return
            
            # Map action string to protobuf enum
            action_type = self._get_action_type(action)
            
            # Show what will be done if dry run
            if dry_run:
                self._show_dry_run(devices_response, enterprise_user_id, device_tokens, action, action_type)
                return
            
            # Create the device admin action request
            request = DeviceManagement_pb2.DeviceAdminActionRequest()
            admin_action = request.deviceAdminAction.add()
            admin_action.deviceActionType = action_type
            admin_action.enterpriseUserId = enterprise_user_id
            admin_action.encryptedDeviceToken.extend(device_tokens)
            
            # Execute the action
            response = api.communicate_rest(
                params, 
                request,
                'dm/device_admin_action',
                rs_type=DeviceManagement_pb2.DeviceAdminActionResponse
            )
            
            # Display the results
            self._display_action_results(response, **kwargs)
            
        except KeeperApiError as kae:
            if kae.result_code == 'forbidden':
                print(f"{bcolors.FAIL}Error: {kae.message}{bcolors.ENDC}")
                print("This error typically occurs when:")
                print("- The device tokens are invalid or not owned by the specified user")
                print("- The admin doesn't have permission to perform actions on this user's devices")
                print("- The target devices are not accessible")
            else:
                print(f"{bcolors.FAIL}API Error: {kae.message} (Code: {kae.result_code}){bcolors.ENDC}")
            raise
        except Exception as e:
            logging.error(f"Failed to perform device admin action: {e}")
            raise

    def _resolve_devices(self, devices_response, enterprise_user_id, device_identifiers):
        # type: (DeviceManagement_pb2.DeviceAdminResponse, int, list) -> list
        """
        Resolve device identifiers (names, tokens, or IDs) to device tokens for the specified user.
        """
        # Find the device user group for the specified enterprise user
        target_user_group = None
        for device_user_group in devices_response.deviceUserList:
            if device_user_group.enterpriseUserId == enterprise_user_id:
                target_user_group = device_user_group
                break
        
        if not target_user_group:
            print(f"No devices found for enterprise user ID {enterprise_user_id}")
            return []
        
        # Collect all devices for this user
        all_devices = []
        for device_group in target_user_group.deviceGroups:
            for device in device_group.devices:
                all_devices.append(device)
        
        if not all_devices:
            print(f"No devices found for enterprise user ID {enterprise_user_id}")
            return []
        
        resolved_tokens = []
        
        for identifier in device_identifiers:
            matched_devices = []
            
            # Try to match by device ID (numeric index)
            try:
                device_id = int(identifier)
                if 1 <= device_id <= len(all_devices):
                    matched_devices = [all_devices[device_id - 1]]  # 1-based indexing for user friendliness
                else:
                    print(f"Warning: Device ID {device_id} is out of range (1-{len(all_devices)})")
                    continue
            except ValueError:
                # Not a number, try other matching methods
                for device in all_devices:
                    # Check if it's a direct token match (base64 encoded)
                    try:
                        from .. import utils
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
                print(f"Warning: No device found matching '{identifier}' for user {enterprise_user_id}")
                continue
            elif len(matched_devices) > 1:
                print(f"Warning: Multiple devices found matching '{identifier}' for user {enterprise_user_id}:")
                for i, device in enumerate(matched_devices):
                    device_id = next((idx + 1 for idx, d in enumerate(all_devices) if d.encryptedDeviceToken == device.encryptedDeviceToken), "?")
                    print(f"  - ID {device_id}: {device.deviceName}")
                print("Please be more specific or use the device ID. Skipping this identifier.")
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
        }
        
        if action not in action_map:
            raise ValueError(f"Unknown action: {action}")
            
        return action_map[action]

    def _show_dry_run(self, devices_response, enterprise_user_id, device_tokens, action, action_type):
        # type: (DeviceManagement_pb2.DeviceAdminResponse, int, list, str, int) -> None
        """Show what would be done in a dry run."""
        print(f"DRY RUN: Would perform action '{action}' on the following devices for enterprise user {enterprise_user_id}:")
        print()
        
        # Find the device user group for the specified enterprise user
        target_user_group = None
        for device_user_group in devices_response.deviceUserList:
            if device_user_group.enterpriseUserId == enterprise_user_id:
                target_user_group = device_user_group
                break
        
        if target_user_group:
            all_devices = []
            for device_group in target_user_group.deviceGroups:
                for device in device_group.devices:
                    all_devices.append(device)
            
            for token in device_tokens:
                for device in all_devices:
                    if device.encryptedDeviceToken == token:
                        client_type_name = DeviceManagement_pb2.ClientType.Name(device.clientType)
                        ui_category = self._get_ui_category_for_device(device)
                        print(f"  - {device.deviceName} ({client_type_name} - {ui_category})")
                        break
        
        print()
        print(f"Action: {DeviceManagement_pb2.DeviceActionType.Name(action_type)}")
        print(f"Description: {self._get_action_description(action)}")
        print(f"Enterprise User ID: {enterprise_user_id}")

    def _get_action_description(self, action):
        # type: (str) -> str
        """Get human-readable description of the action."""
        descriptions = {
            'logout': 'Logout the enterprise user from the device',
            'remove': 'Logout & Remove the enterprise user from that device',
            'lock': 'Lock the device for all users and auto linked devices. Logout all users',
            'unlock': 'Unlock the devices and auto linked devices for the enterprise user',
            'account-lock': 'Lock the device for the enterprise user only. If user is logged in, logout',
            'account-unlock': 'Unlock the device for the enterprise user',
        }
        return descriptions.get(action, 'Unknown action')

    def _get_ui_category_for_device(self, device):
        # type: (DeviceManagement_pb2.Device) -> str
        """Get UI category for a single device (reusing logic from DeviceAdminListCommand)."""
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
        
        # If none of the above match, mark as Unknown Device
        return "Unknown Device"

    def _display_action_results(self, response, **kwargs):
        # type: (DeviceManagement_pb2.DeviceAdminActionResponse, Any) -> None
        """Display the action results."""
        fmt = kwargs.get('format', 'table')
        output = kwargs.get('output')
        
        if not response.deviceAdminActionResults:
            print("No results returned.")
            return
        
        if fmt == 'json':
            self._display_results_json(response, output)
        else:
            self._display_results_table(response, output)

    def _display_results_table(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceAdminActionResponse, Optional[str]) -> None
        """Display action results in table format."""
        
        headers = ['Enterprise User ID', 'Action', 'Status', 'Description', 'Device Count']
        table_data = []
        
        for result in response.deviceAdminActionResults:
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
            
            device_count = len(result.encryptedDeviceToken)
            
            table_data.append([
                str(result.enterpriseUserId), 
                action_name, 
                status_display, 
                description,
                str(device_count)
            ])
        
        title = f'Device Admin Action Results ({len(table_data)} actions)'
        dump_report_data(table_data, headers=headers, fmt='table', filename=output_file, title=title)

    def _display_results_json(self, response, output_file=None):
        # type: (DeviceManagement_pb2.DeviceAdminActionResponse, Optional[str]) -> None
        """Display action results in JSON format."""
        import json
        
        results = []
        for result in response.deviceAdminActionResults:
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
            results.append(result_info)
        
        output_data = {
            'deviceAdminActionResults': results,
            'totalActions': len(results)
        }
        
        json_output = json.dumps(output_data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Device admin action results saved to {output_file}")
        else:
            print(json_output)
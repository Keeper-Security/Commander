#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import logging
import os
import subprocess
from typing import Tuple

from keepercommander import utils


# Windows Registry Helper Functions
def get_windows_registry_key():
    """Get the Windows registry key for storing biometric flags"""
    try:
        import winreg
        key_path = r"SOFTWARE\Keeper Security\Commander\Biometric"
        try:
            return winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
        except FileNotFoundError:
            return winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
    except ImportError:
        return None


def set_windows_registry_biometric_flag(username: str, enabled: bool) -> bool:
    """Set biometric flag in Windows registry"""
    try:
        import winreg
        key = get_windows_registry_key()
        if key:
            winreg.SetValueEx(key, username, 0, winreg.REG_DWORD, 1 if enabled else 0)
            winreg.CloseKey(key)
            return True
    except Exception as e:
        logging.debug(f'Failed to set Windows registry biometric flag: {e}')
    return False


def get_windows_registry_biometric_flag(username: str) -> bool:
    """Get biometric flag from Windows registry"""
    try:
        import winreg
        key = get_windows_registry_key()
        if key:
            try:
                value, _ = winreg.QueryValueEx(key, username)
                winreg.CloseKey(key)
                return bool(value)
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
    except Exception as e:
        logging.debug(f'Failed to get Windows registry biometric flag: {e}')
    return False


def detect_windows_hello() -> Tuple[bool, str]:
    """Detect Windows Hello availability and configuration"""
    if os.name != 'nt':
        return False, "Not running on Windows"
    
    try:
        result = subprocess.run([
            'powershell', '-Command',
            '''
            $windowsHello = @{}
            try {
                $face = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Hello-Face"
                $windowsHello.Face = $face.State -eq "Enabled"
            } catch {
                $windowsHello.Face = $false
            }
            
            try {
                # Check for biometric devices in Device Manager
                $biometricDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
                    $_.Name -like "*fingerprint*" -or 
                    $_.Name -like "*biometric*" -or 
                    $_.DeviceID -like "*VID_*" -and $_.DeviceID -like "*PID_*" -and (
                        $_.Name -like "*touch*" -or 
                        $_.Name -like "*sensor*"
                    )
                }
                $windowsHello.Fingerprint = $biometricDevices.Count -gt 0
            } catch {
                $windowsHello.Fingerprint = $false
            }
            
            # Check Windows Hello settings
            try {
                # Check if Windows Hello is configured by looking at sign-in options
                $registryPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio\\Credential Provider"
                $windowsHello.Configured = Test-Path $registryPath
                
                # Also check user-specific Windows Hello settings
                $userHelloPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio\\Credential Provider"
                if (-not $windowsHello.Configured) {
                    $windowsHello.Configured = Test-Path $userHelloPath
                }
            } catch {
                $windowsHello.Configured = $false
            }
            
            # Check WebAuthn support which is required for FIDO2
            try {
                $webAuthnDll = Test-Path "$env:WINDIR\\System32\\webauthn.dll"
                $windowsHello.WebAuthn = $webAuthnDll
            } catch {
                $windowsHello.WebAuthn = $false
            }
            
            $result = @{
                Available = $windowsHello.Face -or $windowsHello.Fingerprint -or $windowsHello.WebAuthn
                Face = $windowsHello.Face
                Fingerprint = $windowsHello.Fingerprint
                Configured = $windowsHello.Configured
                WebAuthn = $windowsHello.WebAuthn
            }
            
            $result | ConvertTo-Json -Compress
            '''
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            # Fallback: Try simple WebAuthn check
            webauthn_result = subprocess.run([
                'powershell', '-Command',
                'Test-Path "$env:WINDIR\\System32\\webauthn.dll"'
            ], capture_output=True, text=True, timeout=5)
            
            if webauthn_result.returncode == 0 and 'True' in webauthn_result.stdout:
                return True, "Windows Hello WebAuthn support detected"
            else:
                return False, "Windows Hello WebAuthn not available"
        
        try:
            hello_info = json.loads(result.stdout.strip())
            
            if hello_info.get('Available', False):
                details = []
                if hello_info.get('Face', False):
                    details.append("Face recognition")
                if hello_info.get('Fingerprint', False):
                    details.append("Fingerprint")
                if hello_info.get('WebAuthn', False):
                    details.append("WebAuthn support")
                
                config_status = "configured" if hello_info.get('Configured', False) else "available but not configured"
                message = f"Windows Hello {config_status}: {', '.join(details) if details else 'Generic support'}"
                return True, message
            else:
                return False, "Windows Hello hardware not detected"
                
        except (json.JSONDecodeError, KeyError):
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio\\Credential Provider")
                winreg.CloseKey(key)
                return True, "Windows Hello configuration detected via registry"
            except FileNotFoundError:
                return False, "Windows Hello not configured"
        
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
        try:
            webauthn_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'webauthn.dll')
            if os.path.exists(webauthn_path):
                return True, "Windows Hello WebAuthn support detected (fallback detection)"
            else:
                return False, f"Windows Hello not available: {str(e)}"
        except Exception:
            return False, f"Error checking Windows Hello: {str(e)}"


def create_windows_webauthn_client(data_collector, timeout=30):
    """Create Windows-specific WebAuthn client"""
    try:
        from fido2.client.windows import WindowsClient
        return WindowsClient(client_data_collector=data_collector)
    except ImportError:
        raise Exception('Windows Hello client is not available. Please install fido2[pcsc]')
    except Exception as e:
        logging.warning(f'Windows client creation failed: {e}, trying generic client')
        try:
            from fido2.hid import CtapHidDevice
            from fido2.client import Fido2Client
            
            devices = list(CtapHidDevice.list_devices())
            if devices:
                import importlib
                biometric_module = importlib.import_module('keepercommander.biometric.biometric')
                BiometricInteraction = biometric_module.BiometricInteraction
                interaction = BiometricInteraction(timeout)
                return Fido2Client(
                    devices[0], 
                    client_data_collector=data_collector,
                    user_interaction=interaction
                )
            else:
                raise Exception('No FIDO2 devices found for Windows fallback')
        except ImportError:
            raise Exception('FIDO2 fallback libraries are not available')


def handle_windows_credential_creation(creation_options, timeout=30):
    """Handle Windows-specific credential creation modifications"""
    
    user_id = utils.base64_url_decode(creation_options['user']['id'])
    creation_options['user']['id'] = user_id
    creation_options.pop('hints', None)
    creation_options.pop('extensions', None)
    
    if 'excludeCredentials' in creation_options and not creation_options['excludeCredentials']:
        creation_options.pop('excludeCredentials')
    
    if 'authenticatorSelection' not in creation_options:
        creation_options['authenticatorSelection'] = {}

    creation_options['authenticatorSelection'].update({
        'authenticatorAttachment': 'platform',
        'userVerification': 'required',
        'residentKey': 'required'
    })

    creation_options['attestation'] = 'none'
    
    if 'timeout' not in creation_options:
        creation_options['timeout'] = timeout * 1000
    
    return creation_options


def handle_windows_authentication_options(pk_options, timeout=10):
    """Handle Windows-specific authentication options modifications"""
    pk_options.pop('hints', None)
    pk_options.pop('extensions', None)
    
    if 'allowCredentials' in pk_options:
        for cred in pk_options['allowCredentials']:
            if 'transports' in cred and not cred['transports']:
                cred.pop('transports')
    
    pk_options['userVerification'] = 'required'
    
    if 'timeout' not in pk_options:
        pk_options['timeout'] = timeout * 1000
    
    return pk_options


def perform_windows_authentication(client, options):
    """Perform Windows-specific biometric authentication"""
    try:
        assertion_result = client.get_assertion(options)
        return assertion_result
    except Exception as e:
        error_msg = str(e).lower()
        if "cancelled" in error_msg or "denied" in error_msg:
            raise Exception("Windows Hello authentication was cancelled or denied")
        elif "timeout" in error_msg:
            raise Exception("Windows Hello authentication timed out")
        elif "not available" in error_msg:
            raise Exception("Windows Hello is not available or not set up")
        elif "parameter is incorrect" in error_msg:
            raise Exception("Windows Hello parameter error - please check your biometric setup")
        else:
            raise Exception(f"Windows Hello authentication failed: {str(e)}")


def perform_windows_credential_creation(client, options):
    """Perform Windows-specific credential creation"""
    try:
        credential_response = client.make_credential(options)
        return credential_response
    except Exception as e:
        if "cancelled" in str(e).lower() or "denied" in str(e).lower():
            raise Exception("Windows Hello authentication was cancelled or denied")
        elif "timeout" in str(e).lower():
            raise Exception("Windows Hello authentication timed out")
        elif "not available" in str(e).lower():
            raise Exception("Windows Hello is not available or not set up")
        else:
            raise Exception(f"Windows Hello authentication failed: {str(e)}") 
#!/usr/bin/env python3
"""
Docker KSM Utility - Centralized utility for KSM operations in Docker containers.

This module provides secure file operations for KSM (Keeper Secrets Manager)
records, including config processing, file upload/download, and monitoring.
"""

import sys
import os
import argparse
import time
import hashlib
from pathlib import Path
import base64
import binascii
import glob
import json
import shutil
import tempfile

# =============================================================================
# SECURITY AND VALIDATION FUNCTIONS
# =============================================================================

def validate_file_path(file_path, base_dir=None):
    """
    Validate file path to prevent directory traversal attacks.
    
    Args:
        file_path (str): Path to validate
        base_dir (str, optional): Base directory to restrict access to
        
    Returns:
        tuple: (is_valid, resolved_path)
    """
    try:
        # Convert to Path object and resolve
        path = Path(file_path).resolve()
        
        # Check for directory traversal attempts
        if '..' in str(path) or str(path).startswith('/..'):
            return False, None
            
        # If base_dir is specified, ensure path is within it
        if base_dir:
            base_path = Path(base_dir).resolve()
            try:
                path.relative_to(base_path)
            except ValueError:
                return False, None
        
        # Additional security checks
        str_path = str(path)
        dangerous_patterns = [
            '../', '..\\', '~/', '/etc/', '/proc/', '/sys/'
        ]
        if any(pattern in str_path for pattern in dangerous_patterns):
            return False, None
            
        return True, str(path)
        
    except (OSError, ValueError):
        return False, None

def check_ksm_dependency():
    """Check if keeper_secrets_manager_core is installed.
    
    Returns:
        bool: True if installed, False otherwise
    """
    try:
        import keeper_secrets_manager_core  # noqa: F401
        return True
    except ImportError:
        print("ERROR: keeper_secrets_manager_core is not installed")
        return False


# =============================================================================
# KSM CONFIG PROCESSING FUNCTIONS
# =============================================================================

def is_base64_config(input_str):
    """
    Detect if input is base64-encoded JSON or file path.

    Args:
        input_str (str): Input string to check

    Returns:
        bool: True if base64-encoded JSON, False otherwise
    """
    if not input_str:
        return False
    
    # If it looks like a file path (starts with path indicators or exists as file)
    if (input_str.startswith('/') or input_str.startswith('./') or 
        input_str.startswith('../') or input_str.startswith('~') or 
        os.path.isfile(input_str)):
        return False

    try:
        decoded_bytes = base64.b64decode(input_str, validate=True)
        decoded_str = decoded_bytes.decode('utf-8')
        json.loads(decoded_str)  # Validate JSON
        return True
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return False

def cleanup_old_ksm_dirs():
    """
    Clean up old KSM config directories.
    Removes old timestamped directories to prevent accumulation.
    """
    patterns = ["/home/commander/ksm_*", os.path.expanduser("~/ksm_*")]
    
    for pattern in patterns:
        try:
            ksm_dirs = glob.glob(pattern)
            
            if not ksm_dirs:
                continue
            
            # Remove old timestamped directories
            for old_dir in ksm_dirs:
                try:
                    shutil.rmtree(old_dir)
                except Exception as e:
                    print(f"Warning: Could not remove directory {old_dir}: {e}")
        except Exception:
            pass  # Ignore pattern errors

def _create_temp_ksm_dir():
    """
    Create temporary directory for KSM config with proper fallback.
    
    Returns:
        str: Path to created directory, or None if failed
    """
    try:
        # Try Docker path first
        if os.path.exists("/home/commander"):
            return tempfile.mkdtemp(prefix="ksm_", dir="/home/commander")
        else:
            # Fallback for local testing
            return tempfile.mkdtemp(prefix="ksm_")
    except Exception as e:
        print(f"ERROR: Failed to create temp directory: {e}")
        return None


def _decode_and_save_config(base64_input, config_path):
    """
    Decode base64 config and save to file.
    
    Args:
        base64_input (str): Base64-encoded JSON config
        config_path (str): Path where to save the config
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Decode base64 and validate JSON
        decoded_bytes = base64.b64decode(base64_input)
        decoded_str = decoded_bytes.decode('utf-8')
        config_data = json.loads(decoded_str)
        
        # Basic validation of config structure
        if not isinstance(config_data, dict):
            print("ERROR: Invalid config format - must be JSON object")
            return False
        
        # Write to file with proper formatting
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        
        # Set secure permissions
        os.chmod(config_path, 0o600)
        return True
        
    except Exception as e:
        print("ERROR: Failed to decode and save config")
        return False


def process_ksm_config(ksm_config_input):
    """
    Process KSM config input - detect if base64 or file path and handle accordingly.
    
    Args:
        ksm_config_input (str): Either file path or base64-encoded JSON
        
    Returns:
        str: Final file path to use for KSM config, or None if failed
    """
    if not ksm_config_input:
        return None
    
    # Check if it's base64 or file path
    if is_base64_config(ksm_config_input):
        # Clean up any old KSM directories
        cleanup_old_ksm_dirs()
        
        # Create temporary directory
        ksm_dir = _create_temp_ksm_dir()
        if not ksm_dir:
            return None
            
        config_path = os.path.join(ksm_dir, "ksm-config.json")
        
        # Decode and save config
        if _decode_and_save_config(ksm_config_input, config_path):
            return config_path
        else:
            # Clean up on failure
            try:
                shutil.rmtree(ksm_dir)
            except Exception:
                pass
            return None
    else:
        # It's a file path, validate it exists
        
        if os.path.isfile(ksm_config_input):
            return ksm_config_input
        else:
            print("ERROR: KSM config file not found")
            return None


# =============================================================================
# KSM SECRETS MANAGER OPERATIONS
# =============================================================================

def _initialize_secrets_manager(ksm_config_path, ksm_token):
    """
    Initialize SecretsManager with proper error handling.
    
    Args:
        ksm_config_path (str): Path to KSM config file (optional)
        ksm_token (str): KSM access token (optional)
        
    Returns:
        SecretsManager: Initialized SecretsManager or None if failed
    """
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.storage import FileKeyValueStorage
    
    try:
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                print("ERROR: KSM config file not found")
                return None
            return SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        else:
            return SecretsManager(token=ksm_token)
    except Exception as e:
        print(f"ERROR: Failed to initialize SecretsManager: {e}")
        return None


def _get_secret_by_uid_or_title(secrets_manager, record_identifier):
    """
    Get secret by UID first, then by title as fallback.
    
    Args:
        secrets_manager: Initialized SecretsManager instance
        record_identifier (str): Record UID or title
        
    Returns:
        secret_object: Secret object or None if not found
    """
    try:
        # First try to get by UID
        secrets = secrets_manager.get_secrets([record_identifier])
        if secrets and len(secrets) > 0:
            return secrets[0]
    except Exception:
        # UID lookup failed, continue to title lookup
        pass
    
    try:
        # Try to get by title as fallback
        secrets = secrets_manager.get_secrets_by_title(record_identifier)
        
        if not secrets or len(secrets) == 0:
            print(f"ERROR: Record not found by UID or title: {record_identifier}")
            return None
        elif len(secrets) > 1:
            print(f"ERROR: Multiple records found with title '{record_identifier}' "
                  f"({len(secrets)} records). Please use UID or a unique title.")
            return None
        else:
            return secrets[0]
            
    except Exception as e:
        print(f"ERROR: Failed to lookup record by title: {e}")
        pass
    
    print(f"ERROR: Record not found by UID or title: {record_identifier}")
    return None


def download_config(ksm_config_path, ksm_token, record_identifier, output_path):
    """
    Download config.json from KSM record.
    
    Args:
        ksm_config_path (str): Path to KSM config file (optional)
        ksm_token (str): KSM access token (optional)
        record_identifier (str): UID or title of the KSM record
        output_path (str): Path where to save the downloaded config
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not check_ksm_dependency():
        return False
    
    # Validate file paths
    if ksm_config_path:
        is_valid, validated_config_path = validate_file_path(ksm_config_path)
        if not is_valid:
            print("ERROR: Invalid KSM config file path")
            return False
        ksm_config_path = validated_config_path
    
    is_valid, validated_output_path = validate_file_path(output_path)
    if not is_valid:
        print("ERROR: Invalid output file path")
        return False
    output_path = validated_output_path
    
    # Initialize SecretsManager
    secrets_manager = _initialize_secrets_manager(ksm_config_path, ksm_token)
    if not secrets_manager:
        return False
    
    try:
        # Get the record by UID or title
        secret = _get_secret_by_uid_or_title(secrets_manager, record_identifier)
        if not secret:
            return False
        
        # Find config.json attachment
        for file in secret.files:
            if file.name.lower() == 'config.json':
                # Ensure output directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                file.save_file(output_path, True)
                return True
        
        print("ERROR: config.json attachment not found in record")
        return False
        
    except Exception as e:
        print(f"ERROR: Failed to download config from KSM: {e}")
        return False


# =============================================================================
# FILE MANAGEMENT HELPER FUNCTIONS
# =============================================================================

def _get_file_uid(file_obj):
    """
    Extract file UID from file object.
    
    Args:
        file_obj: File object from KSM
        
    Returns:
        str: File UID or None if not found
    """
    try:
        # Try different ways to get the file UID
        if hasattr(file_obj, 'f') and file_obj.f:
            file_uid = file_obj.f.get('fileUid')
            if file_uid:
                return file_uid
        
        if hasattr(file_obj, 'fileUid'):
            return file_obj.fileUid
        
        if hasattr(file_obj, 'uid'):
            return file_obj.uid
            
        return None
        
    except Exception:
        return None

def _remove_existing_config_files(secrets_manager, secret, record_identifier):
    """
    Remove existing config.json files from KSM record.
    
    Args:
        secrets_manager: KSM SecretsManager instance
        secret: KSM secret object
        record_identifier: Record UID or title for refresh after removal
        
    Returns:
        tuple: (success, updated_secret)
    """
    try:
        # Find existing config.json files
        config_files = [
            f for f in secret.files if f.name.lower() == 'config.json'
        ]
        if not config_files:
            return True, secret
            
        files_to_remove = []
        for file_obj in config_files:
            file_uid = _get_file_uid(file_obj)
            if file_uid:
                files_to_remove.append(file_uid)
                print("Found config.json to remove UID: [REDACTED]")
            else:
                print(f"WARNING: Could not find UID for file: {file_obj.name}")
        
        if files_to_remove:
            secrets_manager.save(secret, links_to_remove=files_to_remove)
            print(f"Removed {len(files_to_remove)} config.json file(s)")
            # Refresh the secret after removal
            updated_secret = _get_secret_by_uid_or_title(
                secrets_manager, record_identifier
            )
            if updated_secret:
                return True, updated_secret
            else:
                print("WARNING: Could not refresh secret after file removal")
                return False, secret
        
        return True, secret
        
    except Exception as e:
        print(f"WARNING: Failed to remove existing files: {e}")
        return False, secret

def _upload_new_config_file(secrets_manager, secret, config_file_path):
    """
    Upload new config.json file to KSM record.
    
    Args:
        secrets_manager: KSM SecretsManager instance
        secret: KSM secret object
        config_file_path: Path to local config file
        
    Returns:
        bool: True if successful, False otherwise
    """
    from keeper_secrets_manager_core.core import KeeperFileUpload
    
    try:
        # Validate config file exists and is readable
        if not os.path.exists(config_file_path):
            print("ERROR: Config file not found")
            return False
        
        print("Uploading new config.json...")
        my_file = KeeperFileUpload.from_file(
            config_file_path, 'config.json', 'config.json'
        )
        secrets_manager.upload_file(secret, file=my_file)
        print("Successfully uploaded new config.json")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to upload config file: {e}")
        return False

def upload_config(ksm_config_path, ksm_token, record_identifier, config_file_path):
    """
    Upload config.json to KSM record, removing existing ones first.
    
    Args:
        ksm_config_path (str): Path to KSM config file (optional)
        ksm_token (str): KSM access token (optional)
        record_identifier (str): UID or title of the KSM record
        config_file_path (str): Path to local config file to upload
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not check_ksm_dependency():
        return False
    
    # Validate file paths
    if ksm_config_path:
        is_valid, validated_config_path = validate_file_path(ksm_config_path)
        if not is_valid:
            print("ERROR: Invalid KSM config file path")
            return False
        ksm_config_path = validated_config_path
    
    is_valid, validated_config_file_path = validate_file_path(config_file_path)
    if not is_valid:
        print("ERROR: Invalid config file path")
        return False
    config_file_path = validated_config_file_path
    
    # Initialize SecretsManager
    secrets_manager = _initialize_secrets_manager(ksm_config_path, ksm_token)
    if not secrets_manager:
        return False
    
    try:
        # Get the record by UID or title
        secret = _get_secret_by_uid_or_title(secrets_manager, record_identifier)
        if not secret:
            return False
        
        # Remove existing config.json files
        success, updated_secret = _remove_existing_config_files(
            secrets_manager, secret, record_identifier
        )
        if not success:
            return False
        
        # Upload new config.json file
        return _upload_new_config_file(
            secrets_manager, updated_secret, config_file_path
        )
        
    except Exception as e:
        print(f"ERROR: Failed to upload config: {e}")
        return False


# =============================================================================
# FILE MONITORING AND UTILITIES
# =============================================================================

def _get_secure_file_hash(file_path):
    """
    Securely calculate file hash with proper error handling.
    
    Args:
        file_path (str): Path to file
        
    Returns:
        str: File hash or None if file doesn't exist/error
    """
    try:
        is_valid, validated_path = validate_file_path(file_path)
        if not is_valid:
            return None
        
        if not os.path.exists(validated_path):
            return None
            
        # Use context manager for atomic file read
        with open(validated_path, 'rb') as f:
            content = f.read()
            # Use SHA-256 instead of MD5 for security
            return hashlib.sha256(content).hexdigest()
            
    except (OSError, IOError):
        return None

def monitor_config(ksm_config_path, ksm_token, record_identifier, config_file_path):
    """
    Monitor config.json file for changes and upload when modified.
    
    Args:
        ksm_config_path (str): Path to KSM config file (optional)
        ksm_token (str): KSM access token (optional)
        record_identifier (str): UID or title of the KSM record
        config_file_path (str): Path to config file to monitor
    """
    # Validate file paths at startup
    is_valid, validated_config_file_path = validate_file_path(config_file_path)
    if not is_valid:
        print("ERROR: Invalid config file path for monitoring")
        return
    config_file_path = validated_config_file_path
    
    if ksm_config_path:
        is_valid, validated_ksm_config_path = validate_file_path(ksm_config_path)
        if not is_valid:
            print("ERROR: Invalid KSM config file path for monitoring")
            return
        ksm_config_path = validated_ksm_config_path
    
    print(f"Monitoring config file for changes")
    
    last_hash = _get_secure_file_hash(config_file_path)
    monitor_interval = 30  # Check every 30 seconds
    
    while True:
        try:
            time.sleep(monitor_interval)
            
            current_hash = _get_secure_file_hash(config_file_path)
            
            if current_hash is None:
                if last_hash is not None:
                    print("Config file was removed, continuing to monitor...")
                    last_hash = None
                continue
            
            if current_hash != last_hash:
                print("Config file changed, uploading to KSM record...")
                upload_success = upload_config(
                    ksm_config_path, ksm_token, record_identifier, config_file_path
                )
                if upload_success:
                    print("Config upload completed successfully")
                    # Only update hash on successful upload
                    last_hash = current_hash
                else:
                    print("Config upload failed, will retry on next change")
                
        except KeyboardInterrupt:
            print("Monitoring stopped by user")
            break
        except Exception as e:
            print(f"ERROR: Error in config monitor: {e}")
            time.sleep(5)


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def _validate_command_args(args):
    """
    Validate command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Handle process-config command separately
    if args.command == 'process-config':
        if not args.ksm_config:
            print("ERROR: --ksm-config is required for process-config command")
            return False
        return True
    
    # For other commands, validate required parameters
    if not args.record_uid:
        print("ERROR: --record-uid is required for this command")
        return False
    
    if not args.config_file:
        print("ERROR: --config-file is required for this command")
        return False
    
    # Validate authentication parameters
    if not args.ksm_config and not args.ksm_token:
        print("Either --ksm-config or --ksm-token must be provided")
        return False
    
    if args.ksm_config and args.ksm_token:
        print("Cannot specify both --ksm-config and --ksm-token")
        return False
    
    # Validate file paths early
    if args.ksm_config:
        is_valid, _ = validate_file_path(args.ksm_config)
        if not is_valid:
            print("Invalid KSM config file path")
            return False
    
    is_valid, _ = validate_file_path(args.config_file)
    if not is_valid:
        print("Invalid config file path")
        return False
    
    return True


def _execute_command(args):
    """
    Execute the specified command.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        bool: True if successful, False otherwise
    """
    if args.command == 'process-config':
        result_path = process_ksm_config(args.ksm_config)
        if result_path:
            print(result_path)  # Output the final config path
            return True
        return False
    
    elif args.command == 'download':
        return download_config(
            args.ksm_config, args.ksm_token, args.record_uid, args.config_file
        )
    
    elif args.command == 'upload':
        return upload_config(
            args.ksm_config, args.ksm_token, args.record_uid, args.config_file
        )
    
    elif args.command == 'monitor':
        # Monitor runs indefinitely
        monitor_config(
            args.ksm_config, args.ksm_token, args.record_uid, args.config_file
        )
        return True
    
    return False


def main():
    """
    Main entry point for the KSM Docker Utility.
    """
    parser = argparse.ArgumentParser(
        description="KSM Docker Utility - Secure file operations for KSM records",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "command",
        choices=['download', 'upload', 'monitor', 'process-config'],
        help="Command to execute"
    )
    parser.add_argument(
        "--ksm-config",
        help="KSM config file path or base64-encoded JSON"
    )
    parser.add_argument(
        "--ksm-token",
        help="KSM access token"
    )
    parser.add_argument(
        "--record-uid",
        help="KSM record UID or title"
    )
    parser.add_argument(
        "--config-file",
        help="Local config.json file path"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not _validate_command_args(args):
        sys.exit(1)
    
    # Execute command
    success = False
    try:
        success = _execute_command(args)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        success = True
    except Exception as e:
        print(f"ERROR: Unexpected error occurred: {e}")
        success = False
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

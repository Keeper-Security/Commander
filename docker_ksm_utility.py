#!/usr/bin/env python3
"""
Docker KSM Utility - Centralized utility for KSM operations in Docker containers.
"""

import sys
import os
import argparse
import time
import hashlib
from pathlib import Path

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
        dangerous_patterns = ['../', '..\\', '~/', '/etc/', '/proc/', '/sys/']
        if any(pattern in str_path for pattern in dangerous_patterns):
            return False, None
            
        return True, str(path)
        
    except (OSError, ValueError):
        return False, None


def check_ksm_dependency():
    """Check if keeper_secrets_manager_core is installed."""
    try:
        import keeper_secrets_manager_core
        return True
    except ImportError:
        print("ERROR: keeper_secrets_manager_core is not installed")
        return False

def download_config(ksm_config_path, ksm_token, record_uid, output_path):
    """Download config.json from KSM record."""
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
    
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.storage import FileKeyValueStorage
    
    try:
        # Initialize SecretsManager
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                print("ERROR: KSM config file not found")
                return False
            secrets_manager = SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        else:
            secrets_manager = SecretsManager(token=ksm_token)
        
        # Get the record
        secrets = secrets_manager.get_secrets([record_uid])
        if not secrets:
            print("ERROR: Record not found")
            return False
            
        secret = secrets[0]
        
        # Find config.json attachment
        for file in secret.files:
            if file.name.lower() == 'config.json':
                print(f"Found config.json attachment: {file.name}")
                # Ensure output directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                file.save_file(output_path, True)
                print("Downloaded config.json successfully")
                return True
        
        print("ERROR: config.json attachment not found in record")
        return False
        
    except Exception as e:
        print(f"ERROR: Failed to download config from KSM")
        return False

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

def _remove_existing_config_files(secrets_manager, secret, record_uid):
    """
    Remove existing config.json files from KSM record.
    
    Args:
        secrets_manager: KSM SecretsManager instance
        secret: KSM secret object
        record_uid: Record UID for error context
        
    Returns:
        tuple: (success, updated_secret)
    """
    try:
        # Find existing config.json files
        config_files = [f for f in secret.files if f.name.lower() == 'config.json']
        if len(config_files) == 0:
            return True, secret
            
        files_to_remove = []
        for file_obj in config_files:
            file_uid = _get_file_uid(file_obj)
            if file_uid:
                files_to_remove.append(file_uid)
                print(f"Found config.json to remove UID: [REDACTED]")
            else:
                print(f"WARNING: Could not find UID for file: {file_obj.name}")
        
        if files_to_remove:
            secrets_manager.save(secret, links_to_remove=files_to_remove)
            print(f"Removed {len(files_to_remove)} config.json file(s)")
            # Refresh the secret after removal
            updated_secret = secrets_manager.get_secrets([record_uid])[0]
            return True, updated_secret
        
        return True, secret
        
    except Exception:
        print(f"WARNING: Failed to remove existing files")
        return False, secret

def _upload_new_config_file(secrets_manager, secret, config_file_path):
    """
    Upload new config.json file to KSM record.
    
    Args:
        secrets_manager: KSM SecretsManager instance
        secret: KSM secret object
        config_file_path: Path to local config file
        
    Returns:
        bool: success
    """
    from keeper_secrets_manager_core.core import KeeperFileUpload
    
    try:
        # Validate config file exists and is readable
        if not os.path.exists(config_file_path):
            print("ERROR: Config file not found")
            return False, None
        
        print("Uploading new config.json...")
        my_file = KeeperFileUpload.from_file(config_file_path, 'config.json', 'config.json')
        file_uid = secrets_manager.upload_file(secret, file=my_file)
        print("Successfully uploaded new config.json")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to upload config file")
        return False

def upload_config(ksm_config_path, ksm_token, record_uid, config_file_path):
    """Upload config.json to KSM record, removing existing ones first."""
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
    
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.storage import FileKeyValueStorage
    
    try:
        # Initialize SecretsManager
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                print("ERROR: KSM config file not found")
                return False
            secrets_manager = SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        else:
            secrets_manager = SecretsManager(token=ksm_token)
        
        # Get the record
        secrets = secrets_manager.get_secrets([record_uid])
        if not secrets:
            print("ERROR: Record not found")
            return False
            
        secret = secrets[0]
        
        # Remove existing config.json files
        success, updated_secret = _remove_existing_config_files(secrets_manager, secret, record_uid)
        if not success:
            return False
        
        # Upload new config.json file
        success = _upload_new_config_file(secrets_manager, updated_secret, config_file_path)
        return success
        
    except Exception:
        print(f"ERROR: Failed to upload config")
        return False

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
            return hashlib.sha256(content).hexdigest()  # Use SHA-256 instead of MD5 for security
            
    except (OSError, IOError):
        return None

def monitor_config(ksm_config_path, ksm_token, record_uid, config_file_path):
    """Monitor config.json file for changes and upload when modified."""
    
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
    
    print("Monitoring config file for changes...")
    
    last_hash = _get_secure_file_hash(config_file_path)
    
    while True:
        try:
            time.sleep(30)  # Check every 30 seconds
            
            current_hash = _get_secure_file_hash(config_file_path)
            
            if current_hash is None:
                if last_hash is not None:
                    print("Config file was removed, continuing to monitor...")
                    last_hash = None
                continue
            
            if current_hash != last_hash:
                print("Config file changed, uploading to KSM record...")
                if upload_config(ksm_config_path, ksm_token, record_uid, config_file_path):
                    print("Config upload completed successfully")
                    last_hash = current_hash  # Only update hash on successful upload
                else:
                    print("Config upload failed, will retry on next change")
                
        except KeyboardInterrupt:
            print("Monitoring stopped by user")
            break
        except Exception:
            print(f"ERROR: Error in config monitor")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="KSM Docker Utility - Secure file operations for KSM records")
    parser.add_argument("command", choices=['download', 'upload', 'monitor'], help="Command to execute")
    parser.add_argument("--ksm-config", help="KSM config file path")
    parser.add_argument("--ksm-token", help="KSM access token")
    parser.add_argument("--record-uid", required=True, help="KSM record UID")
    parser.add_argument("--config-file", required=True, help="Local config.json file path")
    
    args = parser.parse_args()
    
    # Validate authentication parameters
    if not args.ksm_config and not args.ksm_token:
        print("Either --ksm-config or --ksm-token must be provided")
        sys.exit(1)
    
    if args.ksm_config and args.ksm_token:
        print("Cannot specify both --ksm-config and --ksm-token")
        sys.exit(1)
    
    # Validate file paths early
    if args.ksm_config:
        is_valid, _ = validate_file_path(args.ksm_config)
        if not is_valid:
            print("Invalid KSM config file path")
            sys.exit(1)
    
    is_valid, _ = validate_file_path(args.config_file)
    if not is_valid:
        print("Invalid config file path")
        sys.exit(1)

    
    success = False
    
    try:
        if args.command == 'download':
            success = download_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
        elif args.command == 'upload':
            success = upload_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
        elif args.command == 'monitor':
            # Monitor runs indefinitely
            monitor_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
            success = True
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        success = True
    except Exception:
        print(f"ERROR: Unexpected error occurred")
        success = False
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

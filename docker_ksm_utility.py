#!/usr/bin/env python3
"""
Docker KSM Utility - Centralized utility for KSM operations in Docker containers.
Eliminates the need for temporary script generation.
"""

import sys
import os
import argparse
import time
import hashlib

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
    
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.storage import FileKeyValueStorage
    
    try:
        # Initialize SecretsManager
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                print(f"ERROR: KSM config file not found: {ksm_config_path}")
                return False
            secrets_manager = SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        else:
            secrets_manager = SecretsManager(token=ksm_token)
        
        # Get the record
        secrets = secrets_manager.get_secrets([record_uid])
        if not secrets:
            print(f"ERROR: Record not found: {record_uid}")
            return False
            
        secret = secrets[0]
        
        # Find config.json attachment
        for file in secret.files:
            if file.name.lower() == 'config.json':
                print(f"Found config.json attachment: {file.name}")
                file.save_file(output_path, True)
                print(f"Downloaded config.json to {output_path}")
                return True
        
        print(f"ERROR: config.json attachment not found in record: {record_uid}")
        return False
        
    except Exception as e:
        print(f"ERROR: Failed to download config from KSM: {str(e)}")
        return False

def upload_config(ksm_config_path, ksm_token, record_uid, config_file_path):
    """Upload config.json to KSM record, removing existing ones first."""
    if not check_ksm_dependency():
        return False
    
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.storage import FileKeyValueStorage
    from keeper_secrets_manager_core.core import KeeperFileUpload
    
    try:
        # Initialize SecretsManager
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                print(f"ERROR: KSM config file not found: {ksm_config_path}")
                return False
            secrets_manager = SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        else:
            secrets_manager = SecretsManager(token=ksm_token)
        
        # Get the record
        secrets = secrets_manager.get_secrets([record_uid])
        if not secrets:
            print(f"ERROR: Record not found: {record_uid}")
            return False
            
        secret = secrets[0]
        
        # Remove existing config.json files
        config_files = [f for f in secret.files if f.name.lower() == 'config.json']
        if len(config_files) > 0:
            files_to_remove = []
            for file_obj in config_files:
                try:
                    # Get UID directly from the file object instead of lookup by name
                    file_uid = None
                    if hasattr(file_obj, 'f') and file_obj.f:
                        file_uid = file_obj.f.get('fileUid')
                    elif hasattr(file_obj, 'fileUid'):
                        file_uid = file_obj.fileUid
                    elif hasattr(file_obj, 'uid'):
                        file_uid = file_obj.uid
                    
                    if file_uid:
                        files_to_remove.append(file_uid)
                        print(f"Found config.json to remove UID: {file_uid}")
                    else:
                        print(f"WARNING: Could not find UID for file: {file_obj.name}")
                        
                except Exception as e:
                    print(f"WARNING: Failed to get file UID for {file_obj.name}: {str(e)}")
            
            if files_to_remove:
                secrets_manager.save(secret, links_to_remove=files_to_remove)
                print(f"Removed {len(files_to_remove)} config.json file(s)")
                secret = secrets_manager.get_secrets([record_uid])[0]
        
        # Upload new config.json file
        if not os.path.exists(config_file_path):
            print(f"ERROR: Config file not found: {config_file_path}")
            return False
            
        print("Uploading new config.json...")
        my_file = KeeperFileUpload.from_file(config_file_path, 'config.json', 'config.json')
        file_uid = secrets_manager.upload_file(secret, file=my_file)
        print(f"Successfully uploaded new config.json UID: {file_uid}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to upload config: {str(e)}")
        return False

def monitor_config(ksm_config_path, ksm_token, record_uid, config_file_path):
    """Monitor config.json file for changes and upload when modified."""
    def get_file_hash(file_path):
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    print(f"Monitoring {config_file_path} for changes...")
    
    last_hash = get_file_hash(config_file_path)
    
    while True:
        try:
            time.sleep(30)  # Check every 30 seconds
            
            current_hash = get_file_hash(config_file_path)
            
            if current_hash is None:
                if last_hash is not None:
                    print(f"Config file {config_file_path} was removed, continuing to monitor...")
                    last_hash = None
                continue
            
            if current_hash != last_hash:
                print(f"Config file {config_file_path} changed, uploading to KSM record...")
                if upload_config(ksm_config_path, ksm_token, record_uid, config_file_path):
                    print("Config upload completed successfully")
                else:
                    print("Config upload failed")
                    
                last_hash = current_hash
                
        except Exception as e:
            print(f"Error in config monitor: {str(e)}")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="KSM Docker Utility")
    parser.add_argument("command", choices=['download', 'upload', 'monitor'], help="Command to execute")
    parser.add_argument("--ksm-config", help="KSM config file path")
    parser.add_argument("--ksm-token", help="KSM access token")
    parser.add_argument("--record-uid", required=True, help="KSM record UID")
    parser.add_argument("--config-file", required=True, help="Local config.json file path")
    
    args = parser.parse_args()
    
    # Validate authentication
    if not args.ksm_config and not args.ksm_token:
        print("ERROR: Either --ksm-config or --ksm-token must be provided")
        sys.exit(1)
    
    if args.ksm_config and args.ksm_token:
        print("ERROR: Cannot specify both --ksm-config and --ksm-token")
        sys.exit(1)
    
    success = False
    
    if args.command == 'download':
        success = download_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
    elif args.command == 'upload':
        success = upload_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
    elif args.command == 'monitor':
        # Monitor runs indefinitely
        monitor_config(args.ksm_config, args.ksm_token, args.record_uid, args.config_file)
        success = True
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

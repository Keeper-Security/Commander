#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to parse --user, --password, --server, --ksm-config, --ksm-token, and --record from arguments
parse_credentials() {
    USER=""
    PASSWORD=""
    SERVER=""
    KSM_CONFIG=""
    KSM_TOKEN=""
    RECORD=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --user)
                USER="$2"
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --server)
                SERVER="$2"
                shift 2
                ;;
            --ksm-config)
                KSM_CONFIG="$2"
                shift 2
                ;;
            --ksm-token)
                KSM_TOKEN="$2"
                shift 2
                ;;
            --record)
                RECORD="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
}

# Function to setup device registration and persistent login
setup_device() {
    local user="$1"
    local password="$2"
    local server="$3"
    # Step 1: Register device
    log "Registering device..."
    if ! python3 keeper.py --user "$user" --password "$password" --server $server this-device register; then
        log "ERROR: Device registration failed"
        exit 1
    fi
    
    # Step 2: Enable persistent login
    log "Enabling persistent login..."
    if ! python3 keeper.py --user "$user" --password "$password" --server $server this-device persistent-login on; then
        log "ERROR: Persistent login setup failed"
        exit 1
    fi

    # Step 3: Set timeout
    log "Setting device logout timeout to 30 Days..."
    if ! python3 keeper.py --user "$user" --password "$password" --server "$server" \
        this-device timeout 43200 \
        > /dev/null; then
        log "ERROR: Timeout setup failed"
        exit 1
    fi
    log "Device Logout Timeout set successfully"
    log "Device setup completed successfully"
}

# Function to download config.json from KSM record and save it to /home/commander/.keeper/
download_config_from_ksm() {
    local ksm_config_path="$1"
    local ksm_token="$2"
    local record_uid="$3"
    
    log "Downloading config.json from KSM record: $record_uid"
    
    # Create a temporary Python script to handle KSM operations
    local temp_script="/tmp/ksm_download.py"
    cat > "$temp_script" << 'EOF'
import sys
import os
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 ksm_download.py <ksm_config_path|token> <record_uid> <auth_type>")
        sys.exit(1)
    
    auth_param = sys.argv[1]
    record_uid = sys.argv[2]
    auth_type = sys.argv[3]  # 'config' or 'token'
    
    try:
        # Initialize SecretsManager based on auth type
        if auth_type == 'config':
            if not os.path.exists(auth_param):
                print(f"ERROR: KSM config file not found: {auth_param}")
                sys.exit(1)
            secrets_manager = SecretsManager(config=FileKeyValueStorage(auth_param))
        elif auth_type == 'token':
            secrets_manager = SecretsManager(token=auth_param)
        else:
            print(f"ERROR: Invalid auth type: {auth_type}")
            sys.exit(1)
        
        # Get the record
        secrets = secrets_manager.get_secrets([record_uid])
        if not secrets:
            print(f"ERROR: Record not found or no access to record: {record_uid}")
            sys.exit(1)
            
        secret = secrets[0]
        
        # Find and download config.json attachment
        config_found = False
        for file in secret.files:
            if file.name.lower() == 'config.json':
                print(f"Found config.json attachment: {file.name}")
                file.save_file("/home/commander/.keeper/config.json", True)
                config_found = True
                print("Successfully downloaded config.json to /home/commander/.keeper/config.json")
                break
        
        if not config_found:
            print(f"ERROR: config.json attachment not found in record: {record_uid}")
            available_files = [f.name for f in secret.files]
            print(f"Available attachments: {available_files}")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: Failed to download config from KSM: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

    # Execute the Python script
    if [[ -n "$ksm_config_path" ]]; then
        if ! python3 "$temp_script" "$ksm_config_path" "$record_uid" "config"; then
            log "ERROR: Failed to download config using KSM config file"
            rm -f "$temp_script"
            exit 1
        fi
    elif [[ -n "$ksm_token" ]]; then
        if ! python3 "$temp_script" "$ksm_token" "$record_uid" "token"; then
            log "ERROR: Failed to download config using KSM token"
            rm -f "$temp_script"
            exit 1
        fi
    else
        log "ERROR: Neither KSM config path nor KSM token provided"
        rm -f "$temp_script"
        exit 1
    fi
    
    # Clean up temporary script
    rm -f "$temp_script"
    log "Config.json downloaded successfully from KSM record"
}

# Function to remove --user, --password, --server, --ksm-config, --ksm-token, and --record from arguments and return the rest
filter_args() {
    local filtered_args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --user)
                shift 2  # Skip --user and its value
                ;;
            --password)
                shift 2  # Skip --password and its value
                ;;
            --server)
                shift 2  # Skip --server and its value
                ;;
            --ksm-config)
                shift 2  # Skip --ksm-config and its value
                ;;
            --ksm-token)
                shift 2  # Skip --ksm-token and its value
                ;;
            --record)
                shift 2  # Skip --record and its value
                ;;
            *)
                filtered_args+=("$1")
                shift
                ;;
        esac
    done
    
    echo "${filtered_args[@]}"
}

parse_credentials "$@"

mkdir -p /home/commander/.keeper

# Check if KSM authentication is requested
if [[ (-n "$KSM_CONFIG" || -n "$KSM_TOKEN") && -n "$RECORD" ]]; then
    log "KSM authentication detected, downloading config from record: $RECORD"
    
    # Validate KSM authentication parameters
    if [[ -n "$KSM_CONFIG" && -n "$KSM_TOKEN" ]]; then
        log "ERROR: Cannot specify both --ksm-config and --ksm-token"
        exit 1
    fi
    
    if [[ -n "$KSM_CONFIG" && ! -f "$KSM_CONFIG" ]]; then
        log "ERROR: KSM config file not found: $KSM_CONFIG"
        exit 1
    fi
    
    # Set environment variable to suppress KSM config file permission warnings
    export KSM_CONFIG_SKIP_MODE_WARNING=TRUE
    
    # Download config.json from KSM record
    download_config_from_ksm "$KSM_CONFIG" "$KSM_TOKEN" "$RECORD"
    
    # Filter out KSM arguments from command args
    COMMAND_ARGS=$(filter_args "$@")
    
    # Check if there are any command arguments
    if [[ -z "$COMMAND_ARGS" ]]; then
        log "No command arguments provided, keeping container alive..."
        sleep infinity
    else
        # Run the service command with downloaded config file
        log "Running: python3 keeper.py --config /home/commander/.keeper/config.json $COMMAND_ARGS"
        python3 keeper.py --config "/home/commander/.keeper/config.json" $COMMAND_ARGS
        log "Keeping container alive..."
        sleep infinity
    fi
# Check if config.json is mounted
elif [[ -f "/home/commander/.keeper/config.json" ]]; then
    CONFIG_FILE="/home/commander/.keeper/config.json"
    log "Config file found at $CONFIG_FILE, using config-based authentication"
    
    # Filter out --user and --password from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")
    
    # Check if there are any command arguments
    if [[ -z "$COMMAND_ARGS" ]]; then
        log "No command arguments provided, keeping container alive..."
        sleep infinity
    else
        # Run the service command with config file
        log "Running: python3 keeper.py --config $CONFIG_FILE $COMMAND_ARGS"
        python3 keeper.py --config "$CONFIG_FILE" $COMMAND_ARGS
        log "Keeping container alive..."
        sleep infinity
    fi
elif [[ -n "$USER" && -n "$PASSWORD" ]]; then
    log "No config file found, using user/password authentication"
    # Set default server if not specified
    if [[ -z "$SERVER" ]]; then
        SERVER="keepersecurity.com"
        log "Using default server: $SERVER"
    else
        log "Using specified server: $SERVER"
    fi

    # Setup device registration first
    setup_device "$USER" "$PASSWORD" "$SERVER"

    # Filter out --user, --password, and --server from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Check if there are any command arguments
    if [[ -z "$COMMAND_ARGS" ]]; then
        log "Keeping container alive..."
        sleep infinity
    else
        # Run the service-create command without credentials (device is now registered)
        log "Running: python3 keeper.py $COMMAND_ARGS"
        python3 keeper.py $COMMAND_ARGS
        log "Keeping container alive..."
        sleep infinity
    fi
else
    log "No config file found and no user/password provided"
    
    # Filter out --user, --password, and --server from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Check if there are any command arguments
    if [[ -z "$COMMAND_ARGS" ]]; then
        log "Keeping container alive..."
        sleep infinity
    else
        # Run the command directly without any authentication setup
        log "Running: python3 keeper.py $COMMAND_ARGS"
        python3 keeper.py $COMMAND_ARGS
        log "Keeping container alive..."
        sleep infinity
    fi
fi
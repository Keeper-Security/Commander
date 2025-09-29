#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to run keeper service with intelligent lifecycle management
run_keeper_service() {
    local config_arg="$1"
    local command_args="$2"
    
    # Check if command contains service-create
    if [[ "$command_args" =~ service-create ]]; then
        log "Service command detected, checking service status..."
        
        # Get service status
        local service_status=$(python3 keeper.py $config_arg service-status 2>/dev/null)
        
        if echo "$service_status" | grep -q "Stopped"; then
            log "Service exists but is stopped, starting it..."
            python3 keeper.py $config_arg service-start
        elif echo "$service_status" | grep -q "Running"; then
            log "Service is already running, no action needed."
        else
            log "Service not found, creating new service..."
            log "Running: python3 keeper.py $config_arg $command_args"
            python3 keeper.py $config_arg $command_args
        fi
    else
        # Not a service command, run as normal
        python3 keeper.py $config_arg $command_args
    fi
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
    
    # Use the KSM helper script for download
    local helper_args="download --record-uid $record_uid --config-file /home/commander/.keeper/config.json"
    
    if [[ -n "$ksm_config_path" ]]; then
        helper_args="$helper_args --ksm-config $ksm_config_path"
    elif [[ -n "$ksm_token" ]]; then
        helper_args="$helper_args --ksm-token $ksm_token"
    else
        log "ERROR: Neither KSM config path nor KSM token provided"
        exit 1
    fi
    
    if ! python3 docker_ksm_utility.py $helper_args; then
        log "ERROR: Failed to download config from KSM"
        exit 1
    fi
    
    log "Config.json downloaded successfully from KSM record"
}

# Function to start config.json monitoring and upload changes
start_config_monitor() {
    local ksm_config_path="$1"
    local ksm_token="$2"
    local record_uid="$3"
    local config_file_path="/home/commander/.keeper/config.json"
    
    log "Starting config.json monitoring for changes..."
    
    # Use the KSM helper script for monitoring
    local helper_args="monitor --record-uid $record_uid --config-file $config_file_path"
    
    if [[ -n "$ksm_config_path" ]]; then
        helper_args="$helper_args --ksm-config $ksm_config_path"
    elif [[ -n "$ksm_token" ]]; then
        helper_args="$helper_args --ksm-token $ksm_token"
    else
        log "ERROR: Neither KSM config path nor KSM token provided"
        return 1
    fi
    
    # Start the monitoring in the background
    nohup python3 docker_ksm_utility.py $helper_args > /home/commander/.keeper/config_monitor.log 2>&1 &
    local monitor_pid=$!
    echo "$monitor_pid" > /home/commander/.keeper/config_monitor.pid

    log "Monitor logs available at: /home/commander/.keeper/config_monitor.log"
}

# Function to stop config.json monitoring
stop_config_monitor() {
    local pid_file="/home/commander/.keeper/config_monitor.pid"
    
    if [[ -f "$pid_file" ]]; then
        local monitor_pid=$(cat "$pid_file")
        if kill -0 "$monitor_pid" 2>/dev/null; then
            log "Stopping config monitor with PID: $monitor_pid"
            kill "$monitor_pid" 2>/dev/null
            log "Config monitor stopped successfully"
        else
            log "Config monitor process (PID: $monitor_pid) not found"
        fi
        rm -f "$pid_file"
    fi
    
    # Clean up any remaining helper processes
    pkill -f "docker_ksm_utility.py.*monitor" 2>/dev/null || true
}

# Function to handle cleanup on exit
cleanup_on_exit() {
    log "Performing cleanup on exit..."
    stop_config_monitor
    log "Cleanup completed"
}

# Set up exit trap
trap cleanup_on_exit EXIT INT TERM

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
    
    # Start monitoring for config.json changes to upload back to KSM
    start_config_monitor "$KSM_CONFIG" "$KSM_TOKEN" "$RECORD"
    
    # Filter out KSM arguments from command args
    COMMAND_ARGS=$(filter_args "$@")
    
    # Check if there are any command arguments
    if [[ -z "$COMMAND_ARGS" ]]; then
        log "No command arguments provided, keeping container alive..."
        sleep infinity
    else
        # Run the service command with downloaded config file
        run_keeper_service "--config /home/commander/.keeper/config.json" "$COMMAND_ARGS"
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
        run_keeper_service "--config $CONFIG_FILE" "$COMMAND_ARGS"
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
        # Run the service command without credentials (device is now registered)
        run_keeper_service "" "$COMMAND_ARGS"
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
        run_keeper_service "" "$COMMAND_ARGS"
        log "Keeping container alive..."
        sleep infinity
    fi
fi
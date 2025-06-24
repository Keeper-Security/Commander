#!/bin/bash
set -e

# =============================================================================
# DOCKER ENTRYPOINT SCRIPT FOR KEEPER COMMANDER
# =============================================================================
# This script handles authentication and lifecycle management for Keeper
# Commander running in Docker containers. It supports multiple authentication
# methods: user/password, config files, and KSM (Keeper Secrets Manager).
# =============================================================================

# Configuration constants
readonly KEEPER_DIR="/home/commander/.keeper"
readonly CONFIG_FILE="${KEEPER_DIR}/config.json"
readonly MONITOR_LOG="${KEEPER_DIR}/config_monitor.log"
readonly MONITOR_PID_FILE="${KEEPER_DIR}/config_monitor.pid"
readonly DEFAULT_SERVER="keepersecurity.com"
readonly DEVICE_TIMEOUT="43200"  # 30 days in minutes
readonly MONITOR_INTERVAL="30"   # Config monitoring interval in seconds

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Function to log messages with timestamp
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
        local service_status
        service_status=$(python3 keeper.py ${config_arg} service-status 2>/dev/null || true)
        
        if echo "${service_status}" | grep -q "Stopped"; then
            log "Service exists but is stopped, starting it..."
            python3 keeper.py ${config_arg} service-start
        elif echo "${service_status}" | grep -q "Running"; then
            log "Service is already running, no action needed."
        else
            log "Service not found, creating new service..."
            log "Running: python3 keeper.py ${config_arg} ${command_args}"
            python3 keeper.py ${config_arg} ${command_args}
        fi
    else
        # Not a service command, run as normal
        python3 keeper.py ${config_arg} ${command_args}
    fi
}


# =============================================================================
# ARGUMENT PARSING FUNCTIONS
# =============================================================================

# Parse authentication credentials from command line arguments
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

# Filter out authentication arguments and return remaining command arguments
filter_args() {
    local filtered_args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --user|--password|--server|--ksm-config|--ksm-token|--record)
                shift 2  # Skip argument and its value
                ;;
            *)
                filtered_args+=("$1")
                shift
                ;;
        esac
    done
    
    echo "${filtered_args[@]}"
}


# =============================================================================
# KSM CONFIG PROCESSING FUNCTIONS
# =============================================================================

# Process KSM config using docker_ksm_utility.py
process_ksm_config() {
    local ksm_config_input="$1"
    
    log "Processing KSM config..." >&2
    
    # Use docker_ksm_utility.py to process the config
    local result_output
    result_output=$(python3 docker_ksm_utility.py process-config \
        --ksm-config "${ksm_config_input}" 2>/dev/null)
    local exit_code=$?
    
    if [[ ${exit_code} -eq 0 && -n "${result_output}" ]]; then
        # Extract the file path (last line of output)
        local file_path
        file_path=$(echo "${result_output}" | tail -n1)
        if [[ -f "${file_path}" ]]; then
            log "Successfully processed KSM config: ${file_path}" >&2
            echo "${file_path}"  # Only output the file path to stdout
            return 0
        fi
    fi
    
    log "ERROR: Failed to process KSM config" >&2
    return 1
}


# =============================================================================
# DEVICE SETUP AND AUTHENTICATION FUNCTIONS
# =============================================================================

# Setup device registration and persistent login
setup_device() {
    local user="$1"
    local password="$2"
    local server="$3"
    
    # Step 1: Register device
    log "Registering device..."
    if ! python3 keeper.py --user "${user}" --password "${password}" \
        --server "${server}" this-device register; then
        log "ERROR: Device registration failed"
        exit 1
    fi
    
    # Step 2: Enable persistent login
    log "Enabling persistent login..."
    if ! python3 keeper.py --user "${user}" --password "${password}" \
        --server "${server}" this-device persistent-login on; then
        log "ERROR: Persistent login setup failed"
        exit 1
    fi

    # Step 3: Set timeout
    log "Setting device logout timeout to 30 Days..."
    if ! python3 keeper.py --user "${user}" --password "${password}" \
        --server "${server}" this-device timeout "${DEVICE_TIMEOUT}" \
        > /dev/null; then
        log "ERROR: Timeout setup failed"
        exit 1
    fi
    
    log "Device Logout Timeout set successfully"
    log "Device setup completed successfully"
}


# =============================================================================
# KSM OPERATIONS FUNCTIONS
# =============================================================================

# Download config.json from KSM record and save it to the keeper directory
download_config_from_ksm() {
    local ksm_config_path="$1"
    local ksm_token="$2"
    local record_uid="$3"
    
    log "Downloading config.json from KSM record: ${record_uid}"
    
    # Build helper arguments
    local helper_args=("download" "--record-uid" "${record_uid}" \
        "--config-file" "${CONFIG_FILE}")
    
    if [[ -n "${ksm_config_path}" ]]; then
        helper_args+=("--ksm-config" "${ksm_config_path}")
    elif [[ -n "${ksm_token}" ]]; then
        helper_args+=("--ksm-token" "${ksm_token}")
    else
        log "ERROR: Neither KSM config path nor KSM token provided"
        exit 1
    fi
    
    if ! python3 docker_ksm_utility.py "${helper_args[@]}"; then
        log "ERROR: Failed to download config from KSM"
        exit 1
    fi
    
    log "Config.json downloaded successfully from KSM record"
}

# Start config.json monitoring and upload changes
start_config_monitor() {
    local ksm_config_path="$1"
    local ksm_token="$2"
    local record_uid="$3"
    
    log "Starting config.json monitoring for changes..."
    
    # Build helper arguments
    local helper_args=("monitor" "--record-uid" "${record_uid}" \
        "--config-file" "${CONFIG_FILE}")
    
    if [[ -n "${ksm_config_path}" ]]; then
        helper_args+=("--ksm-config" "${ksm_config_path}")
    elif [[ -n "${ksm_token}" ]]; then
        helper_args+=("--ksm-token" "${ksm_token}")
    else
        log "ERROR: Neither KSM config path nor KSM token provided"
        return 1
    fi
    
    # Start the monitoring in the background
    nohup python3 docker_ksm_utility.py "${helper_args[@]}" \
        > "${MONITOR_LOG}" 2>&1 &
    local monitor_pid=$!
    echo "${monitor_pid}" > "${MONITOR_PID_FILE}"

    log "Monitor logs available at: ${MONITOR_LOG}"
}

# Stop config.json monitoring
stop_config_monitor() {
    if [[ -f "${MONITOR_PID_FILE}" ]]; then
        local monitor_pid
        monitor_pid=$(cat "${MONITOR_PID_FILE}")
        if kill -0 "${monitor_pid}" 2>/dev/null; then
            log "Stopping config monitor with PID: ${monitor_pid}"
            kill "${monitor_pid}" 2>/dev/null || true
            log "Config monitor stopped successfully"
        else
            log "Config monitor process (PID: ${monitor_pid}) not found"
        fi
        rm -f "${MONITOR_PID_FILE}"
    fi
    
    # Clean up any remaining helper processes
    pkill -f "docker_ksm_utility.py.*monitor" 2>/dev/null || true
}


# =============================================================================
# CLEANUP AND SIGNAL HANDLING
# =============================================================================

# Handle cleanup on exit
cleanup_on_exit() {
    log "Performing cleanup on exit..."
    stop_config_monitor
    log "Cleanup completed"
}

# Set up exit trap for cleanup
trap cleanup_on_exit EXIT INT TERM


# =============================================================================
# MAIN EXECUTION LOGIC
# =============================================================================

# Parse command line arguments
parse_credentials "$@"

# Ensure keeper directory exists
mkdir -p "${KEEPER_DIR}"

# Process KSM config if provided
if [[ -n "${KSM_CONFIG}" ]]; then
    if PROCESSED_CONFIG_PATH=$(process_ksm_config "${KSM_CONFIG}"); then
        KSM_CONFIG="${PROCESSED_CONFIG_PATH}"
        log "KSM config ready: ${KSM_CONFIG}"
    else
        log "ERROR: Failed to process KSM config"
        exit 1
    fi
fi

# =============================================================================
# AUTHENTICATION METHOD DETECTION AND EXECUTION
# =============================================================================

# Check if KSM authentication is requested with record download
if [[ (-n "${KSM_CONFIG}" || -n "${KSM_TOKEN}") && -n "${RECORD}" ]]; then
    log "KSM authentication detected, downloading config from record: ${RECORD}"
    
    # Validate KSM authentication parameters
    if [[ -n "${KSM_CONFIG}" && -n "${KSM_TOKEN}" ]]; then
        log "ERROR: Cannot specify both --ksm-config and --ksm-token"
        exit 1
    fi
    
    if [[ -n "${KSM_CONFIG}" && ! -f "${KSM_CONFIG}" ]]; then
        log "ERROR: KSM config file not found: ${KSM_CONFIG}"
        exit 1
    fi
    
    # Set environment variable to suppress KSM config file permission warnings
    export KSM_CONFIG_SKIP_MODE_WARNING=TRUE
    
    # Download config.json from KSM record
    download_config_from_ksm "${KSM_CONFIG}" "${KSM_TOKEN}" "${RECORD}"
    
    # Start monitoring for config.json changes to upload back to KSM
    start_config_monitor "${KSM_CONFIG}" "${KSM_TOKEN}" "${RECORD}"
    
    # Filter out KSM arguments from command args
    COMMAND_ARGS=$(filter_args "$@")
    
    # Execute commands or keep container alive
    if [[ -z "${COMMAND_ARGS}" ]]; then
        log "No command arguments provided, keeping container alive..."
        sleep infinity
    else
        # Run the service command with downloaded config file
        run_keeper_service "--config ${CONFIG_FILE}" "${COMMAND_ARGS}"
        log "Keeping container alive..."
        sleep infinity
    fi
# Check if config.json is mounted or available
elif [[ -f "${CONFIG_FILE}" ]]; then
    log "Config file found at ${CONFIG_FILE}, using config-based authentication"
    
    # Filter out authentication arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")
    
    # Execute commands or keep container alive
    if [[ -z "${COMMAND_ARGS}" ]]; then
        log "No command arguments provided, keeping container alive..."
        sleep infinity
    else
        # Run the service command with config file
        run_keeper_service "--config ${CONFIG_FILE}" "${COMMAND_ARGS}"
        log "Keeping container alive..."
        sleep infinity
    fi
# Check if user/password authentication is provided
elif [[ -n "${USER}" && -n "${PASSWORD}" ]]; then
    log "No config file found, using user/password authentication"
    
    # Set default server if not specified
    if [[ -z "${SERVER}" ]]; then
        SERVER="${DEFAULT_SERVER}"
        log "Using default server: ${SERVER}"
    else
        log "Using specified server: ${SERVER}"
    fi

    # Setup device registration first
    setup_device "${USER}" "${PASSWORD}" "${SERVER}"

    # Filter out authentication arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Execute commands or keep container alive
    if [[ -z "${COMMAND_ARGS}" ]]; then
        log "Keeping container alive..."
        sleep infinity
    else
        # Run the service command without credentials (device is now registered)
        run_keeper_service "" "${COMMAND_ARGS}"
        log "Keeping container alive..."
        sleep infinity
    fi
# Fallback: no authentication provided
else
    log "No config file found and no user/password provided"
    
    # Filter out authentication arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Execute commands or keep container alive
    if [[ -z "${COMMAND_ARGS}" ]]; then
        log "Keeping container alive..."
        sleep infinity
    else
        # Run the command directly without any authentication setup
        run_keeper_service "" "${COMMAND_ARGS}"
        log "Keeping container alive..."
        sleep infinity
    fi
fi
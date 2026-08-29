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
readonly DEFAULT_SERVER="${KEEPER_SERVER:-keepersecurity.com}"
if [[ -n "${KEEPER_SERVER:-}" ]]; then
    export KEEPER_ALLOW_CUSTOM_SERVER="${KEEPER_ALLOW_CUSTOM_SERVER:-true}"
fi
readonly DEVICE_TIMEOUT="43200"  # 30 days in minutes
readonly MONITOR_INTERVAL="30"   # Config monitoring interval in seconds

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to run keeper service with intelligent lifecycle management.
# Usage: run_keeper_service <config_file_or_empty> <command> [args...]
# Arguments are passed through as an array so values containing spaces survive.
run_keeper_service() {
    local config_file="$1"
    shift

    local config_args=()
    if [[ -n "${config_file}" ]]; then
        config_args=("--config" "${config_file}")
    fi

    # Check if command contains service-create
    if [[ "$*" =~ service-create ]]; then
        log "Service command detected, checking service status..."

        # Get service status
        local service_status
        service_status=$(python3 keeper.py "${config_args[@]}" service-status 2>/dev/null || true)

        if echo "${service_status}" | grep -q "Stopped"; then
            log "Service exists but is stopped, starting it..."
            python3 keeper.py "${config_args[@]}" service-start
        elif echo "${service_status}" | grep -q "Running"; then
            log "Service is already running, no action needed."
        else
            log "Service not found, creating new service..."
            log "Running: python3 keeper.py ${config_args[*]} $*"
            python3 keeper.py "${config_args[@]}" "$@"
        fi
    else
        # Not a service command, run as normal
        python3 keeper.py "${config_args[@]}" "$@"
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

# Filter out authentication arguments, leaving the actual Commander command in
# the global COMMAND_ARGS array. An array rather than a string so that arguments
# containing spaces -- record titles, notes, search queries -- reach Commander
# as single arguments instead of being re-split by word splitting.
filter_args() {
    COMMAND_ARGS=()

    while [[ $# -gt 0 ]]; do
        case $1 in
            --user|--password|--server|--ksm-config|--ksm-token|--record)
                # Skip the flag and its value, tolerating a missing value.
                shift
                if [[ $# -gt 0 ]]; then
                    shift
                fi
                ;;
            *)
                COMMAND_ARGS+=("$1")
                shift
                ;;
        esac
    done
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

# Setup device registration and persistent login.
# All three steps run in a single Commander process so login + vault sync
# only happens once instead of three times.
setup_device() {
    local user="$1"
    local password="$2"
    local server="$3"

    log "Running device setup (register, persistent login, timeout)..."
    local setup_script
    setup_script=$(mktemp /tmp/keeper_setup_XXXXXX.cmd)
    cat > "${setup_script}" <<CMDS
this-device register
this-device persistent-login on
this-device timeout ${DEVICE_TIMEOUT}
CMDS

    if ! python3 keeper.py --user "${user}" --password "${password}" \
        --server "${server}" "${setup_script}"; then
        log "ERROR: Device setup failed"
        rm -f "${setup_script}"
        exit 1
    fi

    rm -f "${setup_script}"
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

# Upload config.json back to the KSM record once, without starting a monitor.
# Used after a one-shot command so refreshed device/session state is persisted
# before the container exits. Best effort: a failed upload must not mask the
# status of the command the user actually asked for.
upload_config_to_ksm() {
    local ksm_config_path="$1"
    local ksm_token="$2"
    local record_uid="$3"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        return 0
    fi

    local helper_args=("upload" "--record-uid" "${record_uid}" \
        "--config-file" "${CONFIG_FILE}")

    if [[ -n "${ksm_config_path}" ]]; then
        helper_args+=("--ksm-config" "${ksm_config_path}")
    elif [[ -n "${ksm_token}" ]]; then
        helper_args+=("--ksm-token" "${ksm_token}")
    else
        return 0
    fi

    log "Syncing config.json back to KSM record: ${record_uid}"
    if ! python3 docker_ksm_utility.py "${helper_args[@]}"; then
        log "WARNING: Failed to sync config back to KSM record"
    fi
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

# PID of the idle process used by keep-alive mode, so signal handling can end it.
KEEP_ALIVE_PID=""

# Handle cleanup on exit
cleanup_on_exit() {
    log "Performing cleanup on exit..."
    stop_config_monitor
    log "Cleanup completed"
}

# Handle SIGTERM/SIGINT (e.g. `docker stop`) by ending the keep-alive wait and
# exiting, which runs the EXIT trap and therefore the cleanup above.
on_terminate() {
    local signum="$1"

    log "Received signal, shutting down..."
    if [[ -n "${KEEP_ALIVE_PID}" ]]; then
        kill "${KEEP_ALIVE_PID}" 2>/dev/null || true
        KEEP_ALIVE_PID=""
    fi

    # Conventional shell status for death by signal.
    exit $((128 + signum))
}

# Set up traps: cleanup always runs on exit, signals shut down deliberately.
trap cleanup_on_exit EXIT
trap 'on_terminate 15' TERM
trap 'on_terminate 2' INT


# =============================================================================
# CONTAINER LIFECYCLE
# =============================================================================

# Decide whether the container should stay resident once setup is done.
#
# Persistent modes have to stay up: service mode leaves Commander running as a
# background daemon, and a bare `docker run` with no command is a request for a
# live container to exec into. A one-shot command is the opposite -- it must
# exit with its own status so the container behaves like the CLI it wraps and
# can be used in scripts and pipelines. Set KEEPER_KEEP_ALIVE=true to force the
# container to stay up regardless.
should_keep_alive() {
    local flag
    flag=$(printf '%s' "${KEEPER_KEEP_ALIVE:-}" | tr '[:upper:]' '[:lower:]')
    case "${flag}" in
        1|true|yes)
            return 0
            ;;
    esac

    # No command given -- nothing to finish, so keep the container available.
    if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
        return 0
    fi

    # Service mode runs Commander as a daemon inside the container.
    if [[ "${COMMAND_ARGS[*]}" =~ (service-create|service-start) ]]; then
        return 0
    fi

    return 1
}

# Run the requested command (if any) and return its exit status. Uses
# `|| status=$?` so that `set -e` does not abort before we can report it.
run_command_args() {
    local config_file="$1"
    local status=0

    if [[ ${#COMMAND_ARGS[@]} -gt 0 ]]; then
        run_keeper_service "${config_file}" "${COMMAND_ARGS[@]}" || status=$?
    fi

    return "${status}"
}

# Final disposition: hold the container open for persistent modes, otherwise
# exit with the wrapped command's status.
finish() {
    local status="${1:-0}"

    if should_keep_alive; then
        log "Keeping container alive..."
        # Idle in the background and `wait` rather than running `sleep infinity`
        # in the foreground: bash defers trap handlers until a foreground child
        # finishes, so a foreground sleep would make the container ignore
        # SIGTERM entirely and force `docker stop` to fall back to SIGKILL
        # without ever running cleanup.
        sleep infinity &
        KEEP_ALIVE_PID=$!
        wait "${KEEP_ALIVE_PID}" || true
    fi

    exit "${status}"
}


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

    # Filter out KSM arguments from command args
    filter_args "$@"

    if should_keep_alive; then
        # Persistent run: watch config.json and push changes back to the record
        # for as long as the container lives.
        start_config_monitor "${KSM_CONFIG}" "${KSM_TOKEN}" "${RECORD}"
        status=0
        run_command_args "${CONFIG_FILE}" || status=$?
        finish "${status}"
    fi

    # One-shot run: no monitor needed. Sync the config back once so refreshed
    # device/session state is preserved, then exit with the command's status.
    status=0
    run_command_args "${CONFIG_FILE}" || status=$?
    upload_config_to_ksm "${KSM_CONFIG}" "${KSM_TOKEN}" "${RECORD}"
    exit "${status}"
# Check if config.json is mounted or available
elif [[ -f "${CONFIG_FILE}" ]]; then
    log "Config file found at ${CONFIG_FILE}, using config-based authentication"

    # Filter out authentication arguments, keep the rest
    filter_args "$@"

    status=0
    run_command_args "${CONFIG_FILE}" || status=$?
    finish "${status}"
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
    filter_args "$@"

    # Run without credentials -- the device is registered at this point.
    status=0
    run_command_args "" || status=$?
    finish "${status}"
# Fallback: no authentication provided
else
    log "No config file found and no user/password provided"

    # Filter out authentication arguments, keep the rest
    filter_args "$@"

    # Run the command directly without any authentication setup
    status=0
    run_command_args "" || status=$?
    finish "${status}"
fi
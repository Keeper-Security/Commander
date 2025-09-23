#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to parse --user, --password, and --server from arguments
parse_credentials() {
    USER=""
    PASSWORD=""
    SERVER=""
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
    log "Setting up device registration and persistent login..."

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

# Function to remove --user, --password, and --server from arguments and return the rest
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
            *)
                filtered_args+=("$1")
                shift
                ;;
        esac
    done
    
    echo "${filtered_args[@]}"
}

parse_credentials "$@"

# Set default server if not specified
if [[ -z "$SERVER" ]]; then
    SERVER="keepersecurity.com"
    log "Using default server: $SERVER"
else
    log "Using specified server: $SERVER"
fi

# Ensure .keeper directory exists (permissions set in Dockerfile)
log "Ensuring .keeper directory exists..."
log "Current user: $(whoami), UID: $(id -u), GID: $(id -g)"
mkdir -p /home/commander/.keeper
log "Directory permissions: $(ls -ld /home/commander/.keeper)"

# Check if config.json is mounted
CONFIG_FILE="/home/commander/.keeper/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    log "Config file found at $CONFIG_FILE, using config-based authentication"
    
    # Filter out --user and --password from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")
    
    # Run the service command with config file
    log "Running: python3 keeper.py --config $CONFIG_FILE $COMMAND_ARGS"
    exec python3 keeper.py --config "$CONFIG_FILE" $COMMAND_ARGS
elif [[ -n "$USER" && -n "$PASSWORD" ]]; then
    log "No config file found, using user/password authentication"
    
    # Setup device registration first
    setup_device "$USER" "$PASSWORD" "$SERVER"

    # Filter out --user, --password, and --server from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Run the service-create command without credentials (device is now registered)
    log "Running: python3 keeper.py $COMMAND_ARGS"
    exec python3 keeper.py $COMMAND_ARGS
else
    log "No config file found and no user/password provided, running command directly"
    log "Note: Command may require authentication parameters to be passed directly"
    
    # Filter out --user, --password, and --server from arguments, keep the rest
    COMMAND_ARGS=$(filter_args "$@")

    # Run the command directly without any authentication setup
    log "Running: python3 keeper.py $COMMAND_ARGS"
    exec python3 keeper.py $COMMAND_ARGS
fi
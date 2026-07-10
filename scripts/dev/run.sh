#!/bin/bash
# scripts/dev/run.sh
# Usage: ./scripts/dev/run.sh [build|--help|args passed to Keeper Commander]

set -euo pipefail

WORKTREE_ROOT=$(git rev-parse --show-toplevel)
COMMON_GIT=$(git rev-parse --path-format=absolute --git-common-dir)

case "$COMMON_GIT" in
    */.git)
        REPO_ROOT=${COMMON_GIT%/.git}
        ;;
    */.git/worktrees/*)
        REPO_ROOT=${COMMON_GIT%%/.git/worktrees/*}
        ;;
    *)
        REPO_ROOT=$(dirname "$COMMON_GIT")
        ;;
esac

REPO_PARENT_DIR=$(dirname "$REPO_ROOT")
KEEPER_BRIDGE_BIN="${KEEPER_BRIDGE_BIN:-$REPO_PARENT_DIR/keeper-desktop-bridge/dist/keeper-desktop-bridge}"
KEEPER_BRIDGE_LEAF_SOCKET="${KEEPER_BRIDGE_LEAF_SOCKET:-/tmp/keeper-bridge-leaf.sock}"
KEEPER_VAULT_PERMISSION_SOCKET="${KEEPER_VAULT_PERMISSION_SOCKET:-/tmp/keeper-vault-permission.sock}"
KEEPER_BRIDGE_KEYCHAIN_SERVICE="${KEEPER_BRIDGE_KEYCHAIN_SERVICE:-keeper-desktop-bridge-dev}"
KDBC_VERIFICATION_POLICY="${KDBC_VERIFICATION_POLICY:-log_only}"
KDBC_WHEELS_DIR="$REPO_PARENT_DIR/keeper-desktop-bridge/dist/wheels"

python_bin() {
    if [[ -x "$WORKTREE_ROOT/.venv/bin/python" ]]; then
        printf '%s\n' "$WORKTREE_ROOT/.venv/bin/python"
    elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
        printf '%s\n' "$REPO_ROOT/.venv/bin/python"
    elif [[ -x "$WORKTREE_ROOT/venv/bin/python" ]]; then
        printf '%s\n' "$WORKTREE_ROOT/venv/bin/python"
    elif [[ -x "$REPO_ROOT/venv/bin/python" ]]; then
        printf '%s\n' "$REPO_ROOT/venv/bin/python"
    else
        command -v python3
    fi
}

PYTHON_BIN=$(python_bin)

keeper_bin() {
    if [[ -x "$WORKTREE_ROOT/.venv/bin/keeper" ]]; then
        printf '%s\n' "$WORKTREE_ROOT/.venv/bin/keeper"
    elif [[ -x "$REPO_ROOT/.venv/bin/keeper" ]]; then
        printf '%s\n' "$REPO_ROOT/.venv/bin/keeper"
    elif [[ -x "$WORKTREE_ROOT/venv/bin/keeper" ]]; then
        printf '%s\n' "$WORKTREE_ROOT/venv/bin/keeper"
    elif [[ -x "$REPO_ROOT/venv/bin/keeper" ]]; then
        printf '%s\n' "$REPO_ROOT/venv/bin/keeper"
    else
        echo "No Keeper Commander entrypoint found in $WORKTREE_ROOT/.venv or $WORKTREE_ROOT/venv" >&2
        echo "Run ./scripts/dev/run.sh build after creating the Commander virtualenv." >&2
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage:
  ./scripts/dev/run.sh             Build Commander, then open the Commander shell with --via-desktop.
  ./scripts/dev/run.sh build       Install local dev dependencies and Commander, then exit.
  ./scripts/dev/run.sh --help      Show this help.
  ./scripts/dev/run.sh [args...]   Build, then pass args to Commander.

Build behavior:
  - Installs keeper-desktop-bridge-client from:
    $KDBC_WHEELS_DIR/*.whl
  - Installs Commander editable from:
    $WORKTREE_ROOT

Default runtime paths:
  KEEPER_BRIDGE_BIN=$KEEPER_BRIDGE_BIN
  KEEPER_BRIDGE_LEAF_SOCKET=$KEEPER_BRIDGE_LEAF_SOCKET
  KEEPER_VAULT_PERMISSION_SOCKET=$KEEPER_VAULT_PERMISSION_SOCKET
  KEEPER_BRIDGE_KEYCHAIN_SERVICE=$KEEPER_BRIDGE_KEYCHAIN_SERVICE
  KDBC_VERIFICATION_POLICY=log_only

Override any default by exporting the same environment variable before running this script.
EOF
}

install_kdbc_wheel() {
    if ! compgen -G "$KDBC_WHEELS_DIR/*.whl" > /dev/null; then
        echo "No KDBC wheel found in $KDBC_WHEELS_DIR" >&2
        echo "Build keeper-desktop-bridge first so it publishes keeper-desktop-bridge-client wheels there." >&2
        exit 1
    fi

    echo "Installing KDBC wheel from $KDBC_WHEELS_DIR..."
    "$PYTHON_BIN" -m pip install \
        --no-index \
        --find-links "$KDBC_WHEELS_DIR" \
        --force-reinstall \
        keeper-desktop-bridge-client
}

build() {
    echo "Building Commander..."
    install_kdbc_wheel
    "$PYTHON_BIN" -m pip install -e "$WORKTREE_ROOT"
}

run() {
    echo "Running Commander..."
    if [[ "$#" -eq 0 ]]; then
        set -- shell
    fi

    if [[ ! -x "$KEEPER_BRIDGE_BIN" ]]; then
        echo "Missing keeper-desktop-bridge binary at $KEEPER_BRIDGE_BIN" >&2
        echo "Build keeper-desktop-bridge with its scripts/dev/run.sh first." >&2
        exit 1
    fi

    KEEPER_BIN=$(keeper_bin)

    KDBC_VERIFICATION_POLICY="$KDBC_VERIFICATION_POLICY" \
    KEEPER_BRIDGE_BIN="$KEEPER_BRIDGE_BIN" \
    KEEPER_BRIDGE_LEAF_SOCKET="$KEEPER_BRIDGE_LEAF_SOCKET" \
    KEEPER_VAULT_PERMISSION_SOCKET="$KEEPER_VAULT_PERMISSION_SOCKET" \
    KEEPER_BRIDGE_KEYCHAIN_SERVICE="$KEEPER_BRIDGE_KEYCHAIN_SERVICE" \
    "$KEEPER_BIN" --via-desktop "$@"
}

case "${1:-}" in
    -h|--help|help)
        usage
        ;;
    build)
        shift
        if [[ "$#" -ne 0 ]]; then
            echo "Usage error: build does not accept extra arguments." >&2
            echo "Run ./scripts/dev/run.sh --help for supported modes." >&2
            exit 2
        fi
        build
        ;;
    *)
        build
        run "$@"
        ;;
esac

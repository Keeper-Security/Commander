#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Test Runner
# ═══════════════════════════════════════════════════════════════════════════════
#
# A/B test harness for Keeper Commander's compliance commands.
# Runs a comprehensive batch of compliance subcommands and compares JSON output
# between two Commander installs (e.g. feature branch vs. baseline release).
#
# Prerequisites:
#   - Each Commander directory must have a .venv with keeper installed
#   - A logged-in session (run `keeper shell` once to cache credentials)
#   - python3 on PATH
#
# Quick start:
#   bash tests/compliance/run.sh after           # run tests on current branch
#   bash tests/compliance/run.sh before          # run tests on baseline
#   bash tests/compliance/run.sh diff            # compare existing results
#   bash tests/compliance/run.sh parallel        # run both simultaneously
#   bash tests/compliance/run.sh all             # run both sequentially, then diff
#
# Configuration:
#   The script auto-discovers users and teams from the vault. Override any
#   value by exporting env vars or creating tests/compliance/test.env:
#
#     AFTER_DIR       Commander under test      (default: repo root)
#     BEFORE_DIR      Baseline Commander        (default: empty, skips 'before')
#     KEEPER_CONFIG   Config file path          (default: ./config.json)
#     USER1           Primary admin email       (auto-discovered)
#     USER2           Secondary user email      (auto-discovered)
#     TEAM_ONLY_USER  User with team-only SF    (auto-discovered from TEAM1)
#     TEAM1           Team name or UID          (auto-discovered)
#
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEMPLATE="$SCRIPT_DIR/test.batch"
RESULTS_DIR="$SCRIPT_DIR/results"

# Load env file if present (won't override already-exported vars)
ENV_FILE="$SCRIPT_DIR/test.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading config from $ENV_FILE"
    set -a; source "$ENV_FILE"; set +a
fi

AFTER_DIR="${AFTER_DIR:-$REPO_DIR}"
BEFORE_DIR="${BEFORE_DIR:-}"
KEEPER_CONFIG="${KEEPER_CONFIG:-./config.json}"
AFTER_KEEPER_CONFIG="${AFTER_KEEPER_CONFIG:-$KEEPER_CONFIG}"
BEFORE_KEEPER_CONFIG="${BEFORE_KEEPER_CONFIG:-$KEEPER_CONFIG}"

# Convert path to native OS format for Python (no-op on Unix, forward-slash Windows path on MSYS)
native_path() {
    if command -v cygpath &>/dev/null; then
        cygpath -m "$1"
    else
        echo "$1"
    fi
}

# Resolve venv bin directory (Scripts on Windows, bin on Unix)
venv_keeper() {
    local dir="$1"
    if [ -x "$dir/.venv/Scripts/keeper" ] || [ -x "$dir/.venv/Scripts/keeper.exe" ]; then
        echo ".venv/Scripts/keeper"
    else
        echo ".venv/bin/keeper"
    fi
}

# ── Helper: run a keeper command and capture output ──────────────────────────
keeper_cmd() {
    local dir="$1"; shift
    local keeper; keeper=$(venv_keeper "$dir")
    local cfg="$KEEPER_CONFIG"
    [[ "$dir" == "$AFTER_DIR" ]] && cfg="$AFTER_KEEPER_CONFIG"
    [[ "$dir" == "$BEFORE_DIR" ]] && cfg="$BEFORE_KEEPER_CONFIG"
    (cd "$dir" && "$keeper" --config "$cfg" "$@" 2>/dev/null)
}

# ── Auto-discover test parameters from the vault ────────────────────────────
discover() {
    local dir="$1"
    echo "Discovering test parameters from vault ($dir) ..."

    if [ -z "${USER1:-}" ] || [ -z "${USER2:-}" ] || [ -z "${TEAM1:-}" ] || [ -z "${TEAM_ONLY_USER:-}" ]; then
        local users_json="" teams_json=""

        if [ -z "${USER1:-}" ] || [ -z "${USER2:-}" ]; then
            users_json=$(keeper_cmd "$dir" enterprise-info -u --format json || echo "[]")
            if [ -z "${USER1:-}" ]; then
                USER1=$(python3 -c "
import json, sys, random
users = json.loads(sys.stdin.read())
active = [u for u in users if u.get('status','') == 'Active']
print(random.choice(active)['email'] if active else users[0]['email'] if users else '')
" <<< "$users_json")
                echo "  USER1=$USER1"
            fi
            if [ -z "${USER2:-}" ]; then
                USER2=$(python3 -c "
import json, sys, random
users = json.loads(sys.stdin.read())
active = [u for u in users if u.get('status','') == 'Active' and u.get('email','') != '$USER1']
print(random.choice(active)['email'] if active else '')
" <<< "$users_json")
                echo "  USER2=$USER2"
            fi
        fi

        if [ -z "${TEAM1:-}" ] || [ -z "${TEAM_ONLY_USER:-}" ]; then
            teams_json=$(keeper_cmd "$dir" enterprise-info -t --columns users --format json || echo "[]")
            if [ -z "${TEAM1:-}" ]; then
                TEAM1=$(python3 -c "
import json, sys, random
teams = json.loads(sys.stdin.read())
skip = {'everyone', 'admins'}
candidates = [t for t in teams if t.get('name', t.get('team_name','')).lower() not in skip and len(t.get('users', [])) >= 2]
if not candidates:
    candidates = [t for t in teams if t.get('name', t.get('team_name','')).lower() not in skip and len(t.get('users', [])) >= 1]
if candidates:
    pick = random.choice(candidates)
    print(pick.get('name', pick.get('team_name','')))
elif teams:
    print(teams[0].get('name', teams[0].get('team_name','')))
" <<< "$teams_json")
                echo "  TEAM1=$TEAM1"
            fi
            if [ -z "${TEAM_ONLY_USER:-}" ]; then
                TEAM_ONLY_USER=$(python3 -c "
import json, sys
teams = json.loads(sys.stdin.read())
target, u1 = '$TEAM1', '$USER1'
for t in teams:
    if t.get('name', t.get('team_name','')) == target:
        members = t.get('users', [])
        others = [m for m in members if m != u1]
        if others:
            print(others[0])
            sys.exit(0)
print('$USER2')
" <<< "$teams_json")
                echo "  TEAM_ONLY_USER=$TEAM_ONLY_USER"
            fi
        fi
    fi

    # Validate
    local missing=()
    [ -z "${USER1:-}" ] && missing+=("USER1")
    [ -z "${USER2:-}" ] && missing+=("USER2")
    [ -z "${TEAM1:-}" ] && missing+=("TEAM1")
    [ -z "${TEAM_ONLY_USER:-}" ] && missing+=("TEAM_ONLY_USER")
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: Could not determine: ${missing[*]}"
        echo "Set them in $ENV_FILE or export as env vars."
        exit 1
    fi
    echo ""
}

# ── Generate a concrete batch file from the template ─────────────────────────
generate_batch() {
    local outdir="$1" dest="$2"
    outdir=$(native_path "$outdir")
    sed -e "s|{OUTDIR}|$outdir|g" \
        -e "s|{USER1}|$USER1|g" \
        -e "s|{USER2}|$USER2|g" \
        -e "s|{TEAM_ONLY_USER}|$TEAM_ONLY_USER|g" \
        -e "s|{TEAM1}|$TEAM1|g" \
        "$TEMPLATE" > "$dest"
}

# ── Run suites ───────────────────────────────────────────────────────────────
run_after() {
    discover "$AFTER_DIR"
    local out="$RESULTS_DIR/after"
    local batch="$RESULTS_DIR/after.batch"
    mkdir -p "$out"
    generate_batch "$out" "$batch"

    local keeper; keeper=$(venv_keeper "$AFTER_DIR")
    echo "=== Running AFTER (current branch) ==="
    echo "  Dir:    $AFTER_DIR"
    echo "  Output: $out"
    echo "  Config:"
    echo "    USER1=$USER1  USER2=$USER2"
    echo "    TEAM1=$TEAM1  TEAM_ONLY_USER=$TEAM_ONLY_USER"
    echo ""
    cd "$AFTER_DIR"
    "$keeper" --config "$AFTER_KEEPER_CONFIG" run-batch "$batch" 2>&1 | tee "$out/_run.log"
    echo ""
    echo "=== AFTER complete ==="
}

run_before() {
    if [ -z "$BEFORE_DIR" ]; then
        echo "ERROR: BEFORE_DIR is not set. Set it in $ENV_FILE or export it."
        exit 1
    fi
    discover "$BEFORE_DIR"
    local out="$RESULTS_DIR/before"
    local batch="$RESULTS_DIR/before.batch"
    mkdir -p "$out"
    generate_batch "$out" "$batch"

    local keeper; keeper=$(venv_keeper "$BEFORE_DIR")
    echo "=== Running BEFORE (baseline) ==="
    echo "  Dir:    $BEFORE_DIR"
    echo "  Output: $out"
    echo "  Config:"
    echo "    USER1=$USER1  USER2=$USER2"
    echo "    TEAM1=$TEAM1  TEAM_ONLY_USER=$TEAM_ONLY_USER"
    echo ""
    cd "$BEFORE_DIR"
    "$keeper" --config "$BEFORE_KEEPER_CONFIG" run-batch "$batch" 2>&1 | tee "$out/_run.log"
    echo ""
    echo "=== BEFORE complete ==="
}

# ── Compare results ──────────────────────────────────────────────────────────
diff_results() {
    local results_native
    results_native=$(native_path "$RESULTS_DIR")
    echo ""
    echo "=== Comparing results ==="
    echo ""
    python3 "$SCRIPT_DIR/diff.py" "$results_native"
}

# ── Main ─────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    after)    run_after ;;
    before)   run_before ;;
    diff)     diff_results ;;
    parallel)
        discover "$AFTER_DIR"
        run_after &
        local_after_pid=$!
        run_before &
        local_before_pid=$!
        echo "=== Running in parallel: after=$local_after_pid, before=$local_before_pid ==="
        wait $local_after_pid
        wait $local_before_pid
        diff_results
        ;;
    all)
        run_after
        echo ""
        run_before
        diff_results
        ;;
    *)
        cat <<'USAGE'
Compliance Test Runner — A/B test harness for Commander compliance commands.

Usage: bash tests/compliance/run.sh <mode>

Modes:
  after      Run the test suite against the current branch (AFTER_DIR)
  before     Run the test suite against the baseline install (BEFORE_DIR)
  diff       Compare existing after/before results
  parallel   Run both after and before simultaneously, then diff
  all        Run after, then before, then diff

Configuration:
  Set values in tests/compliance/test.env or export as env vars.
  If not set, USER1/USER2/TEAM1/TEAM_ONLY_USER are auto-discovered
  from the vault via enterprise-info.

  See tests/compliance/test.env.example for all options.
USAGE
        exit 1
        ;;
esac

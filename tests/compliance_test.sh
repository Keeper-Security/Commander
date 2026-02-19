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
#   bash tests/compliance_test.sh after           # run tests on current branch
#   bash tests/compliance_test.sh before          # run tests on baseline
#   bash tests/compliance_test.sh diff            # compare existing results
#   bash tests/compliance_test.sh parallel        # run both simultaneously
#   bash tests/compliance_test.sh all             # run both sequentially, then diff
#
# Configuration:
#   The script auto-discovers users and teams from the vault. Override any
#   value by exporting env vars or creating tests/compliance_test.env:
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
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$SCRIPT_DIR/compliance_test.batch"
RESULTS_DIR="$SCRIPT_DIR/compliance_test_results"

# Load env file if present (won't override already-exported vars)
ENV_FILE="$SCRIPT_DIR/compliance_test.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading config from $ENV_FILE"
    set -a; source "$ENV_FILE"; set +a
fi

AFTER_DIR="${AFTER_DIR:-$REPO_DIR}"
BEFORE_DIR="${BEFORE_DIR:-}"
KEEPER_CONFIG="${KEEPER_CONFIG:-./config.json}"

# ── Helper: run a keeper command and capture output ──────────────────────────
keeper_cmd() {
    local dir="$1"; shift
    (cd "$dir" && .venv/bin/keeper --config "$KEEPER_CONFIG" "$@" 2>/dev/null)
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
import json, sys
users = json.loads(sys.stdin.read())
active = [u for u in users if u.get('status','') == 'Active']
print(active[0]['email'] if active else users[0]['email'] if users else '')
" <<< "$users_json")
                echo "  USER1=$USER1"
            fi
            if [ -z "${USER2:-}" ]; then
                USER2=$(python3 -c "
import json, sys
users = json.loads(sys.stdin.read())
active = [u for u in users if u.get('status','') == 'Active' and u.get('email','') != '$USER1']
print(active[-1]['email'] if active else '')
" <<< "$users_json")
                echo "  USER2=$USER2"
            fi
        fi

        if [ -z "${TEAM1:-}" ] || [ -z "${TEAM_ONLY_USER:-}" ]; then
            teams_json=$(keeper_cmd "$dir" enterprise-info -t --columns users --format json || echo "[]")
            if [ -z "${TEAM1:-}" ]; then
                TEAM1=$(python3 -c "
import json, sys
teams = json.loads(sys.stdin.read())
skip = {'everyone', 'admins'}
candidates = [t for t in teams if t.get('team_name','').lower() not in skip]
print(candidates[0]['team_name'] if candidates else (teams[0]['team_name'] if teams else ''))
" <<< "$teams_json")
                echo "  TEAM1=$TEAM1"
            fi
            if [ -z "${TEAM_ONLY_USER:-}" ]; then
                TEAM_ONLY_USER=$(python3 -c "
import json, sys
teams = json.loads(sys.stdin.read())
target, u1 = '$TEAM1', '$USER1'
for t in teams:
    if t.get('team_name','') == target:
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

    echo "=== Running AFTER (current branch) ==="
    echo "  Dir:    $AFTER_DIR"
    echo "  Output: $out"
    echo "  Config:"
    echo "    USER1=$USER1  USER2=$USER2"
    echo "    TEAM1=$TEAM1  TEAM_ONLY_USER=$TEAM_ONLY_USER"
    echo ""
    cd "$AFTER_DIR"
    .venv/bin/keeper --config "$KEEPER_CONFIG" run-batch "$batch" 2>&1 | tee "$out/_run.log"
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

    echo "=== Running BEFORE (baseline) ==="
    echo "  Dir:    $BEFORE_DIR"
    echo "  Output: $out"
    echo "  Config:"
    echo "    USER1=$USER1  USER2=$USER2"
    echo "    TEAM1=$TEAM1  TEAM_ONLY_USER=$TEAM_ONLY_USER"
    echo ""
    cd "$BEFORE_DIR"
    .venv/bin/keeper --config "$KEEPER_CONFIG" run-batch "$batch" 2>&1 | tee "$out/_run.log"
    echo ""
    echo "=== BEFORE complete ==="
}

# ── Compare results ──────────────────────────────────────────────────────────
diff_results() {
    local after_out="$RESULTS_DIR/after"
    local before_out="$RESULTS_DIR/before"
    echo ""
    echo "=== Comparing results ==="
    echo ""

    if [ ! -d "$after_out" ]; then
        echo "ERROR: No 'after' results found at $after_out"; exit 1
    fi
    if [ ! -d "$before_out" ]; then
        echo "ERROR: No 'before' results found at $before_out"; exit 1
    fi

    local any_diff=0
    for f in "$after_out"/t*.json; do
        local fname
        fname=$(basename "$f")
        local before_f="$before_out/$fname"
        if [ ! -f "$before_f" ]; then
            echo "  [SKIP]  $fname — no baseline (new test or baseline error)"
            continue
        fi
        local after_rows before_rows
        after_rows=$(python3 -c "import json; d=json.load(open('$f')); print(len(d) if isinstance(d,list) else 'obj')" 2>/dev/null || echo "ERR")
        before_rows=$(python3 -c "import json; d=json.load(open('$before_f')); print(len(d) if isinstance(d,list) else 'obj')" 2>/dev/null || echo "ERR")
        if [ "$after_rows" = "$before_rows" ]; then
            echo "  [OK]    $fname — rows: $after_rows"
        else
            echo "  [DIFF]  $fname — before=$before_rows, after=$after_rows"
            any_diff=1
        fi
    done

    for f in "$after_out"/t*.json; do
        local fname
        fname=$(basename "$f")
        if [ ! -f "$before_out/$fname" ]; then
            local after_rows
            after_rows=$(python3 -c "import json; d=json.load(open('$f')); print(len(d) if isinstance(d,list) else 'obj')" 2>/dev/null || echo "ERR")
            echo "  [NEW]   $fname — rows: $after_rows (no baseline to compare)"
        fi
    done

    echo ""
    if [ "$any_diff" -eq 0 ]; then
        echo "All comparable tests match."
    else
        echo "Some tests differ — review above."
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    after)    run_after ;;
    before)   run_before ;;
    diff)     diff_results ;;
    parallel)
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

Usage: bash tests/compliance_test.sh <mode>

Modes:
  after      Run the test suite against the current branch (AFTER_DIR)
  before     Run the test suite against the baseline install (BEFORE_DIR)
  diff       Compare existing after/before results
  parallel   Run both after and before simultaneously, then diff
  all        Run after, then before, then diff

Configuration:
  Set values in tests/compliance_test.env or export as env vars.
  If not set, USER1/USER2/TEAM1/TEAM_ONLY_USER are auto-discovered
  from the vault via enterprise-info.

  See tests/compliance_test.env.example for all options.
USAGE
        exit 1
        ;;
esac

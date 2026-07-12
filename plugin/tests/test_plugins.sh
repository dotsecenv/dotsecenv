#!/usr/bin/env bash
# E2E tests for dotsecenv shell plugins (bash and zsh)
# For fish tests, use test_plugins.fish
#
# Usage:
#   ./test_plugins.sh [--bash-only|--zsh-only] [--verbose]
#
# Requires bash 5.2+ (on macOS, will attempt to use Homebrew's bash)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SHELL_DIR="$PROJECT_ROOT"

# Check if a bash binary is version 5+
is_bash5() {
    local bash_bin="$1"
    [[ -x "$bash_bin" ]] || return 1
    local version
    version=$("$bash_bin" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    [[ -n "$version" ]] || return 1
    local major="${version%%.*}"
    [[ "$major" -ge 5 ]]
}

# Find a suitable bash 5.x binary
find_bash5() {
    local candidates=(
        "/opt/homebrew/bin/bash" # macOS Apple Silicon Homebrew
        "/usr/local/bin/bash"    # macOS Intel Homebrew / Linux custom
        "$(command -v bash)"     # System PATH
    )

    for bash_bin in "${candidates[@]}"; do
        if is_bash5 "$bash_bin"; then
            echo "$bash_bin"
            return 0
        fi
    done

    return 1
}

# Set BASH_BIN to the appropriate bash binary
BASH_BIN=""
if ! BASH_BIN=$(find_bash5); then
    echo "Error: bash 5.x required but not found."
    echo "On macOS, install with: brew install bash"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Options
TEST_BASH=1
TEST_ZSH=1
VERBOSE=0

# Parse arguments
for arg in "$@"; do
    case "$arg" in
    --bash-only)
        TEST_ZSH=0
        ;;
    --zsh-only)
        TEST_BASH=0
        ;;
    --verbose) VERBOSE=1 ;;
    esac
done

# Logging
log() { echo -e "${BLUE}[TEST]${NC} $*"; }
pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++)) || true
}
fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++)) || true
}
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
debug() { [[ $VERBOSE -eq 1 ]] && echo -e "[DEBUG] $*" || true; }

# Create a temporary directory for tests
TEMP_DIR=""
cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

setup_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    debug "Created temp directory: $TEMP_DIR"
}

# Mock dotsecenv CLI for testing
# This creates a mock that returns predictable values
create_mock_dotsecenv() {
    local mock_dir="$TEMP_DIR/mock_bin"
    mkdir -p "$mock_dir"

    cat >"$mock_dir/dotsecenv" <<'MOCK_EOF'
#!/usr/bin/env bash
# Mock dotsecenv CLI for testing

if [[ "$1" == "secret" && "$2" == "get" ]]; then
    case "$3" in
        "DB_PASSWORD") echo "super-secret-password" ;;
        "API_KEY") echo "mock-api-key-12345" ;;
        "PROD_SECRET") echo "production-secret-value" ;;
        "MISSING_SECRET") exit 1 ;;
        "MULTILINE_SECRET") printf 'line1\nline2\nline3' ;;
        *) exit 1 ;;
    esac
else
    # Pass through to real binary if it exists
    if [[ -x "$REAL_DOTSECENV" ]]; then
        "$REAL_DOTSECENV" "$@"
    else
        exit 1
    fi
fi
MOCK_EOF
    chmod +x "$mock_dir/dotsecenv"
    echo "$mock_dir"
}

# Test helper: run a command in a subshell with the plugin loaded
run_with_plugin_bash() {
    local test_dir="$1"
    local mock_path="$2"
    shift 2
    local cmd="$*"

    # Run bash with the plugin sourced, preserving existing PATH
    "$BASH_BIN" -c "
        export PATH='$mock_path:$PATH'
        export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/_dotsecenv_core.sh'
        source '$SHELL_DIR/dotsecenv.plugin.bash'
        cd '$test_dir'
        # Trigger directory change hook
        _dotsecenv_chpwd_hook
        $cmd
    " 2>&1
}

run_with_plugin_zsh() {
    local test_dir="$1"
    local mock_path="$2"
    shift 2
    local cmd="$*"

    # Run zsh with the plugin sourced, preserving existing PATH
    zsh -i -f -c "
        export PATH='$mock_path:$PATH'
        export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/dotsecenv.plugin.zsh'
        cd '$test_dir'
        $cmd
    " 2>&1
}

# ============================================================================
# Test Functions
# ============================================================================

test_parse_plain_secenv() {
    local shell="$1"
    log "[$shell] Testing plain .secenv parsing..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_plain_secenv"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
DATABASE_HOST=localhost
DATABASE_PORT=5432
APP_NAME="My Application"
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$DATABASE_HOST|\$DATABASE_PORT|\$APP_NAME\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$DATABASE_HOST|\$DATABASE_PORT|\$APP_NAME\"
        " 2>&1)
    fi

    if [[ "$result" == *"localhost|5432|My Application"* ]]; then
        pass "[$shell] Plain .secenv parsing works correctly"
    else
        fail "[$shell] Plain .secenv parsing failed, got: $result"
    fi
}

test_parse_secret_same_name() {
    local shell="$1"
    log "[$shell] Testing {dotsecenv} secret (same name)..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_secret_same"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] {dotsecenv} secret resolution works correctly"
    else
        fail "[$shell] {dotsecenv} secret resolution failed, got: $result"
    fi
}

test_parse_secret_named() {
    local shell="$1"
    log "[$shell] Testing {dotsecenv/name} secret (named)..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_secret_named"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
MY_API_KEY={dotsecenv/API_KEY}
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$MY_API_KEY\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$MY_API_KEY\"
        " 2>&1)
    fi

    if [[ "$result" == *"mock-api-key-12345"* ]]; then
        pass "[$shell] {dotsecenv/name} secret resolution works correctly"
    else
        fail "[$shell] {dotsecenv/name} secret resolution failed, got: $result"
    fi
}

test_missing_secret_warning() {
    local shell="$1"
    log "[$shell] Testing missing secret error..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_missing_secret"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
MISSING_SECRET={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"VAR=\$MISSING_SECRET\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"VAR=\$MISSING_SECRET\"
        " 2>&1)
    fi

    if [[ "$result" == *"error"* && "$result" == *"fetching secret"* ]]; then
        pass "[$shell] Missing secret error displayed correctly"
    else
        fail "[$shell] Missing secret error not displayed, got: $result"
    fi
}

test_missing_secret_error_deduped() {
    local shell="$1"
    log "[$shell] Testing missing secret error printed once for multiple keys..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_missing_secret_dedupe"
    mkdir -p "$test_dir"

    # Two keys mapping to the same missing secret
    cat >"$test_dir/.secenv" <<'EOF'
MISSING_SECRET={dotsecenv}
TF_VAR_MISSING={dotsecenv/MISSING_SECRET}
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
        " 2>&1)
    fi

    local error_count
    error_count=$(printf '%s\n' "$result" | grep -c "error fetching secret 'MISSING_SECRET'" || true)

    if [[ "$error_count" == "1" && "$result" == *"TF_VAR_MISSING not set (secret 'MISSING_SECRET' failed above)"* ]]; then
        pass "[$shell] Missing secret error printed once, second key got a short notice"
    else
        fail "[$shell] Expected 1 full error and a short notice, got ($error_count errors): $result"
    fi
}

test_security_check_world_writable() {
    local shell="$1"
    log "[$shell] Testing security check (world-writable)..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_security"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
UNSAFE_VAR=should-not-load
EOF
    chmod 666 "$test_dir/.secenv" # World-writable

    # Pre-trust the directory (but security check should still fail)
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"VAR=\${UNSAFE_VAR:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"VAR=\${UNSAFE_VAR:-unset}\"
        " 2>&1)
    fi

    if [[ "$result" == *"refusing"* && "$result" == *"world-writable"* ]]; then
        pass "[$shell] World-writable file rejected correctly"
    else
        fail "[$shell] World-writable file not rejected, got: $result"
    fi
}

test_two_phase_loading() {
    local shell="$1"
    log "[$shell] Testing two-phase loading..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_two_phase"
    mkdir -p "$test_dir"

    # Mixed plain and secret values in .secenv
    cat >"$test_dir/.secenv" <<'EOF'
PLAIN_VAR=plain-value
SECRET_VAR={dotsecenv/API_KEY}
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$PLAIN_VAR|\$SECRET_VAR\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$PLAIN_VAR|\$SECRET_VAR\"
        " 2>&1)
    fi

    if [[ "$result" == *"plain-value|mock-api-key-12345"* ]]; then
        pass "[$shell] Two-phase loading works correctly"
    else
        fail "[$shell] Two-phase loading failed, got: $result"
    fi
}

test_load_unload_message_split() {
    local shell="$1"
    log "[$shell] Testing env var(s)/secret(s) messages split on load and unload..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_msg_split/project"
    mkdir -p "$test_dir"
    mkdir -p "$TEMP_DIR/test_msg_split/other"

    # 2 plain vars + 2 secret references
    cat >"$test_dir/.secenv" <<'EOF'
APP_ENV=production
NODE_ENV=staging
DB_URL={dotsecenv/DB_PASSWORD}
SVC_KEY={dotsecenv/API_KEY}
EOF
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config_msg_split"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            cd '$TEMP_DIR/test_msg_split/other'
            _dotsecenv_chpwd_hook
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            cd '$TEMP_DIR/test_msg_split/other'
        " 2>&1)
    fi

    if [[ "$result" == *"loaded 2 env var(s) from .secenv: APP_ENV, NODE_ENV"* &&
        "$result" == *"loaded 2 secret(s) from .secenv: DB_URL, SVC_KEY"* &&
        "$result" == *"unloaded 2 env var(s): APP_ENV, NODE_ENV"* &&
        "$result" == *"unloaded 2 secret(s): DB_URL, SVC_KEY"* ]]; then
        pass "[$shell] Plain vars and secrets reported on separate lines"
    else
        fail "[$shell] Message split incorrect, got: $result"
    fi
}

test_empty_secenv_no_message() {
    local shell="$1"
    log "[$shell] Testing an empty .secenv produces no load message..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_empty_secenv"
    mkdir -p "$test_dir"
    : >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config_empty_secenv"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo MARKER
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo MARKER
        " 2>&1)
    fi

    if [[ "$result" == *"MARKER"* && "$result" != *"loaded"* && "$result" != *"env var(s)"* && "$result" != *"secret(s)"* ]]; then
        pass "[$shell] Empty .secenv produces no load message"
    else
        fail "[$shell] Empty .secenv produced unexpected output, got: $result"
    fi
}

test_alias_dse() {
    local shell="$1"
    log "[$shell] Testing 'dse' alias..."
    ((TESTS_RUN++)) || true

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$("$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            type dse
        " 2>&1)
    else
        result=$(zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            type dse
        " 2>&1)
    fi

    if [[ "$result" == *"function"* ]]; then
        pass "[$shell] 'dse' alias is defined"
    else
        fail "[$shell] 'dse' alias not defined, got: $result"
    fi
}

test_alias_dse_get() {
    local shell="$1"
    log "[$shell] Testing 'dse get' subcommand..."
    ((TESTS_RUN++)) || true

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$("$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            dse get API_KEY
        " 2>&1)
    else
        result=$(zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            dse get API_KEY
        " 2>&1)
    fi

    if [[ "$result" == "mock-api-key-12345" ]]; then
        pass "[$shell] 'dse get' subcommand works correctly"
    else
        fail "[$shell] 'dse get' subcommand failed, got: $result"
    fi
}

test_comments_and_empty_lines() {
    local shell="$1"
    log "[$shell] Testing comments and empty lines handling..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_comments"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
# This is a comment
DATABASE_HOST=localhost

# Another comment
DATABASE_PORT=5432

EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$DATABASE_HOST|\$DATABASE_PORT\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$DATABASE_HOST|\$DATABASE_PORT\"
        " 2>&1)
    fi

    if [[ "$result" == *"localhost|5432"* ]]; then
        pass "[$shell] Comments and empty lines handled correctly"
    else
        fail "[$shell] Comments/empty lines handling failed, got: $result"
    fi
}

test_quoted_values() {
    local shell="$1"
    log "[$shell] Testing quoted values..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_quotes"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
DOUBLE_QUOTED="hello world"
SINGLE_QUOTED='hello world'
UNQUOTED=helloworld
EOF
    chmod 644 "$test_dir/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$DOUBLE_QUOTED|\$SINGLE_QUOTED|\$UNQUOTED\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$DOUBLE_QUOTED|\$SINGLE_QUOTED|\$UNQUOTED\"
        " 2>&1)
    fi

    if [[ "$result" == *"hello world|hello world|helloworld"* ]]; then
        pass "[$shell] Quoted values parsed correctly"
    else
        fail "[$shell] Quoted values parsing failed, got: $result"
    fi
}

# ============================================================================
# Tree-Scoped Loading Tests
# ============================================================================

test_tree_scope_persist_in_subdir() {
    local shell="$1"
    log "[$shell] Testing secrets persist when entering subdirectory..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_persist"
    mkdir -p "$test_dir/parent/child"

    # Parent has .secenv
    cat >"$test_dir/parent/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/parent/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/parent'
            _dotsecenv_chpwd_hook
            cd '$test_dir/parent/child'
            _dotsecenv_chpwd_hook
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/parent'
            cd '$test_dir/parent/child'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] Secrets persist in subdirectory"
    else
        fail "[$shell] Secrets did not persist in subdirectory, got: $result"
    fi
}

test_tree_scope_unload_on_leave() {
    local shell="$1"
    log "[$shell] Testing secrets unload when leaving tree..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_unload"
    mkdir -p "$test_dir/project"
    mkdir -p "$test_dir/other"

    # Project has .secenv
    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            cd '$test_dir/other'
            _dotsecenv_chpwd_hook
            echo \"VAR=\${DB_PASSWORD:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            cd '$test_dir/other'
            _dotsecenv_chpwd_hook
            echo \"VAR=\${DB_PASSWORD:-unset}\"
        " 2>&1)
    fi

    if [[ "$result" == *"VAR=unset"* ]]; then
        pass "[$shell] Secrets unloaded when leaving tree"
    else
        fail "[$shell] Secrets not unloaded when leaving tree, got: $result"
    fi
}

test_tree_scope_nested_secenv() {
    local shell="$1"
    log "[$shell] Testing nested .secenv layers on top of parent..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_nested"
    mkdir -p "$test_dir/parent/child"

    # Parent has DB_PASSWORD
    cat >"$test_dir/parent/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/parent/.secenv"

    # Child has API_KEY
    cat >"$test_dir/parent/child/.secenv" <<'EOF'
API_KEY={dotsecenv}
EOF
    chmod 644 "$test_dir/parent/child/.secenv"

    # Pre-trust both directories
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"
    echo "$test_dir/parent/child" >>"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/parent'
            _dotsecenv_chpwd_hook
            cd '$test_dir/parent/child'
            _dotsecenv_chpwd_hook
            echo \"\$DB_PASSWORD|\$API_KEY\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/parent'
            cd '$test_dir/parent/child'
            echo \"\$DB_PASSWORD|\$API_KEY\"
        " 2>&1)
    fi

    if [[ "$result" == *"super-secret-password|mock-api-key-12345"* ]]; then
        pass "[$shell] Nested .secenv layers correctly"
    else
        fail "[$shell] Nested .secenv layering failed, got: $result"
    fi
}

test_tree_scope_sibling_navigation() {
    local shell="$1"
    log "[$shell] Testing sibling navigation keeps ancestor secrets..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_sibling"
    mkdir -p "$test_dir/parent/child1"
    mkdir -p "$test_dir/parent/child2"

    # Parent has .secenv
    cat >"$test_dir/parent/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/parent/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/parent'
            _dotsecenv_chpwd_hook
            cd '$test_dir/parent/child1'
            _dotsecenv_chpwd_hook
            cd '$test_dir/parent/child2'
            _dotsecenv_chpwd_hook
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/parent'
            cd '$test_dir/parent/child1'
            cd '$test_dir/parent/child2'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] Sibling navigation keeps ancestor secrets"
    else
        fail "[$shell] Sibling navigation lost ancestor secrets, got: $result"
    fi
}

test_tree_scope_no_reload_from_subdir() {
    local shell="$1"
    log "[$shell] Testing secrets persist (no reload) when returning from subdirectory..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_no_reload"
    mkdir -p "$test_dir/project/src"

    # Project has .secenv
    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    # Pre-trust the directory
    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            cd '$test_dir/project/src'
            _dotsecenv_chpwd_hook
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            cd '$test_dir/project/src'
            cd '$test_dir/project'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    # Should NOT see unload message - secrets should persist without reloading
    # But should still have the secret value
    if [[ "$result" == *"unloaded"* ]]; then
        fail "[$shell] Secrets were unnecessarily unloaded, got: $result"
    elif [[ "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] Secrets persist without reload when returning from subdirectory"
    else
        fail "[$shell] Secret value not found, got: $result"
    fi
}

test_multiline_warning() {
    local shell="$1"
    log "[$shell] Testing multiline value warning..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_multiline"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
MULTILINE_SECRET={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
        " 2>&1)
    fi

    if [[ "$result" == *"contains newlines"* && "$result" == *"always quote"* ]]; then
        pass "[$shell] Multiline value warning displayed correctly"
    else
        fail "[$shell] Multiline value warning not displayed, got: $result"
    fi
}

# ============================================================================
# dse up Tests
# ============================================================================

test_dse_up_basic() {
    local shell="$1"
    log "[$shell] Testing 'dse up' loads ancestor .secenv..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_up_basic"
    mkdir -p "$test_dir/project/terraform/modules"

    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    local config_dir="$TEMP_DIR/config_dse_up_basic"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project/terraform/modules'
            _dotsecenv_chpwd_hook
            dse up '$test_dir'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project/terraform/modules'
            dse up '$test_dir'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] 'dse up' loads ancestor .secenv correctly"
    else
        fail "[$shell] 'dse up' failed to load ancestor .secenv, got: $result"
    fi
}

test_dse_up_multiple_ancestors() {
    local shell="$1"
    log "[$shell] Testing 'dse up' loads multiple ancestor .secenv files..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_up_multi"
    mkdir -p "$test_dir/root/project/src"

    cat >"$test_dir/root/.secenv" <<'EOF'
APP_ENV=production
EOF
    chmod 644 "$test_dir/root/.secenv"

    cat >"$test_dir/root/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/root/project/.secenv"

    local config_dir="$TEMP_DIR/config_dse_up_multi"
    mkdir -p "$config_dir"
    echo "$test_dir/root" >"$config_dir/trusted_dirs"
    echo "$test_dir/root/project" >>"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/root/project/src'
            _dotsecenv_chpwd_hook
            dse up '$test_dir'
            echo \"\$APP_ENV|\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/root/project/src'
            dse up '$test_dir'
            echo \"\$APP_ENV|\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"production|super-secret-password"* ]]; then
        pass "[$shell] 'dse up' loads multiple ancestor .secenv files correctly"
    else
        fail "[$shell] 'dse up' multi-ancestor failed, got: $result"
    fi
}

test_dse_up_skips_already_loaded() {
    local shell="$1"
    log "[$shell] Testing 'dse up' skips already-loaded ancestors..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_up_skip"
    mkdir -p "$test_dir/project/src"

    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    local config_dir="$TEMP_DIR/config_dse_up_skip"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            cd '$test_dir/project/src'
            _dotsecenv_chpwd_hook
            dse up '$test_dir'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            cd '$test_dir/project/src'
            dse up '$test_dir'
            echo \"\$DB_PASSWORD\"
        " 2>&1)
    fi

    if [[ "$result" == *"no new ancestor"* && "$result" == *"super-secret-password"* ]]; then
        pass "[$shell] 'dse up' correctly skips already-loaded ancestors"
    else
        fail "[$shell] 'dse up' skip-already-loaded failed, got: $result"
    fi
}

test_dse_up_no_ancestors() {
    local shell="$1"
    log "[$shell] Testing 'dse up' graceful when no ancestor .secenv exists..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_up_none"
    mkdir -p "$test_dir/project/src"

    local config_dir="$TEMP_DIR/config_dse_up_none"
    mkdir -p "$config_dir"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project/src'
            _dotsecenv_chpwd_hook
            dse up '$test_dir'
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project/src'
            dse up '$test_dir'
        " 2>&1)
    fi

    if [[ "$result" == *"no new ancestor .secenv files found"* ]]; then
        pass "[$shell] 'dse up' gracefully reports no ancestors"
    else
        fail "[$shell] 'dse up' no-ancestors failed, got: $result"
    fi
}

# ============================================================================
# dse reload Tests
# ============================================================================

test_dse_reload_refreshes_values() {
    local shell="$1"
    log "[$shell] Testing 'dse reload' refreshes secret values..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_reload_refresh"
    mkdir -p "$test_dir/project"

    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
APP_NAME=original
EOF
    chmod 644 "$test_dir/project/.secenv"

    # Create a mock that changes its return value based on a flag file
    local mock_dir="$TEMP_DIR/mock_bin_reload"
    mkdir -p "$mock_dir"
    cat >"$mock_dir/dotsecenv" <<MOCK_EOF
#!/usr/bin/env bash
if [[ "\$1" == "secret" && "\$2" == "get" ]]; then
    if [[ -f "$test_dir/updated_flag" ]]; then
        case "\$3" in
            "DB_PASSWORD") echo "new-secret-password" ;;
            *) exit 1 ;;
        esac
    else
        case "\$3" in
            "DB_PASSWORD") echo "old-secret-password" ;;
            *) exit 1 ;;
        esac
    fi
else
    exit 1
fi
MOCK_EOF
    chmod +x "$mock_dir/dotsecenv"

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$("$BASH_BIN" -c "
            export PATH='$mock_dir:$PATH'
            export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config_reload'
            mkdir -p '$TEMP_DIR/config_reload'
            echo '$test_dir/project' > '$TEMP_DIR/config_reload/trusted_dirs'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            local before_secret=\"\$DB_PASSWORD\"
            local before_plain=\"\$APP_NAME\"
            # Simulate vault update
            touch '$test_dir/updated_flag'
            # Also update the plain value
            echo 'DB_PASSWORD={dotsecenv}' > '$test_dir/project/.secenv'
            echo 'APP_NAME=updated' >> '$test_dir/project/.secenv'
            dse reload
            echo \"before_secret=\$before_secret|after_secret=\$DB_PASSWORD|before_plain=\$before_plain|after_plain=\$APP_NAME\"
        " 2>/dev/null)
    else
        result=$(zsh -i -f -c "
            export PATH='$mock_dir:$PATH'
            export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config_reload'
            mkdir -p '$TEMP_DIR/config_reload'
            echo '$test_dir/project' > '$TEMP_DIR/config_reload/trusted_dirs'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            local before_secret=\"\$DB_PASSWORD\"
            local before_plain=\"\$APP_NAME\"
            # Simulate vault update
            touch '$test_dir/updated_flag'
            # Also update the plain value
            echo 'DB_PASSWORD={dotsecenv}' > '$test_dir/project/.secenv'
            echo 'APP_NAME=updated' >> '$test_dir/project/.secenv'
            dse reload
            echo \"before_secret=\$before_secret|after_secret=\$DB_PASSWORD|before_plain=\$before_plain|after_plain=\$APP_NAME\"
        " 2>/dev/null)
    fi

    rm -f "$test_dir/updated_flag"

    if [[ "$result" == *"after_secret=new-secret-password"* && "$result" == *"after_plain=updated"* ]]; then
        pass "[$shell] 'dse reload' refreshes both secret and plain values"
    else
        fail "[$shell] 'dse reload' refresh failed, got: $result"
    fi
}

test_dse_reload_clears_and_reloads_stack() {
    local shell="$1"
    log "[$shell] Testing 'dse reload' clears and reloads nested stack..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_dse_reload_stack"
    mkdir -p "$test_dir/root/project"

    cat >"$test_dir/root/.secenv" <<'EOF'
APP_ENV=production
EOF
    chmod 644 "$test_dir/root/.secenv"

    cat >"$test_dir/root/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/root/project/.secenv"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$("$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config_reload_stack'
            mkdir -p '$TEMP_DIR/config_reload_stack'
            echo '$test_dir/root' > '$TEMP_DIR/config_reload_stack/trusted_dirs'
            echo '$test_dir/root/project' >> '$TEMP_DIR/config_reload_stack/trusted_dirs'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/root'
            _dotsecenv_chpwd_hook
            cd '$test_dir/root/project'
            _dotsecenv_chpwd_hook
            # Both should be loaded now
            local before_env=\"\$APP_ENV\"
            local before_pw=\"\$DB_PASSWORD\"
            # Run reload from the nested dir
            dse reload
            echo \"before_env=\$before_env|after_env=\$APP_ENV|before_pw=\$before_pw|after_pw=\$DB_PASSWORD|stack=\${_DOTSECENV_SOURCE_STACK[*]}\"
        " 2>/dev/null)
    else
        result=$(zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            export DOTSECENV_CONFIG_DIR='$TEMP_DIR/config_reload_stack'
            mkdir -p '$TEMP_DIR/config_reload_stack'
            echo '$test_dir/root' > '$TEMP_DIR/config_reload_stack/trusted_dirs'
            echo '$test_dir/root/project' >> '$TEMP_DIR/config_reload_stack/trusted_dirs'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/root'
            cd '$test_dir/root/project'
            local before_env=\"\$APP_ENV\"
            local before_pw=\"\$DB_PASSWORD\"
            dse reload
            echo \"before_env=\$before_env|after_env=\$APP_ENV|before_pw=\$before_pw|after_pw=\$DB_PASSWORD|stack=\${_DOTSECENV_SOURCE_STACK[*]}\"
        " 2>/dev/null)
    fi

    if [[ "$result" == *"after_env=production"* && "$result" == *"after_pw=super-secret-password"* ]]; then
        pass "[$shell] 'dse reload' reloads entire nested stack"
    else
        fail "[$shell] 'dse reload' nested stack reload failed, got: $result"
    fi
}

# ============================================================================
# Trailing-whitespace / CRLF parsing tests (FIX B)
# ============================================================================

# Helper: parse one line in a subshell and echo TYPE|VALUE
_parse_one() {
    local shell="$1"
    local line="$2"
    if [[ "$shell" == "bash" ]]; then
        "$BASH_BIN" -c "
            source '$SHELL_DIR/_dotsecenv_core.sh'
            _dotsecenv_parse_line \"\$1\"
            echo \"\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        " _ "$line" 2>&1
    else
        zsh -i -f -c "
            source '$SHELL_DIR/_dotsecenv_core.sh'
            _dotsecenv_parse_line \"\$1\"
            echo \"\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        " _ "$line" 2>&1
    fi
}

test_parse_trailing_whitespace_secret() {
    local shell="$1"
    log "[$shell] Testing {dotsecenv*} with trailing whitespace resolves as secret..."
    ((TESTS_RUN++)) || true

    local ok=1
    local r
    # {dotsecenv} forms
    r=$(_parse_one "$shell" "DB_PASSWORD={dotsecenv} ")
    [[ "$r" == "secret_same|DB_PASSWORD" ]] || ok=0
    # {dotsecenv/} empty-name forms
    r=$(_parse_one "$shell" "CLOUDFLARE_API_TOKEN={dotsecenv/}")
    [[ "$r" == "secret_same|CLOUDFLARE_API_TOKEN" ]] || ok=0
    r=$(_parse_one "$shell" "CLOUDFLARE_API_TOKEN={dotsecenv/} ")
    [[ "$r" == "secret_same|CLOUDFLARE_API_TOKEN" ]] || ok=0
    # CRLF on empty-name form
    r=$(_parse_one "$shell" $'CLOUDFLARE_API_TOKEN={dotsecenv/}\r')
    [[ "$r" == "secret_same|CLOUDFLARE_API_TOKEN" ]] || ok=0
    # {dotsecenv/name} forms
    r=$(_parse_one "$shell" "MY_VAR={dotsecenv/API_KEY} ")
    [[ "$r" == "secret_named|API_KEY" ]] || ok=0
    r=$(_parse_one "$shell" $'MY_VAR={dotsecenv/API_KEY}\r')
    [[ "$r" == "secret_named|API_KEY" ]] || ok=0

    if [[ $ok -eq 1 ]]; then
        pass "[$shell] Trailing whitespace/CR forms resolve as secrets (not literal)"
    else
        fail "[$shell] Trailing whitespace/CR mis-parsed, last got: $r"
    fi
}

test_load_crlf_empty_name_resolves() {
    local shell="$1"
    log "[$shell] Testing end-to-end CRLF {dotsecenv/} loads resolved secret..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_crlf_empty"
    mkdir -p "$test_dir"
    # API_KEY={dotsecenv/} with a real CRLF line ending
    printf 'API_KEY={dotsecenv/}\r\n' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"\$API_KEY\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo \"\$API_KEY\"
        " 2>&1)
    fi

    if [[ "$result" == *"mock-api-key-12345"* && "$result" != *"{dotsecenv/}"* ]]; then
        pass "[$shell] CRLF {dotsecenv/} resolved to secret value"
    else
        fail "[$shell] CRLF {dotsecenv/} not resolved, got: $result"
    fi
}

# ============================================================================
# Reload / new-key detection tests (FIX A)
# ============================================================================

test_sync_new_key_always_trusted() {
    local shell="$1"
    log "[$shell] Testing new key auto-loads in always-trusted dir (no prompt)..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_sync_always"
    mkdir -p "$test_dir/src"

    cat >"$test_dir/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config_sync_always"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    # Enter dir, append a new key, then trigger the same-dir PHASE 2 sync by
    # going into a subdir and back (works in both bash and zsh).
    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
            cd '$test_dir/src'
            _dotsecenv_chpwd_hook
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
            cd '$test_dir/src'
            cd '$test_dir'
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    fi

    if [[ "$result" == *"DB=super-secret-password|API=mock-api-key-12345"* && "$result" != *"Load secrets"* ]]; then
        pass "[$shell] Always-trusted new key auto-loaded without prompt"
    else
        fail "[$shell] Always-trusted new key not auto-loaded, got: $result"
    fi
}

test_sync_no_new_keys_noop() {
    local shell="$1"
    log "[$shell] Testing no new keys means no prompt and no spurious load line..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_sync_noop"
    mkdir -p "$test_dir/src"

    cat >"$test_dir/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config_sync_noop"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    # Enter, then trigger same-dir sync repeatedly with NO file change.
    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            cd '$test_dir/src'; _dotsecenv_chpwd_hook
            cd '$test_dir'; _dotsecenv_chpwd_hook
            cd '$test_dir/src'; _dotsecenv_chpwd_hook
            cd '$test_dir'; _dotsecenv_chpwd_hook
            echo MARKER
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            cd '$test_dir/src'
            cd '$test_dir'
            cd '$test_dir/src'
            cd '$test_dir'
            echo MARKER
        " 2>&1)
    fi

    if [[ "$result" != *"new key(s)"* && "$result" != *"Load secrets"* && "$result" == *"MARKER"* ]]; then
        pass "[$shell] No-op sync produces no prompt and no load-spam"
    else
        fail "[$shell] No-op sync produced unexpected output, got: $result"
    fi
}

test_sync_new_key_unload_integrity() {
    local shell="$1"
    log "[$shell] Testing synced new key is tracked and unloads on leaving tree..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_sync_unload"
    mkdir -p "$test_dir/project/src"
    mkdir -p "$test_dir/other"

    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    local config_dir="$TEMP_DIR/config_sync_unload"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
            cd '$test_dir/project/src'; _dotsecenv_chpwd_hook
            cd '$test_dir/project'; _dotsecenv_chpwd_hook
            cd '$test_dir/other'; _dotsecenv_chpwd_hook
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
            cd '$test_dir/project/src'
            cd '$test_dir/project'
            cd '$test_dir/other'
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    fi

    if [[ "$result" == *"DB=unset|API=unset"* ]]; then
        pass "[$shell] Synced key tracked and unloaded on leave"
    else
        fail "[$shell] Synced key leaked on leave, got: $result"
    fi
}

test_reload_ingests_new_key() {
    local shell="$1"
    log "[$shell] Testing 'dse reload' ingests a key added to an already-loaded dir..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_reload_newkey"
    mkdir -p "$test_dir/project"

    cat >"$test_dir/project/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/project/.secenv"

    local config_dir="$TEMP_DIR/config_reload_newkey"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir/project'
            _dotsecenv_chpwd_hook
            echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
            dse reload
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
            dse reload
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    fi

    if [[ "$result" == *"DB=super-secret-password|API=mock-api-key-12345"* ]]; then
        pass "[$shell] 'dse reload' ingests newly-added key"
    else
        fail "[$shell] 'dse reload' did not ingest new key, got: $result"
    fi
}

test_sync_new_key_not_always_trusted_no_autoload() {
    local shell="$1"
    log "[$shell] Testing new key in a NOT-always-trusted dir does not silently auto-load..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_sync_session"
    mkdir -p "$test_dir/src"

    cat >"$test_dir/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    # NOT in the persistent trusted_dirs file: session-trust the dir at runtime
    # via the session array, so the first load succeeds but the dir is not
    # always-trusted. A new key must NOT auto-load; without a TTY the sync
    # re-prompt is skipped (no-TTY guard), so the key stays unloaded.
    local config_dir="$TEMP_DIR/config_sync_session"
    mkdir -p "$config_dir"
    : >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            _dotsecenv_trust_session '$test_dir'
            cd '$test_dir'
            _dotsecenv_chpwd_hook
            echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
            _dotsecenv_sync_new_keys '$test_dir' </dev/null
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -i -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            _dotsecenv_trust_session '$test_dir'
            cd '$test_dir'
            echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
            _dotsecenv_sync_new_keys '$test_dir' </dev/null
            echo \"DB=\${DB_PASSWORD:-unset}|API=\${API_KEY:-unset}\"
        " 2>&1)
    fi

    # Original DB_PASSWORD stays loaded; the new API_KEY is NOT silently added.
    if [[ "$result" == *"DB=super-secret-password|API=unset"* ]]; then
        pass "[$shell] New key in session-trusted dir is not silently auto-loaded"
    else
        fail "[$shell] Session-trusted new-key handling wrong, got: $result"
    fi
}

test_bash_cd_dot_asymmetry() {
    local shell="$1"
    # Only meaningful for bash (PROMPT_COMMAND gated on PWD change).
    [[ "$shell" == "bash" ]] || return 0
    log "[$shell] Testing bash hook does not pick up on unchanged PWD, reload does..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_bash_asym"
    mkdir -p "$test_dir"

    cat >"$test_dir/.secenv" <<'EOF'
DB_PASSWORD={dotsecenv}
EOF
    chmod 644 "$test_dir/.secenv"

    local config_dir="$TEMP_DIR/config_bash_asym"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
        export PATH='$mock_path:$PATH'
        source '$SHELL_DIR/_dotsecenv_core.sh'
        source '$SHELL_DIR/dotsecenv.plugin.bash'
        cd '$test_dir'
        _dotsecenv_prompt_hook
        echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
        _dotsecenv_prompt_hook
        echo \"AFTER_HOOK=\${API_KEY:-unset}\"
        dse reload
        echo \"AFTER_RELOAD=\${API_KEY:-unset}\"
    " 2>&1)

    if [[ "$result" == *"AFTER_HOOK=unset"* && "$result" == *"AFTER_RELOAD=mock-api-key-12345"* ]]; then
        pass "[$shell] bash unchanged-PWD hook is a no-op; reload ingests"
    else
        fail "[$shell] bash cd-dot asymmetry wrong, got: $result"
    fi
}

# Regression: a NON-interactive shell (editor/script that captures output) must
# emit nothing when the plugin is sourced and a directory with an untrusted
# .secenv is entered. See dotsecenv/plugin#29. Note this test deliberately does
# NOT pass -i (zsh) or call the hook explicitly (bash): it exercises the real
# non-interactive path.
test_noninteractive_silent() {
    local shell="$1"
    log "[$shell] Testing non-interactive shell stays silent (plugin#29)..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_noninteractive_$shell"
    mkdir -p "$test_dir"
    echo 'FOO=bar' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    # Fresh config dir with no trusted_dirs -> the dir is untrusted. In an
    # interactive shell this path prints "skipping ... no TTY for trust prompt";
    # a non-interactive shell must stay silent so captured output isn't corrupted.
    local config_dir="$TEMP_DIR/config_noninteractive_$shell"
    mkdir -p "$config_dir"

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" "$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            source '$SHELL_DIR/dotsecenv.plugin.bash'
            cd '$test_dir'
            echo MARKER
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -f -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir'
            echo MARKER
        " 2>&1)
    fi

    if [[ "$result" == "MARKER" ]]; then
        pass "[$shell] Non-interactive shell emits no dotsecenv output"
    else
        fail "[$shell] Non-interactive shell leaked output, got: $result"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo "=================================================="
    echo "dotsecenv Shell Plugin E2E Tests"
    echo "=================================================="
    echo ""

    # Check prerequisites
    if [[ ! -f "$SHELL_DIR/_dotsecenv_core.sh" ]]; then
        echo "Error: Shell plugins not found at $SHELL_DIR"
        exit 1
    fi

    setup_temp_dir

    # Run bash tests
    if [[ $TEST_BASH -eq 1 ]]; then
        echo ""
        log "Running Bash tests using: $BASH_BIN"
        log "Bash version: $("$BASH_BIN" --version | head -1)"
        echo ""

        test_parse_plain_secenv "bash"
        test_parse_secret_same_name "bash"
        test_parse_secret_named "bash"
        test_missing_secret_warning "bash"
        test_missing_secret_error_deduped "bash"
        test_security_check_world_writable "bash"
        test_two_phase_loading "bash"
        test_load_unload_message_split "bash"
        test_empty_secenv_no_message "bash"
        test_alias_dse "bash"
        test_alias_dse_get "bash"
        test_comments_and_empty_lines "bash"
        test_quoted_values "bash"
        test_tree_scope_persist_in_subdir "bash"
        test_tree_scope_unload_on_leave "bash"
        test_tree_scope_nested_secenv "bash"
        test_tree_scope_sibling_navigation "bash"
        test_tree_scope_no_reload_from_subdir "bash"
        test_multiline_warning "bash"
        test_dse_up_basic "bash"
        test_dse_up_multiple_ancestors "bash"
        test_dse_up_skips_already_loaded "bash"
        test_dse_up_no_ancestors "bash"
        test_dse_reload_refreshes_values "bash"
        test_dse_reload_clears_and_reloads_stack "bash"
        test_parse_trailing_whitespace_secret "bash"
        test_load_crlf_empty_name_resolves "bash"
        test_sync_new_key_always_trusted "bash"
        test_sync_no_new_keys_noop "bash"
        test_sync_new_key_unload_integrity "bash"
        test_reload_ingests_new_key "bash"
        test_sync_new_key_not_always_trusted_no_autoload "bash"
        test_noninteractive_silent "bash"
        test_bash_cd_dot_asymmetry "bash"
    fi

    # Run zsh tests
    if [[ $TEST_ZSH -eq 1 ]]; then
        if command -v zsh &>/dev/null; then
            echo ""
            log "Running Zsh tests..."
            echo ""

            test_parse_plain_secenv "zsh"
            test_parse_secret_same_name "zsh"
            test_parse_secret_named "zsh"
            test_missing_secret_warning "zsh"
            test_missing_secret_error_deduped "zsh"
            test_security_check_world_writable "zsh"
            test_two_phase_loading "zsh"
            test_load_unload_message_split "zsh"
            test_empty_secenv_no_message "zsh"
            test_alias_dse "zsh"
            test_alias_dse_get "zsh"
            test_comments_and_empty_lines "zsh"
            test_quoted_values "zsh"
            test_tree_scope_persist_in_subdir "zsh"
            test_tree_scope_unload_on_leave "zsh"
            test_tree_scope_nested_secenv "zsh"
            test_tree_scope_sibling_navigation "zsh"
            test_tree_scope_no_reload_from_subdir "zsh"
            test_multiline_warning "zsh"
            test_dse_up_basic "zsh"
            test_dse_up_multiple_ancestors "zsh"
            test_dse_up_skips_already_loaded "zsh"
            test_dse_up_no_ancestors "zsh"
            test_dse_reload_refreshes_values "zsh"
            test_dse_reload_clears_and_reloads_stack "zsh"
            test_parse_trailing_whitespace_secret "zsh"
            test_load_crlf_empty_name_resolves "zsh"
            test_sync_new_key_always_trusted "zsh"
            test_sync_no_new_keys_noop "zsh"
            test_sync_new_key_unload_integrity "zsh"
            test_reload_ingests_new_key "zsh"
            test_sync_new_key_not_always_trusted_no_autoload "zsh"
            test_noninteractive_silent "zsh"
        else
            warn "Zsh not found, skipping zsh tests"
        fi
    fi

    # Summary
    echo ""
    echo "=================================================="
    echo "Test Results"
    echo "=================================================="
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    fi
}

main "$@"

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
    zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(zsh -c "
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

test_alias_secret() {
    local shell="$1"
    log "[$shell] Testing 'secret' alias..."
    ((TESTS_RUN++)) || true

    local mock_path
    mock_path=$(create_mock_dotsecenv)

    local result
    if [[ "$shell" == "bash" ]]; then
        result=$("$BASH_BIN" -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/_dotsecenv_core.sh'
            secret API_KEY
        " 2>&1)
    else
        result=$(zsh -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            secret API_KEY
        " 2>&1)
    fi

    if [[ "$result" == "mock-api-key-12345" ]]; then
        pass "[$shell] 'secret' alias works correctly"
    else
        fail "[$shell] 'secret' alias failed, got: $result"
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
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

test_tree_scope_reload_on_return() {
    local shell="$1"
    log "[$shell] Testing secrets reload when returning to source dir..."
    ((TESTS_RUN++)) || true

    local test_dir="$TEMP_DIR/test_tree_reload"
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
            _dotsecenv_chpwd_hook 2>&1
        " 2>&1)
    else
        result=$(DOTSECENV_CONFIG_DIR="$config_dir" DOTSECENV_TRUSTED_DIRS_FILE="$config_dir/trusted_dirs" zsh -c "
            export PATH='$mock_path:$PATH'
            source '$SHELL_DIR/dotsecenv.plugin.zsh'
            cd '$test_dir/project'
            cd '$test_dir/project/src'
            cd '$test_dir/project' 2>&1
        " 2>&1)
    fi

    # Should see "loaded" message when returning (reloading)
    if [[ "$result" == *"loaded"*"secret"* ]]; then
        pass "[$shell] Secrets reload when returning to source dir"
    else
        fail "[$shell] Secrets did not reload on return, got: $result"
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
        test_security_check_world_writable "bash"
        test_two_phase_loading "bash"
        test_alias_dse "bash"
        test_alias_secret "bash"
        test_comments_and_empty_lines "bash"
        test_quoted_values "bash"
        test_tree_scope_persist_in_subdir "bash"
        test_tree_scope_unload_on_leave "bash"
        test_tree_scope_nested_secenv "bash"
        test_tree_scope_sibling_navigation "bash"
        test_tree_scope_reload_on_return "bash"
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
            test_security_check_world_writable "zsh"
            test_two_phase_loading "zsh"
            test_alias_dse "zsh"
            test_alias_secret "zsh"
            test_comments_and_empty_lines "zsh"
            test_quoted_values "zsh"
            test_tree_scope_persist_in_subdir "zsh"
            test_tree_scope_unload_on_leave "zsh"
            test_tree_scope_nested_secenv "zsh"
            test_tree_scope_sibling_navigation "zsh"
            test_tree_scope_reload_on_return "zsh"
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

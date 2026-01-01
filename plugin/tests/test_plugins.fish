#!/usr/bin/env fish
# E2E tests for dotsecenv fish shell plugin
#
# Usage:
#   fish ./tests/shell/test_plugins.fish [--verbose]

# Configuration
set SCRIPT_DIR (dirname (status -f))
set PROJECT_ROOT (realpath "$SCRIPT_DIR/../..")
set SHELL_DIR "$PROJECT_ROOT/plugin"
set BIN_DIR "$PROJECT_ROOT/bin"

# Colors
set RED '\033[0;31m'
set GREEN '\033[0;32m'
set YELLOW '\033[0;33m'
set BLUE '\033[0;34m'
set NC '\033[0m'

# Counters
set -g TESTS_RUN 0
set -g TESTS_PASSED 0
set -g TESTS_FAILED 0

# Options
set -g VERBOSE 0

# Parse arguments
for arg in $argv
    switch $arg
        case --verbose
            set VERBOSE 1
    end
end

# Logging functions
function log
    echo -e "$BLUE"'[TEST]'"$NC $argv"
end

function pass
    echo -e "$GREEN"'[PASS]'"$NC $argv"
    set TESTS_PASSED (math $TESTS_PASSED + 1)
end

function fail
    echo -e "$RED"'[FAIL]'"$NC $argv"
    set TESTS_FAILED (math $TESTS_FAILED + 1)
end

function warn
    echo -e "$YELLOW"'[WARN]'"$NC $argv"
end

function debug
    if test $VERBOSE -eq 1
        echo "[DEBUG] $argv"
    end
end

# Create temporary directory
set -g TEMP_DIR ""

function setup_temp_dir
    set -g TEMP_DIR (mktemp -d)
    debug "Created temp directory: $TEMP_DIR"
end

function cleanup
    if test -n "$TEMP_DIR"; and test -d "$TEMP_DIR"
        rm -rf "$TEMP_DIR"
    end
end

# Create mock dotsecenv CLI
function create_mock_dotsecenv
    set mock_dir "$TEMP_DIR/mock_bin"
    mkdir -p "$mock_dir"

    echo '#!/usr/bin/env bash
if [[ "$1" == "secret" && "$2" == "get" ]]; then
    case "$3" in
        "DB_PASSWORD") echo "super-secret-password" ;;
        "API_KEY") echo "mock-api-key-12345" ;;
        "PROD_SECRET") echo "production-secret-value" ;;
        "MISSING_SECRET") exit 1 ;;
        *) exit 1 ;;
    esac
else
    exit 1
fi' >"$mock_dir/dotsecenv"
    chmod +x "$mock_dir/dotsecenv"
    echo $mock_dir
end

# ============================================================================
# Test Functions
# ============================================================================

function test_parse_plain_env
    log "[fish] Testing plain .env parsing..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_plain_env"
    mkdir -p "$test_dir"

    echo 'DATABASE_HOST=localhost
DATABASE_PORT=5432
APP_NAME="My Application"' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    # Run fish with the plugin loaded
    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DATABASE_HOST|\$DATABASE_PORT|\$APP_NAME\"
    " 2>&1)

    if test "$result" = "localhost|5432|My Application"
        pass "[fish] Plain .env parsing works correctly"
    else
        fail "[fish] Plain .env parsing failed, got: $result"
    end
end

function test_parse_secret_same_name
    log "[fish] Testing {dotsecenv} secret (same name)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_secret_same"
    mkdir -p "$test_dir"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \$DB_PASSWORD
    " 2>&1)

    if test "$result" = super-secret-password
        pass "[fish] {dotsecenv} secret resolution works correctly"
    else
        fail "[fish] {dotsecenv} secret resolution failed, got: $result"
    end
end

function test_parse_secret_named
    log "[fish] Testing {dotsecenv/name} secret (named)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_secret_named"
    mkdir -p "$test_dir"

    echo 'MY_API_KEY={dotsecenv/API_KEY}' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \$MY_API_KEY
    " 2>&1)

    if test "$result" = mock-api-key-12345
        pass "[fish] {dotsecenv/name} secret resolution works correctly"
    else
        fail "[fish] {dotsecenv/name} secret resolution failed, got: $result"
    end
end

function test_missing_secret_warning
    log "[fish] Testing missing secret error..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_missing_secret"
    mkdir -p "$test_dir"

    echo 'MISSING_SECRET={dotsecenv}' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"VAR=\$MISSING_SECRET\"
    " 2>&1)

    if string match -q "*error*" "$result"; and string match -q "*fetching secret*" "$result"
        pass "[fish] Missing secret error displayed correctly"
    else
        fail "[fish] Missing secret error not displayed, got: $result"
    end
end

function test_security_check_world_writable
    log "[fish] Testing security check (world-writable)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_security"
    mkdir -p "$test_dir"

    echo 'UNSAFE_VAR=should-not-load' >"$test_dir/.env"
    chmod 666 "$test_dir/.env" # World-writable

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"VAR=\"(test -n \"\$UNSAFE_VAR\"; and echo \$UNSAFE_VAR; or echo 'unset')
    " 2>&1)

    if string match -q "*refusing*" "$result"; and string match -q "*world-writable*" "$result"
        pass "[fish] World-writable file rejected correctly"
    else
        fail "[fish] World-writable file not rejected, got: $result"
    end
end

function test_two_phase_loading
    log "[fish] Testing two-phase loading..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_two_phase"
    mkdir -p "$test_dir"

    echo 'PLAIN_VAR=plain-value
SECRET_VAR={dotsecenv/API_KEY}' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$PLAIN_VAR|\$SECRET_VAR\"
    " 2>&1)

    if test "$result" = "plain-value|mock-api-key-12345"
        pass "[fish] Two-phase loading works correctly"
    else
        fail "[fish] Two-phase loading failed, got: $result"
    end
end

function test_alias_dse
    log "[fish] Testing 'dse' function..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        type dse
    " 2>&1)

    if string match -q "*function*" "$result"
        pass "[fish] 'dse' function is defined"
    else
        fail "[fish] 'dse' function not defined, got: $result"
    end
end

function test_alias_secret
    log "[fish] Testing 'secret' function..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        secret API_KEY
    " 2>&1)

    if test "$result" = mock-api-key-12345
        pass "[fish] 'secret' function works correctly"
    else
        fail "[fish] 'secret' function failed, got: $result"
    end
end

function test_comments_and_empty_lines
    log "[fish] Testing comments and empty lines handling..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_comments"
    mkdir -p "$test_dir"

    echo '# This is a comment
DATABASE_HOST=localhost

# Another comment
DATABASE_PORT=5432
' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DATABASE_HOST|\$DATABASE_PORT\"
    " 2>&1)

    if test "$result" = "localhost|5432"
        pass "[fish] Comments and empty lines handled correctly"
    else
        fail "[fish] Comments/empty lines handling failed, got: $result"
    end
end

function test_quoted_values
    log "[fish] Testing quoted values..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_quotes"
    mkdir -p "$test_dir"

    echo 'DOUBLE_QUOTED="hello world"
SINGLE_QUOTED='"'"'hello world'"'"'
UNQUOTED=helloworld' >"$test_dir/.env"
    chmod 644 "$test_dir/.env"

    set mock_path (create_mock_dotsecenv)

    set result (fish -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DOUBLE_QUOTED|\$SINGLE_QUOTED|\$UNQUOTED\"
    " 2>&1)

    if test "$result" = "hello world|hello world|helloworld"
        pass "[fish] Quoted values parsed correctly"
    else
        fail "[fish] Quoted values parsing failed, got: $result"
    end
end

# ============================================================================
# Main
# ============================================================================

function main
    echo ""
    echo "=================================================="
    echo "dotsecenv Fish Shell Plugin E2E Tests"
    echo "=================================================="
    echo ""

    # Check prerequisites
    if not test -f "$SHELL_DIR/conf.d/dotsecenv.fish"
        echo "Error: Fish plugin not found at $SHELL_DIR/conf.d/dotsecenv.fish"
        exit 1
    end

    setup_temp_dir

    echo ""
    log "Running Fish tests..."
    echo ""

    test_parse_plain_env
    test_parse_secret_same_name
    test_parse_secret_named
    test_missing_secret_warning
    test_security_check_world_writable
    test_two_phase_loading
    test_alias_dse
    test_alias_secret
    test_comments_and_empty_lines
    test_quoted_values

    cleanup

    # Summary
    echo ""
    echo "=================================================="
    echo "Test Results"
    echo "=================================================="
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: $GREEN""$TESTS_PASSED""$NC"
    echo -e "Tests failed: $RED""$TESTS_FAILED""$NC"
    echo ""

    if test $TESTS_FAILED -gt 0
        exit 1
    end
end

main $argv

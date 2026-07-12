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

    # Use `printf '%s\n'` rather than `echo`: the mock body contains a literal
    # backslash-n (the MULTILINE_SECRET printf), and fish's `echo` escape
    # handling has varied across versions. `%s` writes the argument verbatim.
    printf '%s\n' '#!/usr/bin/env bash
if [[ "$1" == "secret" && "$2" == "get" ]]; then
    case "$3" in
        "DB_PASSWORD") echo "super-secret-password" ;;
        "API_KEY") echo "mock-api-key-12345" ;;
        "PROD_SECRET") echo "production-secret-value" ;;
        "MISSING_SECRET") exit 1 ;;
        "MULTILINE_SECRET") printf "line1\nline2\nline3" ;;
        *) exit 1 ;;
    esac
else
    exit 1
fi' >"$mock_dir/dotsecenv"
    chmod +x "$mock_dir/dotsecenv"
    echo $mock_dir
end

# Regression: a NON-interactive fish (`fish -c`, as used by editors like Emacs
# and by scripts/CI) must emit nothing when conf.d loads and a directory with an
# untrusted .secenv is entered. See dotsecenv/plugin#29. Note this test does NOT
# pass -i: it exercises the real non-interactive path that the bug reported.
function test_noninteractive_silent
    log "[fish] Testing non-interactive shell stays silent (plugin#29)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_noninteractive"
    mkdir -p "$test_dir"
    echo 'FOO=bar' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    # No trusted_dirs -> untrusted. Interactively this prints "skipping ... no
    # TTY for trust prompt"; non-interactively it must stay silent.
    set result (fish --no-config -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config-noninteractive'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        echo MARKER
    " 2>&1)

    if test "$result" = MARKER
        pass "[fish] Non-interactive shell emits no dotsecenv output"
    else
        fail "[fish] Non-interactive shell leaked output, got: $result"
    end
end

# ============================================================================
# Test Functions
# ============================================================================

function test_parse_plain_env
    log "[fish] Testing plain .secenv parsing..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_plain_env"
    mkdir -p "$test_dir"

    echo 'DATABASE_HOST=localhost
DATABASE_PORT=5432
APP_NAME="My Application"' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    # Run fish with the plugin loaded
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DATABASE_HOST|\$DATABASE_PORT|\$APP_NAME\"
    " 2>&1)

    if string match -q "*localhost|5432|My Application*" "$result"
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

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \$DB_PASSWORD
    " 2>&1)

    if string match -q "*super-secret-password*" "$result"
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

    echo 'MY_API_KEY={dotsecenv/API_KEY}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \$MY_API_KEY
    " 2>&1)

    if string match -q "*mock-api-key-12345*" "$result"
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

    echo 'MISSING_SECRET={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
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

function test_missing_secret_error_deduped
    log "[fish] Testing missing secret error printed once for multiple keys..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_missing_secret_dedupe"
    mkdir -p "$test_dir"

    # Two keys mapping to the same missing secret
    printf 'MISSING_SECRET={dotsecenv}\nTF_VAR_MISSING={dotsecenv/MISSING_SECRET}\n' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        # cd alone triggers the --on-variable PWD hook; calling _dotsecenv_on_cd
        # as well would run a second load and defeat the single-error assertion
        cd '$test_dir'
    " 2>&1)

    set error_count (printf '%s\n' $result | grep -c "error fetching secret 'MISSING_SECRET'")

    if test "$error_count" = 1; and string match -q "*TF_VAR_MISSING not set (secret 'MISSING_SECRET' failed above)*" "$result"
        pass "[fish] Missing secret error printed once, second key got a short notice"
    else
        fail "[fish] Expected 1 full error and a short notice, got ($error_count errors): $result"
    end
end

function test_security_check_world_writable
    log "[fish] Testing security check (world-writable)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_security"
    mkdir -p "$test_dir"

    echo 'UNSAFE_VAR=should-not-load' >"$test_dir/.secenv"
    chmod 666 "$test_dir/.secenv" # World-writable

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
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
SECRET_VAR={dotsecenv/API_KEY}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$PLAIN_VAR|\$SECRET_VAR\"
    " 2>&1)

    if string match -q "*plain-value|mock-api-key-12345*" "$result"
        pass "[fish] Two-phase loading works correctly"
    else
        fail "[fish] Two-phase loading failed, got: $result"
    end
end

function test_load_unload_message_split
    log "[fish] Testing env var(s)/secret(s) messages split on load and unload..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_msg_split/project"
    mkdir -p "$test_dir"
    mkdir -p "$TEMP_DIR/test_msg_split/other"

    echo 'APP_ENV=production
NODE_ENV=staging
DB_URL={dotsecenv/DB_PASSWORD}
SVC_KEY={dotsecenv/API_KEY}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config_msg_split"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        cd '$TEMP_DIR/test_msg_split/other'
    " 2>&1)

    set -l ok 1
    string match -q "*loaded 2 env var(s) from .secenv: APP_ENV, NODE_ENV*" "$result"; or set ok 0
    string match -q "*loaded 2 secret(s) from .secenv: DB_URL, SVC_KEY*" "$result"; or set ok 0
    string match -q "*unloaded 2 env var(s): APP_ENV, NODE_ENV*" "$result"; or set ok 0
    string match -q "*unloaded 2 secret(s): DB_URL, SVC_KEY*" "$result"; or set ok 0

    if test $ok -eq 1
        pass "[fish] Plain vars and secrets reported on separate lines"
    else
        fail "[fish] Message split incorrect, got: $result"
    end
end

function test_empty_secenv_no_message
    log "[fish] Testing an empty .secenv produces no load message..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_empty_secenv"
    mkdir -p "$test_dir"
    printf '' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config_empty_secenv"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        echo MARKER
    " 2>&1)

    set -l ok 1
    string match -q "*MARKER*" "$result"; or set ok 0
    string match -q "*loaded*" "$result"; and set ok 0
    string match -q "*env var(s)*" "$result"; and set ok 0
    string match -q "*secret(s)*" "$result"; and set ok 0

    if test $ok -eq 1
        pass "[fish] Empty .secenv produces no load message"
    else
        fail "[fish] Empty .secenv produced unexpected output, got: $result"
    end
end

function test_alias_dse
    log "[fish] Testing 'dse' function..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
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

function test_alias_dse_get
    log "[fish] Testing 'dse get' subcommand..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        dse get API_KEY
    " 2>&1)

    if string match -q "*mock-api-key-12345*" "$result"
        pass "[fish] 'dse get' subcommand works correctly"
    else
        fail "[fish] 'dse get' subcommand failed, got: $result"
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
' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DATABASE_HOST|\$DATABASE_PORT\"
    " 2>&1)

    if string match -q "*localhost|5432*" "$result"
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
UNQUOTED=helloworld' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
        echo '$test_dir' >'$TEMP_DIR/config/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \"\$DOUBLE_QUOTED|\$SINGLE_QUOTED|\$UNQUOTED\"
    " 2>&1)

    if string match -q "*hello world|hello world|helloworld*" "$result"
        pass "[fish] Quoted values parsed correctly"
    else
        fail "[fish] Quoted values parsing failed, got: $result"
    end
end

# ============================================================================
# Tree-Scoped Loading Tests
# ============================================================================

function test_tree_scope_persist_in_subdir
    log "[fish] Testing secrets persist when entering subdirectory..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_tree_persist"
    mkdir -p "$test_dir/parent/child"

    # Parent has .secenv
    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/parent/.secenv"
    chmod 644 "$test_dir/parent/.secenv"

    # Pre-trust the directory
    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/parent'
        cd '$test_dir/parent/child'
        echo \$DB_PASSWORD
    " 2>&1)

    if string match -q "*super-secret-password*" "$result"
        pass "[fish] Secrets persist in subdirectory"
    else
        fail "[fish] Secrets did not persist in subdirectory, got: $result"
    end
end

function test_tree_scope_unload_on_leave
    log "[fish] Testing secrets unload when leaving tree..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_tree_unload"
    mkdir -p "$test_dir/project"
    mkdir -p "$test_dir/other"

    # Project has .secenv
    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    # Pre-trust the directory
    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        cd '$test_dir/other'
        echo 'VAR='(test -n \"\$DB_PASSWORD\"; and echo \$DB_PASSWORD; or echo 'unset')
    " 2>&1)

    if string match -q "*VAR=unset*" "$result"
        pass "[fish] Secrets unloaded when leaving tree"
    else
        fail "[fish] Secrets not unloaded when leaving tree, got: $result"
    end
end

function test_tree_scope_nested_secenv
    log "[fish] Testing nested .secenv layers on top of parent..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_tree_nested"
    mkdir -p "$test_dir/parent/child"

    # Parent has DB_PASSWORD
    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/parent/.secenv"
    chmod 644 "$test_dir/parent/.secenv"

    # Child has API_KEY
    echo 'API_KEY={dotsecenv}' >"$test_dir/parent/child/.secenv"
    chmod 644 "$test_dir/parent/child/.secenv"

    # Pre-trust both directories
    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"
    echo "$test_dir/parent/child" >>"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/parent'
        cd '$test_dir/parent/child'
        echo \$DB_PASSWORD'|'\$API_KEY
    " 2>&1)

    if string match -q "*super-secret-password|mock-api-key-12345*" "$result"
        pass "[fish] Nested .secenv layers correctly"
    else
        fail "[fish] Nested .secenv layering failed, got: $result"
    end
end

function test_tree_scope_sibling_navigation
    log "[fish] Testing sibling navigation keeps ancestor secrets..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_tree_sibling"
    mkdir -p "$test_dir/parent/child1"
    mkdir -p "$test_dir/parent/child2"

    # Parent has .secenv
    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/parent/.secenv"
    chmod 644 "$test_dir/parent/.secenv"

    # Pre-trust the directory
    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/parent" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/parent'
        cd '$test_dir/parent/child1'
        cd '$test_dir/parent/child2'
        echo \$DB_PASSWORD
    " 2>&1)

    if string match -q "*super-secret-password*" "$result"
        pass "[fish] Sibling navigation keeps ancestor secrets"
    else
        fail "[fish] Sibling navigation lost ancestor secrets, got: $result"
    end
end

function test_tree_scope_no_reload_from_subdir
    log "[fish] Testing secrets persist (no reload) when returning from subdirectory..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_tree_no_reload"
    mkdir -p "$test_dir/project/src"

    # Project has .secenv
    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    # Pre-trust the directory
    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        cd '$test_dir/project/src'
        cd '$test_dir/project'
        echo \$DB_PASSWORD
    " 2>&1)

    # Should NOT see unload/reload messages - secrets should persist
    # But should still have the secret value
    if string match -q "*unloaded*" "$result"
        fail "[fish] Secrets were unnecessarily unloaded, got: $result"
    else if string match -q "*super-secret-password*" "$result"
        pass "[fish] Secrets persist without reload when returning from subdirectory"
    else
        fail "[fish] Secret value not found, got: $result"
    end
end

function test_multiline_warning
    log "[fish] Testing multiline value warning..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_multiline"
    mkdir -p "$test_dir"

    echo 'MULTILINE_SECRET={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
    " 2>&1)

    if string match -q "*contains newlines*" "$result"; and string match -q "*string join*" "$result"
        pass "[fish] Multiline value warning displayed correctly"
    else
        fail "[fish] Multiline value warning not displayed, got: $result"
    end
end

# ============================================================================
# dse up Tests
# ============================================================================

function test_dse_up_basic
    log "[fish] Testing 'dse up' loads ancestor .secenv..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_dse_up_basic"
    mkdir -p "$test_dir/project/terraform/modules"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    set config_dir "$TEMP_DIR/config_dse_up_basic"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project/terraform/modules'
        dse up '$test_dir'
        echo \$DB_PASSWORD
    " 2>&1)

    if string match -q "*super-secret-password*" "$result"
        pass "[fish] 'dse up' loads ancestor .secenv correctly"
    else
        fail "[fish] 'dse up' failed to load ancestor .secenv, got: $result"
    end
end

function test_dse_up_multiple_ancestors
    log "[fish] Testing 'dse up' loads multiple ancestor .secenv files..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_dse_up_multi"
    mkdir -p "$test_dir/root/project/src"

    echo 'APP_ENV=production' >"$test_dir/root/.secenv"
    chmod 644 "$test_dir/root/.secenv"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/root/project/.secenv"
    chmod 644 "$test_dir/root/project/.secenv"

    set config_dir "$TEMP_DIR/config_dse_up_multi"
    mkdir -p "$config_dir"
    echo "$test_dir/root" >"$config_dir/trusted_dirs"
    echo "$test_dir/root/project" >>"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/root/project/src'
        dse up '$test_dir'
        echo \$APP_ENV'|'\$DB_PASSWORD
    " 2>&1)

    if string match -q "*production|super-secret-password*" "$result"
        pass "[fish] 'dse up' loads multiple ancestor .secenv files correctly"
    else
        fail "[fish] 'dse up' multi-ancestor failed, got: $result"
    end
end

function test_dse_up_skips_already_loaded
    log "[fish] Testing 'dse up' skips already-loaded ancestors..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_dse_up_skip"
    mkdir -p "$test_dir/project/src"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    set config_dir "$TEMP_DIR/config_dse_up_skip"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        cd '$test_dir/project/src'
        dse up '$test_dir'
        echo \$DB_PASSWORD
    " 2>&1)

    if string match -q "*no new ancestor*" "$result"; and string match -q "*super-secret-password*" "$result"
        pass "[fish] 'dse up' correctly skips already-loaded ancestors"
    else
        fail "[fish] 'dse up' skip-already-loaded failed, got: $result"
    end
end

function test_dse_up_no_ancestors
    log "[fish] Testing 'dse up' graceful when no ancestor .secenv exists..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_dse_up_none"
    mkdir -p "$test_dir/project/src"

    set config_dir "$TEMP_DIR/config_dse_up_none"
    mkdir -p "$config_dir"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project/src'
        dse up '$test_dir'
    " 2>&1)

    if string match -q "*no new ancestor .secenv files found*" "$result"
        pass "[fish] 'dse up' gracefully reports no ancestors"
    else
        fail "[fish] 'dse up' no-ancestors failed, got: $result"
    end
end

# ============================================================================
# Trailing-whitespace / CRLF parsing tests (FIX B)
# ============================================================================

function test_parse_trailing_whitespace_secret
    log "[fish] Testing {dotsecenv*} with trailing whitespace resolves as secret..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set result (fish --no-config -i -c "
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        _dotsecenv_parse_line 'DB_PASSWORD={dotsecenv} '
        echo \"same|\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        _dotsecenv_parse_line 'CLOUDFLARE_API_TOKEN={dotsecenv/}'
        echo \"emptyclean|\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        _dotsecenv_parse_line 'CLOUDFLARE_API_TOKEN={dotsecenv/} '
        echo \"emptyspace|\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        _dotsecenv_parse_line (printf 'CLOUDFLARE_API_TOKEN={dotsecenv/}\r')
        echo \"emptycr|\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
        _dotsecenv_parse_line 'MY_VAR={dotsecenv/API_KEY} '
        echo \"named|\$_DOTSECENV_PARSE_TYPE|\$_DOTSECENV_PARSE_VALUE\"
    " 2>&1)

    if string match -q "*same|secret_same|DB_PASSWORD*" "$result"; and string match -q "*emptyclean|secret_same|CLOUDFLARE_API_TOKEN*" "$result"; and string match -q "*emptyspace|secret_same|CLOUDFLARE_API_TOKEN*" "$result"; and string match -q "*emptycr|secret_same|CLOUDFLARE_API_TOKEN*" "$result"; and string match -q "*named|secret_named|API_KEY*" "$result"
        pass "[fish] Trailing whitespace/CR and empty-name forms resolve as secrets"
    else
        fail "[fish] Trailing whitespace/CR mis-parsed, got: $result"
    end
end

function test_load_crlf_empty_name_resolves
    log "[fish] Testing end-to-end CRLF {dotsecenv/} loads resolved secret..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_crlf_empty"
    mkdir -p "$test_dir"
    printf 'API_KEY={dotsecenv/}\r\n' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config_crlf"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo \$API_KEY
    " 2>&1)

    if string match -q "*mock-api-key-12345*" "$result"; and not string match -q "*{dotsecenv/}*" "$result"
        pass "[fish] CRLF {dotsecenv/} resolved to secret value"
    else
        fail "[fish] CRLF {dotsecenv/} not resolved, got: $result"
    end
end

# ============================================================================
# Reload / new-key detection tests (FIX A)
# ============================================================================

function test_sync_new_key_always_trusted
    log "[fish] Testing new key auto-loads in always-trusted dir (no prompt)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_sync_always"
    mkdir -p "$test_dir"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config_sync_always"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    # Fish only fires its hook on a real PWD change, so use dse reload / direct
    # sync to ingest the newly-appended key.
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        echo 'API_KEY={dotsecenv}' >> '$test_dir/.secenv'
        _dotsecenv_sync_new_keys '$test_dir'
        echo 'DB='\$DB_PASSWORD'|API='\$API_KEY
    " 2>&1)

    if string match -q "*DB=super-secret-password|API=mock-api-key-12345*" "$result"; and not string match -q "*Load secrets*" "$result"
        pass "[fish] Always-trusted new key auto-loaded without prompt"
    else
        fail "[fish] Always-trusted new key not auto-loaded, got: $result"
    end
end

function test_sync_no_new_keys_noop
    log "[fish] Testing no new keys means no prompt and no spurious load line..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_sync_noop"
    mkdir -p "$test_dir"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set config_dir "$TEMP_DIR/config_sync_noop"
    mkdir -p "$config_dir"
    echo "$test_dir" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
        _dotsecenv_sync_new_keys '$test_dir'
        _dotsecenv_sync_new_keys '$test_dir'
        echo MARKER
    " 2>&1)

    if not string match -q "*new key(s)*" "$result"; and not string match -q "*Load secrets*" "$result"; and string match -q "*MARKER*" "$result"
        pass "[fish] No-op sync produces no prompt and no load-spam"
    else
        fail "[fish] No-op sync produced unexpected output, got: $result"
    end
end

function test_sync_new_key_unload_integrity
    log "[fish] Testing synced new key is tracked and unloads on leaving tree..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_sync_unload"
    mkdir -p "$test_dir/project"
    mkdir -p "$test_dir/other"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    set config_dir "$TEMP_DIR/config_sync_unload"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
        _dotsecenv_sync_new_keys '$test_dir/project'
        cd '$test_dir/other'
        echo 'DB='(test -n \"\$DB_PASSWORD\"; and echo \$DB_PASSWORD; or echo unset)'|API='(test -n \"\$API_KEY\"; and echo \$API_KEY; or echo unset)
    " 2>&1)

    if string match -q "*DB=unset|API=unset*" "$result"
        pass "[fish] Synced key tracked and unloaded on leave"
    else
        fail "[fish] Synced key leaked on leave, got: $result"
    end
end

function test_reload_ingests_new_key
    log "[fish] Testing 'dse reload' ingests a key added to an already-loaded dir..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_reload_newkey"
    mkdir -p "$test_dir/project"

    echo 'DB_PASSWORD={dotsecenv}' >"$test_dir/project/.secenv"
    chmod 644 "$test_dir/project/.secenv"

    set config_dir "$TEMP_DIR/config_reload_newkey"
    mkdir -p "$config_dir"
    echo "$test_dir/project" >"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
        dse reload
        echo 'DB='\$DB_PASSWORD'|API='\$API_KEY
    " 2>&1)

    if string match -q "*DB=super-secret-password|API=mock-api-key-12345*" "$result"
        pass "[fish] 'dse reload' ingests newly-added key"
    else
        fail "[fish] 'dse reload' did not ingest new key, got: $result"
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
    test_missing_secret_error_deduped
    test_security_check_world_writable
    test_two_phase_loading
    test_load_unload_message_split
    test_empty_secenv_no_message
    test_alias_dse
    test_alias_dse_get
    test_comments_and_empty_lines
    test_quoted_values

    # Tree-scoped loading tests
    test_tree_scope_persist_in_subdir
    test_tree_scope_unload_on_leave
    test_tree_scope_nested_secenv
    test_tree_scope_sibling_navigation
    test_tree_scope_no_reload_from_subdir
    test_multiline_warning

    # dse up tests
    test_dse_up_basic
    test_dse_up_multiple_ancestors
    test_dse_up_skips_already_loaded
    test_dse_up_no_ancestors

    # FIX B: trailing-whitespace / CRLF parsing
    test_parse_trailing_whitespace_secret
    test_load_crlf_empty_name_resolves

    # FIX A: reload / new-key detection
    test_sync_new_key_always_trusted
    test_sync_no_new_keys_noop
    test_sync_new_key_unload_integrity
    test_reload_ingests_new_key

    # Regression: non-interactive shells stay silent (plugin#29)
    test_noninteractive_silent

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

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
        "PEM_KEY") printf -- "-----BEGIN TEST KEY-----\nAAAA\n\nBBBB\n-----END TEST KEY-----" ;;
        "ESCAPED") printf "%s" "a\\\\nb\\\\c" ;;
        *) exit 1 ;;
    esac
else
    exit 1
fi' >"$mock_dir/dotsecenv"
    chmod +x "$mock_dir/dotsecenv"
    echo $mock_dir
end

# Trust directories "always" for their current .secenv contents, as
# answering [a]lways to the prompt would
function trust_dirs
    mkdir -p $argv[1]
    for dir in $argv[2..]
        set -l hash (begin
                sha256sum 2>/dev/null; or shasum -a 256
            end <$dir/.secenv | string sub -l 64)
        printf '%s %s\n' $hash $dir
    end >$argv[1]/trusted_dirs
end

# Run a script in an interactive fish with the plugin loaded; output is one string
function run_plugin
    set -l config_dir $argv[1]
    set -l mock_path $argv[2]
    fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        $argv[3]
    " 2>&1 | string collect
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
    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
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

function test_missing_secret_error_deduped
    log "[fish] Testing missing secret error printed once for multiple keys..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_missing_secret_dedupe"
    mkdir -p "$test_dir"

    # Two keys mapping to the same missing secret
    printf 'MISSING_SECRET={dotsecenv}\nTF_VAR_MISSING={dotsecenv/MISSING_SECRET}\n' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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
    log "[fish] Testing security check (world-writable 666 and 777)..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_security"
    mkdir -p "$test_dir"
    echo 'UNSAFE_VAR=should-not-load' >"$test_dir/.secenv"

    set mock_path (create_mock_dotsecenv)

    set -l failed
    for mode in 666 777
        chmod $mode "$test_dir/.secenv"
        # Pre-trust the directory (but security check should still fail)
        trust_dirs "$TEMP_DIR/config" "$test_dir"
        set result (run_plugin "$TEMP_DIR/config" "$mock_path" "
            cd '$test_dir'
            echo VAR=(set -q UNSAFE_VAR; and echo \$UNSAFE_VAR; or echo unset)
        ")
        if not string match -q "*refusing*world-writable*" "$result"; or not string match -q "*VAR=unset*" "$result"
            set -a failed "$mode: $result"
        end
    end

    if test (count $failed) -eq 0
        pass "[fish] World-writable file rejected correctly"
    else
        fail "[fish] World-writable file not rejected, got: $failed"
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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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
    trust_dirs "$config_dir" "$test_dir"

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
    trust_dirs "$config_dir" "$test_dir"

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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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

    trust_dirs "$TEMP_DIR/config" "$test_dir"
    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$TEMP_DIR/config'
        mkdir -p '$TEMP_DIR/config'
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
    trust_dirs "$config_dir" "$test_dir/parent"

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
    trust_dirs "$config_dir" "$test_dir/project"

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
    trust_dirs "$config_dir" "$test_dir/parent" "$test_dir/parent/child"

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
    trust_dirs "$config_dir" "$test_dir/parent"

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
    trust_dirs "$config_dir" "$test_dir/project"

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
    trust_dirs "$config_dir" "$test_dir"

    set mock_path (create_mock_dotsecenv)

    set result (fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir'
        _dotsecenv_on_cd '' '$test_dir'
    " 2>&1)

    if string match -q "*contains newlines*" "$result"
        pass "[fish] Multiline value warning displayed correctly"
    else
        fail "[fish] Multiline value warning not displayed, got: $result"
    end
end

function test_multiline_and_escapes_byte_exact
    log "[fish] Testing multi-line and backslash values arrive byte for byte..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_bytes"
    set out "$test_dir/out"
    mkdir -p "$out"
    printf '%s\n' 'PEM_KEY={dotsecenv}' 'ESCAPED={dotsecenv}' >"$test_dir/.secenv"
    chmod 644 "$test_dir/.secenv"
    printf '%s\n%s\n\n%s\n%s' '-----BEGIN TEST KEY-----' AAAA BBBB '-----END TEST KEY-----' >"$out/want_pem"
    printf '%s' 'a\\nb\\c' >"$out/want_esc"

    set config_dir "$TEMP_DIR/config_bytes"
    trust_dirs "$config_dir" "$test_dir"

    # Clipboard stubs write what they receive to $CLIP_OUT
    set mock_path (create_mock_dotsecenv)
    for tool in pbcopy wl-copy xclip
        printf '#!/bin/sh\ncat >"$CLIP_OUT"\n' >"$mock_path/$tool"
        chmod +x "$mock_path/$tool"
    end

    run_plugin "$config_dir" "$mock_path" "
        set -gx CLIP_OUT '$out/clip'
        set -gx WAYLAND_DISPLAY test
        cd '$test_dir'
        printf '%s' \"\$PEM_KEY\" >'$out/env_pem'
        printf '%s' \"\$ESCAPED\" >'$out/env_esc'
        dse cp PEM_KEY; and mv '$out/clip' '$out/clip_pem'
        dse cp ESCAPED; and mv '$out/clip' '$out/clip_esc'
    " >/dev/null

    set -l bad
    for f in env_pem clip_pem
        cmp -s "$out/want_pem" "$out/$f"; or set -a bad $f
    end
    for f in env_esc clip_esc
        cmp -s "$out/want_esc" "$out/$f"; or set -a bad $f
    end
    if test (count $bad) -eq 0
        pass "[fish] Multi-line and backslash values exact in env and clipboard"
    else
        fail "[fish] Values mangled in: $bad"
    end
end

function test_unload_restores_previous_values
    log "[fish] Testing unload restores the values a .secenv replaced..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set test_dir "$TEMP_DIR/test_restore"
    mkdir -p "$test_dir/parent/child" "$test_dir/other"
    printf '%s\n' 'AWS_PROFILE=dev' 'DB_PASSWORD={dotsecenv}' >"$test_dir/parent/.secenv"
    printf '%s\n' 'AWS_PROFILE=child' 'DB_PASSWORD=child-pw' 'NEW_KEY=x' >"$test_dir/parent/child/.secenv"
    chmod 644 "$test_dir/parent/.secenv" "$test_dir/parent/child/.secenv"

    set config_dir "$TEMP_DIR/config_restore"
    trust_dirs "$config_dir" "$test_dir/parent" "$test_dir/parent/child"
    set mock_path (create_mock_dotsecenv)

    set result (run_plugin "$config_dir" "$mock_path" "
        set -gx AWS_PROFILE prod
        cd '$test_dir/parent'
        cd child
        echo 1:\$AWS_PROFILE:\$DB_PASSWORD:(set -q NEW_KEY; and echo \$NEW_KEY; or echo unset)
        cd ..
        echo 2:\$AWS_PROFILE:\$DB_PASSWORD:(set -q NEW_KEY; and echo \$NEW_KEY; or echo unset)
        cd '$test_dir/other'
        echo 3:\$AWS_PROFILE:(set -q DB_PASSWORD; and echo \$DB_PASSWORD; or echo unset):(set -q NEW_KEY; and echo \$NEW_KEY; or echo unset)
    ")

    if string match -q "*1:child:child-pw:x*" "$result"; and string match -q "*2:dev:super-secret-password:unset*" "$result"; and string match -q "*3:prod:unset:unset*" "$result"
        pass "[fish] Unload restores parent values and the original environment"
    else
        fail "[fish] Unload did not restore previous values, got: $result"
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
    trust_dirs "$config_dir" "$test_dir/project"

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
    trust_dirs "$config_dir" "$test_dir/root" "$test_dir/root/project"

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
    trust_dirs "$config_dir" "$test_dir/project"

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
    trust_dirs "$config_dir" "$test_dir"

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

function test_trust_follows_content
    log "[fish] Testing trust follows .secenv contents and the prompt shows them..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set base "$TEMP_DIR/test_trust_content"
    set proj "$base/proj"
    set legacy "$base/legacy"
    mkdir -p "$proj/src" "$legacy" "$base/other"
    echo 'DB_PASSWORD={dotsecenv}' >"$proj/.secenv"
    echo 'LEGACY=1' >"$legacy/.secenv"
    chmod 644 "$proj/.secenv" "$legacy/.secenv"

    # proj is trusted "always" for its current contents; legacy has an old
    # path-only entry, which must count as changed
    set config_dir "$TEMP_DIR/config_trust_content"
    trust_dirs "$config_dir" "$proj"
    printf '%s\n' "$legacy" >>"$config_dir/trusted_dirs"

    set mock_path (create_mock_dotsecenv)

    # Answers on stdin: [a]lways for the edited proj, [n]o for legacy
    set result (printf 'a\nn\n' | run_plugin "$config_dir" "$mock_path" "
        function _dotsecenv_has_tty; return 0; end
        cd '$proj'
        echo 'API_KEY={dotsecenv}' >> '$proj/.secenv'
        cd src
        cd ..
        echo API=\$API_KEY
        cd '$base/other'
        cd '$proj'
        cd '$legacy'
        echo LEGACY=(set -q LEGACY; and echo \$LEGACY; or echo unset)
    ")

    if string match -q "*new keys in $proj/.secenv*" "$result"
        and string match -q "*  API_KEY={dotsecenv}*" "$result"
        and string match -q "*API=mock-api-key-12345*" "$result"
        and not string match -q "*found .secenv in $proj*" "$result"
        and string match -q "*found .secenv in $legacy*" "$result"
        and string match -q "*LEGACY=unset*" "$result"
        pass "[fish] Changed .secenv and path-only entries prompt; unchanged trusted file does not"
    else
        fail "[fish] Content-based trust wrong, got: $result"
    end
end

function test_trust_one_line_per_dir
    log "[fish] Testing re-trust replaces the old line, so a revert prompts..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set base "$TEMP_DIR/test_trust_revert"
    set proj "$base/proj"
    mkdir -p "$proj" "$base/other"
    echo 'APP=a' >"$proj/.secenv"
    chmod 644 "$proj/.secenv"

    set config_dir "$TEMP_DIR/config_trust_revert"
    trust_dirs "$config_dir" "$proj"
    set mock_path (create_mock_dotsecenv)

    # Contents A are trusted; edit to B and trust it, then revert to A
    set result (printf 'a\na\n' | run_plugin "$config_dir" "$mock_path" "
        function _dotsecenv_has_tty; return 0; end
        cd '$proj'
        echo 'APP=b' >'$proj/.secenv'
        cd '$base/other'
        cd '$proj'
        echo 'APP=a' >'$proj/.secenv'
        cd '$base/other'
        cd '$proj'
        echo APP=\$APP
    ")

    set -l prompts (count (string match -a -- "*found .secenv in $proj*" (string split \n -- $result)))
    set -l lines (count (cat "$config_dir/trusted_dirs"))
    if test $prompts -eq 2; and test $lines -eq 1; and string match -q "*APP=a*" "$result"
        pass "[fish] One trust line per directory; reverting to older contents prompts"
    else
        fail "[fish] Revert handling wrong ($prompts prompts, $lines lines), got: $result"
    end
end

function test_trust_without_hash_tool
    log "[fish] Testing no sha256sum/shasum means every visit prompts..."
    set TESTS_RUN (math $TESTS_RUN + 1)

    set base "$TEMP_DIR/test_trust_nohash"
    set proj "$base/proj"
    mkdir -p "$proj" "$base/other"
    echo 'APP=1' >"$proj/.secenv"
    chmod 644 "$proj/.secenv"

    set config_dir "$TEMP_DIR/config_trust_nohash"
    trust_dirs "$config_dir" "$proj"
    set mock_path (create_mock_dotsecenv)

    # A PATH with what the plugin needs, minus the hashing tools
    set nohash "$TEMP_DIR/nohash_bin"
    mkdir -p "$nohash"
    for tool in bash cat awk grep tr id stat mktemp rm mv cut md5sum md5 mkdir
        set -l path (command -s $tool); and ln -sf $path "$nohash/$tool"
    end

    set result (printf 'a\ny\n' | run_plugin "$config_dir" "$mock_path" "
        set -gx PATH '$mock_path' '$nohash'
        function _dotsecenv_has_tty; return 0; end
        cd '$proj'
        cd '$base/other'
        cd '$proj'
        echo APP=\$APP
    ")

    set -l prompts (count (string match -a -- "*found .secenv in $proj*" (string split \n -- $result)))
    set -l lines (count (cat "$config_dir/trusted_dirs"))
    if test $prompts -eq 2; and test $lines -eq 1; and string match -q "*APP=1*" "$result"
        pass "[fish] Without a hashing tool every visit prompts and nothing is stored"
    else
        fail "[fish] No-hash-tool handling wrong ($prompts prompts, $lines lines), got: $result"
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
    trust_dirs "$config_dir" "$test_dir"

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
    trust_dirs "$config_dir" "$test_dir/project"

    set mock_path (create_mock_dotsecenv)

    set result (echo y | fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        function _dotsecenv_has_tty; return 0; end
        cd '$test_dir/project'
        echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
        _dotsecenv_sync_new_keys '$test_dir/project'
        echo IN=\$API_KEY
        cd '$test_dir/other'
        echo 'DB='(test -n \"\$DB_PASSWORD\"; and echo \$DB_PASSWORD; or echo unset)'|API='(test -n \"\$API_KEY\"; and echo \$API_KEY; or echo unset)
    " 2>&1)

    if string match -q "*IN=mock-api-key-12345*" "$result"; and string match -q "*DB=unset|API=unset*" "$result"
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
    trust_dirs "$config_dir" "$test_dir/project"

    set mock_path (create_mock_dotsecenv)

    set result (echo y | fish --no-config -i -c "
        set -gx PATH '$mock_path' \$PATH
        set -gx DOTSECENV_CONFIG_DIR '$config_dir'
        set -gx DOTSECENV_TRUSTED_DIRS_FILE '$config_dir/trusted_dirs'
        source '$SHELL_DIR/conf.d/dotsecenv.fish'
        cd '$test_dir/project'
        echo 'API_KEY={dotsecenv}' >> '$test_dir/project/.secenv'
        function _dotsecenv_has_tty; return 0; end
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
    test_unload_restores_previous_values
    test_multiline_and_escapes_byte_exact

    # dse up tests
    test_dse_up_basic
    test_dse_up_multiple_ancestors
    test_dse_up_skips_already_loaded
    test_dse_up_no_ancestors

    # FIX B: trailing-whitespace / CRLF parsing
    test_parse_trailing_whitespace_secret
    test_load_crlf_empty_name_resolves

    # FIX A: reload / new-key detection
    test_trust_follows_content
    test_trust_one_line_per_dir
    test_trust_without_hash_tool
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

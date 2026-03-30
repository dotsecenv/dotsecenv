# dotsecenv shell plugin for fish
# Automatically loads .secenv files when entering directories
#
# Installation:
#   fisher install dotsecenv/plugin
#   Or source directly: source /path/to/conf.d/dotsecenv.fish

# Guard against multiple loading
if set -q _DOTSECENV_FISH_LOADED
    exit 0
end
set -g _DOTSECENV_FISH_LOADED 1

# Configuration (respect environment variables if already set)
if not set -q DOTSECENV_CONFIG_DIR
    if test -n "$XDG_CONFIG_HOME"
        set -g DOTSECENV_CONFIG_DIR "$XDG_CONFIG_HOME/dotsecenv"
    else
        set -g DOTSECENV_CONFIG_DIR "$HOME/.config/dotsecenv"
    end
end
if not set -q DOTSECENV_TRUSTED_DIRS_FILE
    set -g DOTSECENV_TRUSTED_DIRS_FILE "$DOTSECENV_CONFIG_DIR/trusted_dirs"
end
set -g _DOTSECENV_SESSION_TRUSTED_DIRS
set -g _DOTSECENV_SESSION_DENIED_DIRS
set -g _DOTSECENV_PREV_PWD ""

# Track loaded variables per directory
# Format: _DOTSECENV_LOADED_<hash> = "VAR1 VAR2 VAR3"
# Track secrets loaded from .secenv (reset per directory change)
set -g _DOTSECENV_SECRETS_LOADED
# Stack of directories with loaded .secenv (ordered ancestor → descendant)
set -g _DOTSECENV_SOURCE_STACK
# Track unloaded keys for re-fetch logic
set -g _DOTSECENV_UNLOADED_KEYS

# Ensure config directory exists
function _dotsecenv_ensure_config_dir
    test -d "$DOTSECENV_CONFIG_DIR"; or mkdir -p "$DOTSECENV_CONFIG_DIR"
end

# Generate a hash for a directory path (for variable naming)
function _dotsecenv_dir_hash
    echo $argv[1] | md5sum | cut -c1-16
end

# Check if child_dir is a subdirectory of parent_dir (or the same)
function _dotsecenv_is_subdir
    set -l parent (string trim -r -c '/' $argv[1])
    set -l child (string trim -r -c '/' $argv[2])
    test "$child" = "$parent"; or string match -q "$parent/*" "$child"
end

# Stack operations for tree-scoped loading
function _dotsecenv_stack_push
    set -g -a _DOTSECENV_SOURCE_STACK $argv[1]
end

function _dotsecenv_stack_pop
    if test (count $_DOTSECENV_SOURCE_STACK) -gt 0
        set -e _DOTSECENV_SOURCE_STACK[-1]
    end
end

function _dotsecenv_stack_top
    if test (count $_DOTSECENV_SOURCE_STACK) -gt 0
        echo $_DOTSECENV_SOURCE_STACK[-1]
    end
end

# Check if a file passes security checks
function _dotsecenv_security_check
    set -l file $argv[1]

    if not test -f "$file"
        return 1
    end

    # Get file owner and permissions
    # Detect GNU vs BSD stat by checking if --version works
    set -l file_owner
    set -l file_perms
    if stat --version >/dev/null 2>&1
        # GNU stat (Linux or GNU coreutils on macOS)
        set file_owner (stat -c '%u' "$file")
        set file_perms (stat -c '%a' "$file")
    else
        # BSD stat (native macOS)
        set file_owner (stat -f '%u' "$file")
        set file_perms (stat -f '%Lp' "$file")
    end

    set -l current_uid (id -u)

    # Check ownership: must be owned by current user or root
    if test "$file_owner" != "$current_uid"; and test "$file_owner" != 0
        echo "dotsecenv: refusing to load $file - not owned by current user or root" >&2
        return 1
    end

    # Check permissions: must not be world-writable
    set -l world_perms (math "$file_perms % 10")
    if test (math "$world_perms % 4 / 2") -eq 1
        echo "dotsecenv: refusing to load $file - world-writable" >&2
        return 1
    end

    return 0
end

# Check if directory is trusted
# Returns 0 if trusted, 1 if not trusted, 2 if denied
function _dotsecenv_is_trusted
    set -l dir $argv[1]

    # Check session-denied list first
    for denied in $_DOTSECENV_SESSION_DENIED_DIRS
        if test "$denied" = "$dir"
            return 2
        end
    end

    # Check session-trusted list
    for trusted in $_DOTSECENV_SESSION_TRUSTED_DIRS
        if test "$trusted" = "$dir"
            return 0
        end
    end

    # Check persistent trusted_dirs file
    if test -f "$DOTSECENV_TRUSTED_DIRS_FILE"
        if grep -qxF "$dir" "$DOTSECENV_TRUSTED_DIRS_FILE" 2>/dev/null
            return 0
        end
    end

    return 1
end

# Add directory to persistent trusted list
function _dotsecenv_trust_always
    set -l dir $argv[1]
    _dotsecenv_ensure_config_dir
    echo "$dir" >>"$DOTSECENV_TRUSTED_DIRS_FILE"
end

# Add directory to session-only trusted list
function _dotsecenv_trust_session
    set -l dir $argv[1]
    set -g -a _DOTSECENV_SESSION_TRUSTED_DIRS "$dir"
end

# Add directory to session-denied list
function _dotsecenv_deny_session
    set -l dir $argv[1]
    set -g -a _DOTSECENV_SESSION_DENIED_DIRS "$dir"
end

# Prompt user for trust decision
function _dotsecenv_prompt_trust
    set -l dir $argv[1]

    # Only prompt if we have a TTY
    if not isatty stdin
        echo "dotsecenv: skipping $dir/.secenv - no TTY for trust prompt" >&2
        return 1
    end

    echo "dotsecenv: found .secenv in $dir" >&2
    read -P "Load secrets? [y]es / [n]o / [a]lways: " response

    switch (string lower "$response")
        case y yes
            _dotsecenv_trust_session "$dir"
            return 0
        case a always
            _dotsecenv_trust_always "$dir"
            return 0
        case '*'
            _dotsecenv_deny_session "$dir"
            return 1
    end
end

# Parse a line from .secenv file
# Sets: _DOTSECENV_PARSE_KEY, _DOTSECENV_PARSE_VALUE, _DOTSECENV_PARSE_TYPE
function _dotsecenv_parse_line
    set -l line $argv[1]
    set -g _DOTSECENV_PARSE_KEY ""
    set -g _DOTSECENV_PARSE_VALUE ""
    set -g _DOTSECENV_PARSE_TYPE ""

    # Skip empty lines and comments
    if test -z "$line"; or string match -qr '^\s*#' "$line"
        return 1
    end

    # Trim leading whitespace
    set line (string trim -l "$line")

    # Match KEY=VALUE pattern
    if string match -qr '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$' "$line"
        set -g _DOTSECENV_PARSE_KEY (string replace -r '^([A-Za-z_][A-Za-z0-9_]*)=.*$' '$1' "$line")
        set -l value (string replace -r '^[A-Za-z_][A-Za-z0-9_]*=(.*)$' '$1' "$line")

        # Remove surrounding quotes if present
        if string match -qr '^"(.*)"$' "$value"
            set value (string replace -r '^"(.*)"$' '$1' "$value")
        else if string match -qr "^'(.*)'\$" "$value"
            set value (string replace -r "^'(.*)'\$" '$1' "$value")
        end

        # Check for dotsecenv patterns
        if test "$value" = "{dotsecenv}"
            set -g _DOTSECENV_PARSE_VALUE "$_DOTSECENV_PARSE_KEY"
            set -g _DOTSECENV_PARSE_TYPE secret_same
        else if string match -qr '^\{dotsecenv/.*\}$' "$value"
            # Extract secret name (everything between first / and closing })
            set -l secret_name (string replace -r '^\{dotsecenv/(.*)\}$' '$1' "$value")
            # Validate: no additional slashes, valid secret name format
            if test -z "$secret_name"
                # Empty name like {dotsecenv/} - treat as plain value silently
                set -g _DOTSECENV_PARSE_VALUE "$value"
                set -g _DOTSECENV_PARSE_TYPE plain
            else if string match -q "*/*" "$secret_name"
                echo "dotsecenv: error: invalid syntax '$value' - only one '/' allowed" >&2
                return 1
            else if string match -qr '^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)?$' "$secret_name"
                set -g _DOTSECENV_PARSE_VALUE "$secret_name"
                set -g _DOTSECENV_PARSE_TYPE secret_named
            else
                echo "dotsecenv: error: invalid secret name '$secret_name' in '$value'" >&2
                return 1
            end
        else
            set -g _DOTSECENV_PARSE_VALUE "$value"
            set -g _DOTSECENV_PARSE_TYPE plain
        end
        return 0
    end

    return 1
end

# Load a single .secenv file
function _dotsecenv_load_file
    set -l file $argv[1]
    set -l phase $argv[2]
    set -l dir $argv[3]
    set -l dir_hash (_dotsecenv_dir_hash "$dir")

    if not test -f "$file"
        return 0
    end

    while read -l line
        if _dotsecenv_parse_line "$line"
            set -l key "$_DOTSECENV_PARSE_KEY"
            set -l value "$_DOTSECENV_PARSE_VALUE"
            set -l ptype "$_DOTSECENV_PARSE_TYPE"

            if test "$phase" = 1; and test "$ptype" = plain
                # Phase 1: load plain variables
                set -gx $key "$value"
                set -g -a _DOTSECENV_LOADED_$dir_hash "$key"

            else if test "$phase" = 2; and begin
                    test "$ptype" = secret_same; or test "$ptype" = secret_named
                end
                # Phase 2: load secrets via dotsecenv CLI
                set -l secret_name "$value"

                # Fetch secret from vault (capture stderr separately to preserve secret value)
                set -l secret_stderr_file (mktemp)
                set -l secret_result (dotsecenv secret get "$secret_name" 2>$secret_stderr_file)
                set -l secret_status $status
                if test $secret_status -eq 0
                    set -gx $key "$secret_result"
                    set -g -a _DOTSECENV_LOADED_$dir_hash "$key"
                    set -g -a _DOTSECENV_SECRETS_LOADED "$key"
                    # Show any warnings that were emitted
                    test -s "$secret_stderr_file"; and cat "$secret_stderr_file" >&2
                    # Warn if value contains newlines (fish splits on newlines into list elements)
                    if test (count $secret_result) -gt 1
                        echo "dotsecenv: warning: $key contains newlines; use (string join \\n \$$key) to reconstruct the full value" >&2
                    end
                else
                    echo "dotsecenv: error fetching secret '$secret_name' for $key:" >&2
                    cat "$secret_stderr_file" >&2
                end
                rm -f "$secret_stderr_file"
            end
        end
    end <"$file"
end

# Unload variables for a directory and track unloaded keys
function _dotsecenv_unload_dir
    set -l dir $argv[1]
    set -l dir_hash (_dotsecenv_dir_hash "$dir")
    set -l vars_var "_DOTSECENV_LOADED_$dir_hash"
    set -l secrets_var "_DOTSECENV_SECRETS_$dir_hash"

    # Reset the unloaded keys tracking
    set -g _DOTSECENV_UNLOADED_KEYS

    # Report secrets being unloaded before clearing them
    if set -q $secrets_var
        set -l secret_count (count $$secrets_var)
        if test $secret_count -gt 0
            set -l secrets_list (string join ', ' $$secrets_var)
            echo "dotsecenv: unloaded $secret_count secret(s): $secrets_list" >&2
        end
        set -e $secrets_var
    end

    if set -q $vars_var
        for var in $$vars_var
            set -g -a _DOTSECENV_UNLOADED_KEYS $var
            set -e $var
        end
        set -e $vars_var
    end
end

# Re-fetch a specific secret key from a directory's .secenv file
function _dotsecenv_refetch_key
    set -l dir $argv[1]
    set -l target_key $argv[2]
    set -l file "$dir/.secenv"

    if not test -f "$file"
        return 1
    end

    while read -l line
        if _dotsecenv_parse_line "$line"
            set -l key "$_DOTSECENV_PARSE_KEY"
            set -l value "$_DOTSECENV_PARSE_VALUE"
            set -l ptype "$_DOTSECENV_PARSE_TYPE"

            if test "$key" = "$target_key"
                if test "$ptype" = secret_same; or test "$ptype" = secret_named
                    set -l secret_name "$value"
                    set -l secret_stderr_file (mktemp)
                    set -l secret_result (dotsecenv secret get "$secret_name" 2>$secret_stderr_file)
                    if test $status -eq 0
                        set -gx $key "$secret_result"
                        test -s "$secret_stderr_file"; and cat "$secret_stderr_file" >&2
                        if test (count $secret_result) -gt 1
                            echo "dotsecenv: warning: $key contains newlines; use (string join \\n \$$key) to reconstruct the full value" >&2
                        end
                    end
                    rm -f "$secret_stderr_file"
                else if test "$ptype" = plain
                    set -gx $key "$value"
                end
                return 0
            end
        end
    end <"$file"
    return 1
end

# Check if a key is defined in a directory's loaded vars
function _dotsecenv_dir_has_key
    set -l dir $argv[1]
    set -l target_key $argv[2]
    set -l dir_hash (_dotsecenv_dir_hash "$dir")
    set -l vars_var "_DOTSECENV_LOADED_$dir_hash"

    if set -q $vars_var
        contains $target_key $$vars_var
        return $status
    end
    return 1
end

# Main function to process directory change (tree-scoped loading)
# Note: old_dir kept for interface compatibility but unused (we use stack-based tracking)
function _dotsecenv_on_cd
    set -l old_dir $argv[1]
    set -l new_dir $argv[2]

    # =========================================================================
    # PHASE 1: POP - Unload directories we've left
    # Walk stack from top (deepest) to bottom, pop entries we're no longer under
    # =========================================================================
    set -l stack_len (count $_DOTSECENV_SOURCE_STACK)

    # Iterate from the end of the stack (deepest directory) backwards
    # Note: skip if stack is empty to avoid "seq: needs positive increment" error
    if test $stack_len -gt 0
        for i in (seq $stack_len -1 1)
            set -l stack_dir $_DOTSECENV_SOURCE_STACK[$i]

            if not _dotsecenv_is_subdir "$stack_dir" "$new_dir"
                # We've left this directory tree - pop and unload
                _dotsecenv_stack_pop
                _dotsecenv_unload_dir "$stack_dir"

                # Re-fetch any keys that were shadowed by this directory
                for unloaded_key in $_DOTSECENV_UNLOADED_KEYS
                    # Check remaining stack entries (ancestors) for this key
                    # Skip if no ancestors remain (i <= 1)
                    if test $i -gt 1
                        for j in (seq (math "$i - 1") -1 1)
                            set -l ancestor_dir $_DOTSECENV_SOURCE_STACK[$j]
                            if _dotsecenv_dir_has_key "$ancestor_dir" "$unloaded_key"
                                # Re-fetch from the ancestor's .secenv
                                _dotsecenv_refetch_key "$ancestor_dir" "$unloaded_key"
                                break
                            end
                        end
                    end
                end
            else
                # Still under this directory - stop popping
                break
            end
        end
    end

    # =========================================================================
    # PHASE 2: RELOAD check - Only reload if we returned from OUTSIDE the tree
    # (If we're navigating within the tree, e.g. subdir -> parent, don't reload)
    # =========================================================================
    set stack_len (count $_DOTSECENV_SOURCE_STACK)
    if test $stack_len -gt 0
        set -l top_dir $_DOTSECENV_SOURCE_STACK[-1]
        if test "$new_dir" = "$top_dir"
            # Only reload if we came from outside this directory's tree
            if test -n "$old_dir"; and not _dotsecenv_is_subdir "$top_dir" "$old_dir"
                # We returned from outside - pop and reload fresh
                _dotsecenv_stack_pop
                _dotsecenv_unload_dir "$top_dir"
            else
                # Coming from a subdirectory - secrets already loaded, nothing to do
                return 0
            end
        end
    end

    # =========================================================================
    # PHASE 3: Check if we're in a subtree with no new .secenv to load
    # =========================================================================
    set -l has_secenv 0
    test -f "$new_dir/.secenv"; and set has_secenv 1

    set stack_len (count $_DOTSECENV_SOURCE_STACK)
    if test $stack_len -gt 0; and test $has_secenv -eq 0
        # We're in a subtree of an existing source directory with no new .secenv
        # Secrets persist - nothing to do
        return 0
    end

    # =========================================================================
    # PHASE 4: PUSH - Load .secenv if present
    # =========================================================================
    if test $has_secenv -eq 0
        return 0
    end

    # Initialize tracking for this directory
    set -l dir_hash (_dotsecenv_dir_hash "$new_dir")

    # Security check for .secenv
    if not _dotsecenv_security_check "$new_dir/.secenv"
        return 0
    end

    # Trust check for .secenv
    set -l should_load 0
    _dotsecenv_is_trusted "$new_dir"
    set -l trust_status $status

    if test $trust_status -eq 0
        set should_load 1
    else if test $trust_status -eq 2
        # Denied this session
        return 0
    else
        # Not trusted, prompt user
        if _dotsecenv_prompt_trust "$new_dir"
            set should_load 1
        end
    end

    if test $should_load -eq 0
        return 0
    end

    # Phase 1: Load plain variables from .secenv
    _dotsecenv_load_file "$new_dir/.secenv" 1 "$new_dir"

    # Phase 2: Load secrets from .secenv
    set -g _DOTSECENV_SECRETS_LOADED
    _dotsecenv_load_file "$new_dir/.secenv" 2 "$new_dir"

    if test (count $_DOTSECENV_SECRETS_LOADED) -gt 0
        # Track secrets per directory for unload reporting
        set -g _DOTSECENV_SECRETS_$dir_hash $_DOTSECENV_SECRETS_LOADED
        set -l keys_list (string join ', ' $_DOTSECENV_SECRETS_LOADED)
        echo "dotsecenv: loaded "(count $_DOTSECENV_SECRETS_LOADED)" secret(s) from .secenv: $keys_list" >&2
    end

    # Push this directory onto the stack if we loaded anything
    set -l vars_var "_DOTSECENV_LOADED_$dir_hash"
    if set -q $vars_var; and test (count $$vars_var) -gt 0
        _dotsecenv_stack_push "$new_dir"
    end
end

# Walk up from current directory and load ancestor .secenv files (root-first)
# Arguments: [boundary_dir]
#   boundary_dir: stop walking at this directory (default: git root, fallback: filesystem root)
function _dotsecenv_load_ancestors
    set -l original_dir "$PWD"
    set -l boundary ""

    if test (count $argv) -gt 0
        set boundary $argv[1]
    end

    # Determine boundary
    if test -z "$boundary"
        set boundary (git rev-parse --show-toplevel 2>/dev/null)
        or set boundary ""
    end

    # Walk up from current dir (exclusive) to boundary (inclusive), collect dirs with .secenv
    set -l ancestor_secenvs
    set -l dir "$original_dir"
    while true
        set -l parent (dirname "$dir")
        test "$parent" = "$dir"; and break # reached filesystem root
        set dir "$parent"
        if test -f "$dir/.secenv"
            set -a ancestor_secenvs "$dir"
        end
        if test -n "$boundary"; and test "$dir" = "$boundary"
            break
        end
    end

    # Filter out directories already on the stack
    set -l to_load
    for ancestor in $ancestor_secenvs
        set -l already_loaded 0
        for stack_entry in $_DOTSECENV_SOURCE_STACK
            if test "$stack_entry" = "$ancestor"
                set already_loaded 1
                break
            end
        end
        if test $already_loaded -eq 0
            set -a to_load "$ancestor"
        end
    end

    if test (count $to_load) -eq 0
        echo "dotsecenv: no new ancestor .secenv files found" >&2
        return 0
    end

    # Process root-first (reverse) by cd-ing into each directory.
    # Actual cd is required so dotsecenv CLI resolves vault paths relative to the
    # .secenv directory. Fish's --on-variable PWD hook fires automatically from cd.
    for i in (seq (count $to_load) -1 1)
        cd "$to_load[$i]"; or continue
    end

    # Return to the original directory
    cd "$original_dir"
end

# Hook function called on directory change
function _dotsecenv_cd_hook --on-variable PWD
    set -l old_dir "$_DOTSECENV_PREV_PWD"
    set -l new_dir "$PWD"

    # Update previous directory tracker
    set -g _DOTSECENV_PREV_PWD "$PWD"

    # Process the directory change
    _dotsecenv_on_cd "$old_dir" "$new_dir"
end

# Reload all .secenv files - clears stack and re-fetches everything fresh
function _dotsecenv_reload
    # Save current stack entries (ancestor → descendant order)
    set -l dirs_to_reload $_DOTSECENV_SOURCE_STACK

    # Clear the entire stack and unload all variables
    while test (count $_DOTSECENV_SOURCE_STACK) -gt 0
        set -l top $_DOTSECENV_SOURCE_STACK[-1]
        _dotsecenv_stack_pop
        _dotsecenv_unload_dir "$top"
    end

    # Re-load each directory in original order (ancestor → descendant)
    for dir in $dirs_to_reload
        if test -f "$dir/.secenv"
            _dotsecenv_on_cd "" "$dir"
        end
    end

    # Also pick up current dir if it now has .secenv and wasn't previously loaded
    if test -f "$PWD/.secenv"
        if not contains "$PWD" $dirs_to_reload
            _dotsecenv_on_cd "" "$PWD"
        end
    end
end

# Reload secrets in current directory
function reloadsecenv
    _dotsecenv_reload
end

# Clipboard helper - copies stdin to clipboard
function _dotsecenv_clipboard_copy
    # macOS - use pbcopy
    if test (uname -s) = Darwin
        pbcopy
        return $status
    end

    # Wayland - check for display and wl-copy
    if test -n "$WAYLAND_DISPLAY"; and command -sq wl-copy
        wl-copy
        return $status
    end

    # X11 - check for display before trying X11 clipboard tools
    if test -n "$DISPLAY"
        if command -sq xclip
            xclip -selection clipboard
            return $status
        end

        if command -sq xsel
            xsel --clipboard --input
            return $status
        end
    end

    echo "dotsecenv: no clipboard available (no display or clipboard utility found)" >&2
    return 1
end

# Alias: dse (with subcommands: reload, get, cp)
function dse
    if test (count $argv) -eq 0
        dotsecenv
        return
    end

    switch $argv[1]
        case reload
            _dotsecenv_reload
        case get
            dotsecenv secret get $argv[2..]
        case cp
            set -l output
            if set output (dotsecenv secret get $argv[2..])
                if echo -n "$output" | _dotsecenv_clipboard_copy
                    echo "dotsecenv: secret copied to clipboard" >&2
                else
                    return 1
                end
            else
                return 1
            end
        case up
            _dotsecenv_load_ancestors $argv[2..]
        case '*'
            dotsecenv $argv
    end
end

# Process current directory on plugin load
set -g _DOTSECENV_PREV_PWD ""
_dotsecenv_on_cd "" "$PWD"

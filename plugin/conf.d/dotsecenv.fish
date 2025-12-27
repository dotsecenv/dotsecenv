# dotsecenv shell plugin for fish
# Automatically loads .env and .secenv files when entering directories
#
# Installation:
#   fisher install dotsecenv/plugin
#   Or source directly: source /path/to/conf.d/dotsecenv.fish

# Guard against multiple loading
if set -q _DOTSECENV_FISH_LOADED
    exit 0
end
set -g _DOTSECENV_FISH_LOADED 1

# Configuration
set -g DOTSECENV_CONFIG_DIR (test -n "$XDG_CONFIG_HOME"; and echo "$XDG_CONFIG_HOME"; or echo "$HOME/.config")/dotsecenv
set -g DOTSECENV_TRUSTED_DIRS_FILE "$DOTSECENV_CONFIG_DIR/trusted_dirs"
set -g _DOTSECENV_SESSION_TRUSTED_DIRS
set -g _DOTSECENV_SESSION_DENIED_DIRS
set -g _DOTSECENV_PREV_PWD ""

# Track loaded variables per directory
# Format: _DOTSECENV_LOADED_<hash> = "VAR1 VAR2 VAR3"
# Track which vars were set by .env
set -g _DOTSECENV_ENV_VARS

# Ensure config directory exists
function _dotsecenv_ensure_config_dir
    test -d "$DOTSECENV_CONFIG_DIR"; or mkdir -p "$DOTSECENV_CONFIG_DIR"
end

# Generate a hash for a directory path (for variable naming)
function _dotsecenv_dir_hash
    echo $argv[1] | md5sum | cut -c1-16
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

# Parse a line from .env or .secenv file
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

# Load a single .env or .secenv file
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
                set -g -a _DOTSECENV_ENV_VARS "$key"

            else if test "$phase" = 2; and begin
                    test "$ptype" = secret_same; or test "$ptype" = secret_named
                end
                # Phase 2: load secrets via dotsecenv CLI
                set -l secret_name "$value"

                # Check if this will override a .env variable
                if contains "$key" $_DOTSECENV_ENV_VARS
                    echo "dotsecenv: warning: $key from .secenv overrides value from .env" >&2
                end

                # Fetch secret from vault
                set -l secret_value
                if set secret_value (dotsecenv secret get "$secret_name" 2>/dev/null)
                    set -gx $key "$secret_value"
                    set -g -a _DOTSECENV_LOADED_$dir_hash "$key"
                else
                    echo "dotsecenv: warning: secret '$secret_name' not found in vault, $key left unset" >&2
                    echo "run: \`dotsecenv secret put $secret_name\` to create it." >&2
                end
            end
        end
    end <"$file"
end

# Unload variables for a directory
function _dotsecenv_unload_dir
    set -l dir $argv[1]
    set -l dir_hash (_dotsecenv_dir_hash "$dir")
    set -l vars_var "_DOTSECENV_LOADED_$dir_hash"

    if set -q $vars_var
        for var in $$vars_var
            set -e $var
        end
        set -e $vars_var
    end
end

# Main function to process directory change
function _dotsecenv_on_cd
    set -l old_dir $argv[1]
    set -l new_dir $argv[2]

    # Unload variables from old directory
    if test -n "$old_dir"
        _dotsecenv_unload_dir "$old_dir"
    end

    # Check if new directory has .env or .secenv
    set -l has_env 0
    set -l has_secenv 0
    set -l should_load_secenv 0

    test -f "$new_dir/.env"; and set has_env 1
    test -f "$new_dir/.secenv"; and set has_secenv 1

    # Nothing to load
    if test $has_env -eq 0; and test $has_secenv -eq 0
        return 0
    end

    # Security check for .env
    if test $has_env -eq 1
        if not _dotsecenv_security_check "$new_dir/.env"
            set has_env 0
        end
    end

    # Security check and trust check for .secenv
    if test $has_secenv -eq 1
        if not _dotsecenv_security_check "$new_dir/.secenv"
            set has_secenv 0
        else
            # Check trust status
            _dotsecenv_is_trusted "$new_dir"
            set -l trust_status $status

            if test $trust_status -eq 0
                set should_load_secenv 1
            else if test $trust_status -eq 2
                # Denied this session
                set should_load_secenv 0
            else
                # Not trusted, prompt user
                if _dotsecenv_prompt_trust "$new_dir"
                    set should_load_secenv 1
                end
            end
        end
    end

    # Clear env var tracking for fresh load
    set -g _DOTSECENV_ENV_VARS

    # Phase 1: Load plain variables from .env
    if test $has_env -eq 1
        _dotsecenv_load_file "$new_dir/.env" 1 "$new_dir"
    end

    # Phase 1: Load plain variables from .secenv (if trusted)
    if test $has_secenv -eq 1; and test $should_load_secenv -eq 1
        _dotsecenv_load_file "$new_dir/.secenv" 1 "$new_dir"
    end

    # Phase 2: Load secrets from .env
    if test $has_env -eq 1
        _dotsecenv_load_file "$new_dir/.env" 2 "$new_dir"
    end

    # Phase 2: Load secrets from .secenv (if trusted)
    if test $has_secenv -eq 1; and test $should_load_secenv -eq 1
        _dotsecenv_load_file "$new_dir/.secenv" 2 "$new_dir"
    end
end

# Hook function called on directory change
function _dotsecenv_cd_hook --on-variable PWD
    set -l old_dir "$_DOTSECENV_PREV_PWD"
    set -l new_dir "$PWD"

    # Update previous directory tracker
    set -g _DOTSECENV_PREV_PWD "$PWD"

    # Process the directory change (allows cd . to reload .secenv files)
    _dotsecenv_on_cd "$old_dir" "$new_dir"
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

# Alias: dse
function dse
    dotsecenv $argv
end

# Alias: secret
function secret
    dotsecenv secret get $argv
end

# secretcp: copies secret to clipboard
function secretcp
    set -l output
    if set output (dotsecenv secret get $argv)
        if echo -n "$output" | _dotsecenv_clipboard_copy
            echo "dotsecenv: secret copied to clipboard" >&2
        else
            return 1
        end
    else
        return 1
    end
end

# Process current directory on plugin load
set -g _DOTSECENV_PREV_PWD ""
_dotsecenv_on_cd "" "$PWD"

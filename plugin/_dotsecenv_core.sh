#!/usr/bin/env bash
# dotsecenv shell plugin - core shared logic for bash/zsh
# This file is sourced by both dotsecenv.plugin.bash and dotsecenv.plugin.zsh
# Requires bash 5.2+ or zsh 5.0+

# Configuration - use existing values if set, otherwise use defaults
: "${DOTSECENV_CONFIG_DIR:=${XDG_CONFIG_HOME:-$HOME/.config}/dotsecenv}"
: "${DOTSECENV_TRUSTED_DIRS_FILE:=${DOTSECENV_CONFIG_DIR}/trusted_dirs}"

# Session-level trust lists (arrays)
declare -g -a _DOTSECENV_SESSION_TRUSTED_DIRS=()
declare -g -a _DOTSECENV_SESSION_DENIED_DIRS=()

# Track which vars were set by .env (for override warnings)
declare -g -a _DOTSECENV_ENV_VARS=()

# Track loaded variables per directory
# Format: _DOTSECENV_LOADED_<hash> = (VAR1 VAR2 VAR3)

# Ensure config directory exists
_dotsecenv_ensure_config_dir() {
    [[ -d "$DOTSECENV_CONFIG_DIR" ]] || mkdir -p "$DOTSECENV_CONFIG_DIR"
}

# Generate a hash for a directory path (for variable naming)
_dotsecenv_dir_hash() {
    echo "$1" | md5sum 2>/dev/null | cut -c1-16 || echo "$1" | md5 2>/dev/null | cut -c1-16
}

# Check if a file passes security checks
# Returns 0 if safe, 1 if unsafe
_dotsecenv_security_check() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    # Get file stats - detect stat variant
    local file_owner file_perms
    if stat --version &>/dev/null; then
        # GNU stat (Linux)
        file_owner=$(stat -c '%u' "$file")
        file_perms=$(stat -c '%a' "$file")
    else
        # BSD stat (macOS)
        file_owner=$(stat -f '%u' "$file")
        file_perms=$(stat -f '%Lp' "$file")
    fi

    local current_uid
    current_uid=$(id -u)

    # Check ownership: must be owned by current user or root
    if [[ "$file_owner" != "$current_uid" && "$file_owner" != "0" ]]; then
        echo "dotsecenv: refusing to load $file - not owned by current user or root" >&2
        return 1
    fi

    # Check permissions: must not be world-writable
    local world_perms=$((file_perms % 10))
    if ((world_perms & 2)); then
        echo "dotsecenv: refusing to load $file - world-writable" >&2
        return 1
    fi

    return 0
}

# Check if directory is trusted
# Returns 0 if trusted, 1 if not trusted, 2 if denied
_dotsecenv_is_trusted() {
    local dir="$1"

    # Check session-denied list first
    local denied
    for denied in "${_DOTSECENV_SESSION_DENIED_DIRS[@]}"; do
        if [[ "$denied" == "$dir" ]]; then
            return 2
        fi
    done

    # Check session-trusted list
    local trusted
    for trusted in "${_DOTSECENV_SESSION_TRUSTED_DIRS[@]}"; do
        if [[ "$trusted" == "$dir" ]]; then
            return 0
        fi
    done

    # Check persistent trusted_dirs file
    if [[ -f "$DOTSECENV_TRUSTED_DIRS_FILE" ]]; then
        if grep -qxF "$dir" "$DOTSECENV_TRUSTED_DIRS_FILE" 2>/dev/null; then
            return 0
        fi
    fi

    return 1
}

# Add directory to persistent trusted list
_dotsecenv_trust_always() {
    local dir="$1"
    _dotsecenv_ensure_config_dir
    echo "$dir" >> "$DOTSECENV_TRUSTED_DIRS_FILE"
}

# Add directory to session-only trusted list
_dotsecenv_trust_session() {
    local dir="$1"
    _DOTSECENV_SESSION_TRUSTED_DIRS+=("$dir")
}

# Add directory to session-denied list
_dotsecenv_deny_session() {
    local dir="$1"
    _DOTSECENV_SESSION_DENIED_DIRS+=("$dir")
}

# Prompt user for trust decision
# Returns 0 if should load, 1 if should not load
_dotsecenv_prompt_trust() {
    local dir="$1"
    local response

    # Only prompt if we have a TTY
    if [[ ! -t 0 ]]; then
        echo "dotsecenv: skipping $dir/.secenv - no TTY for trust prompt" >&2
        return 1
    fi

    echo "dotsecenv: found .secenv in $dir" >&2
    echo -n "Load secrets? [y]es / [n]o / [a]lways: " >&2
    read -r response

    # Convert to lowercase (portable for bash and zsh)
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    case "$response" in
        y|yes)
            _dotsecenv_trust_session "$dir"
            return 0
            ;;
        a|always)
            _dotsecenv_trust_always "$dir"
            return 0
            ;;
        n|no|*)
            _dotsecenv_deny_session "$dir"
            return 1
            ;;
    esac
}

# Parse a line from .env or .secenv file
# Sets global variables: _DOTSECENV_PARSE_KEY, _DOTSECENV_PARSE_VALUE, _DOTSECENV_PARSE_TYPE
# Type: "plain", "secret_same" (key matches secret name), "secret_named" (different secret name)
_dotsecenv_parse_line() {
    local line="$1"
    _DOTSECENV_PARSE_KEY=""
    _DOTSECENV_PARSE_VALUE=""
    _DOTSECENV_PARSE_TYPE=""

    # Skip empty lines and comments
    [[ -z "$line" ]] && return 1
    [[ "$line" =~ ^[[:space:]]*# ]] && return 1

    # Trim leading whitespace
    line="${line#"${line%%[![:space:]]*}"}"

    # Match KEY=VALUE pattern
    if [[ "$line" == *=* ]]; then
        local key="${line%%=*}"
        local value="${line#*=}"

        # Validate key format: starts with letter or underscore, followed by alphanumeric/underscore
        if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            _DOTSECENV_PARSE_KEY="$key"

            # Remove surrounding quotes if present
            if [[ "$value" =~ ^\"(.*)\"$ ]]; then
                value="${value:1:${#value}-2}"
            elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
                value="${value:1:${#value}-2}"
            fi

            # Check for dotsecenv patterns
            if [[ "$value" == "{dotsecenv}" ]]; then
                _DOTSECENV_PARSE_VALUE="$_DOTSECENV_PARSE_KEY"
                _DOTSECENV_PARSE_TYPE="secret_same"
            elif [[ "$value" == \{dotsecenv:*\} ]]; then
                # Extract secret name
                local secret_name="${value#\{dotsecenv:}"
                secret_name="${secret_name%\}}"
                # Validate the secret name format
                if [[ "$secret_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
                    _DOTSECENV_PARSE_VALUE="$secret_name"
                    _DOTSECENV_PARSE_TYPE="secret_named"
                else
                    _DOTSECENV_PARSE_VALUE="$value"
                    _DOTSECENV_PARSE_TYPE="plain"
                fi
            else
                _DOTSECENV_PARSE_VALUE="$value"
                _DOTSECENV_PARSE_TYPE="plain"
            fi
            return 0
        fi
    fi

    return 1
}

# Append a value to a dynamically named array (works in both bash and zsh)
_dotsecenv_array_append() {
    local array_name="$1"
    local value="$2"
    eval "${array_name}+=(\"\$value\")"
}

# Load a single .env or .secenv file
# Arguments: file_path, phase (1=plain vars only, 2=secrets only), dir
_dotsecenv_load_file() {
    local file="$1"
    local phase="$2"
    local dir="$3"
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$dir")

    [[ -f "$file" ]] || return 0

    # Variable name for tracking loaded vars for this directory
    local vars_var="_DOTSECENV_LOADED_${dir_hash}"

    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        if _dotsecenv_parse_line "$line"; then
            local key="$_DOTSECENV_PARSE_KEY"
            local value="$_DOTSECENV_PARSE_VALUE"
            local ptype="$_DOTSECENV_PARSE_TYPE"

            if [[ "$phase" == "1" && "$ptype" == "plain" ]]; then
                # Phase 1: load plain variables
                export "$key=$value"
                _dotsecenv_array_append "$vars_var" "$key"
                _DOTSECENV_ENV_VARS+=("$key")

            elif [[ "$phase" == "2" && ("$ptype" == "secret_same" || "$ptype" == "secret_named") ]]; then
                # Phase 2: load secrets via dotsecenv CLI
                local secret_name="$value"
                local secret_value

                # Check if this will override a .env variable
                local env_var
                for env_var in "${_DOTSECENV_ENV_VARS[@]}"; do
                    if [[ "$env_var" == "$key" ]]; then
                        echo "dotsecenv: warning: $key from .secenv overrides value from .env" >&2
                        break
                    fi
                done

                # Fetch secret from vault
                if secret_value=$(dotsecenv secret get "$secret_name" 2>/dev/null); then
                    export "$key=$secret_value"
                    _dotsecenv_array_append "$vars_var" "$key"
                else
                    echo "dotsecenv: warning: secret '$secret_name' not found in vault, $key left unset" >&2
                fi
            fi
        fi
    done < "$file"
}

# Unload variables for a directory
_dotsecenv_unload_dir() {
    local dir="$1"
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$dir")
    local vars_var="_DOTSECENV_LOADED_${dir_hash}"

    # Check if the tracking variable exists and unload vars
    # Use eval for zsh/bash compatibility
    if eval "[[ \${#${vars_var}[@]} -gt 0 ]]" 2>/dev/null; then
        local var
        eval "for var in \"\${${vars_var}[@]}\"; do unset \"\$var\"; done"
        unset "$vars_var"
    fi
}

# Main function to process directory change
# Arguments: old_dir, new_dir
_dotsecenv_on_cd() {
    local old_dir="$1"
    local new_dir="$2"

    # Unload variables from old directory
    if [[ -n "$old_dir" ]]; then
        _dotsecenv_unload_dir "$old_dir"
    fi

    # Check if new directory has .env or .secenv
    local has_env=0
    local has_secenv=0
    local should_load_secenv=0

    [[ -f "$new_dir/.env" ]] && has_env=1
    [[ -f "$new_dir/.secenv" ]] && has_secenv=1

    # Nothing to load
    if [[ $has_env -eq 0 && $has_secenv -eq 0 ]]; then
        return 0
    fi

    # Security check for .env
    if [[ $has_env -eq 1 ]]; then
        if ! _dotsecenv_security_check "$new_dir/.env"; then
            has_env=0
        fi
    fi

    # Security check and trust check for .secenv
    if [[ $has_secenv -eq 1 ]]; then
        if ! _dotsecenv_security_check "$new_dir/.secenv"; then
            has_secenv=0
        else
            # Check trust status
            _dotsecenv_is_trusted "$new_dir"
            local trust_status=$?

            if [[ $trust_status -eq 0 ]]; then
                should_load_secenv=1
            elif [[ $trust_status -eq 2 ]]; then
                # Denied this session
                should_load_secenv=0
            else
                # Not trusted, prompt user
                if _dotsecenv_prompt_trust "$new_dir"; then
                    should_load_secenv=1
                fi
            fi
        fi
    fi

    # Clear env var tracking for fresh load
    _DOTSECENV_ENV_VARS=()

    # Initialize the loaded vars array for this directory
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$new_dir")
    eval "_DOTSECENV_LOADED_${dir_hash}=()"

    # Phase 1: Load plain variables from .env
    if [[ $has_env -eq 1 ]]; then
        _dotsecenv_load_file "$new_dir/.env" 1 "$new_dir"
    fi

    # Phase 1: Load plain variables from .secenv (if trusted)
    if [[ $has_secenv -eq 1 && $should_load_secenv -eq 1 ]]; then
        _dotsecenv_load_file "$new_dir/.secenv" 1 "$new_dir"
    fi

    # Phase 2: Load secrets from .env
    if [[ $has_env -eq 1 ]]; then
        _dotsecenv_load_file "$new_dir/.env" 2 "$new_dir"
    fi

    # Phase 2: Load secrets from .secenv (if trusted)
    if [[ $has_secenv -eq 1 && $should_load_secenv -eq 1 ]]; then
        _dotsecenv_load_file "$new_dir/.secenv" 2 "$new_dir"
    fi
}

# Clipboard helper - copies stdin to clipboard
_dotsecenv_clipboard_copy() {
    # macOS - use pbcopy
    if [[ "$OSTYPE" == darwin* ]]; then
        pbcopy
        return $?
    fi

    # Wayland - check for display and wl-copy
    if [[ -n "$WAYLAND_DISPLAY" ]] && command -v wl-copy &>/dev/null; then
        wl-copy
        return $?
    fi

    # X11 - check for display before trying X11 clipboard tools
    if [[ -n "$DISPLAY" ]]; then
        if command -v xclip &>/dev/null; then
            xclip -selection clipboard
            return $?
        fi

        if command -v xsel &>/dev/null; then
            xsel --clipboard --input
            return $?
        fi
    fi

    echo "dotsecenv: no clipboard available (no display or clipboard utility found)" >&2
    return 1
}

# Aliases - defined as functions to work in both bash and zsh
dse() {
    dotsecenv "$@"
}

secret() {
    dotsecenv secret get "$@"
}

# secretcp copies output to clipboard
secretcp() {
    local output
    if output=$(dotsecenv secret get "$@"); then
        if echo -n "$output" | _dotsecenv_clipboard_copy; then
            echo "dotsecenv: secret copied to clipboard" >&2
        else
            return 1
        fi
    else
        return 1
    fi
}

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

# Track secrets loaded from .secenv (reset per directory change)
declare -g -a _DOTSECENV_SECRETS_LOADED=()

# Stack of directories with loaded .secenv (ordered ancestor → descendant)
# Used for tree-scoped secret loading
declare -g -a _DOTSECENV_SOURCE_STACK=()

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

# Check if child_dir is a subdirectory of parent_dir (or the same)
_dotsecenv_is_subdir() {
    local parent="${1%/}"
    local child="${2%/}"
    [[ "$child" == "$parent" || "$child" == "$parent/"* ]]
}

# Stack operations for tree-scoped loading
_dotsecenv_stack_push() {
    _DOTSECENV_SOURCE_STACK+=("$1")
}

_dotsecenv_stack_pop() {
    # Remove last element from stack
    # Note: zsh's unset 'arr[-1]' empties the element but doesn't shrink
    # the array inside functions, so use slice reassignment instead
    local len=${#_DOTSECENV_SOURCE_STACK[@]}
    if [[ $len -eq 0 ]]; then
        return
    elif [[ -n "$ZSH_VERSION" ]]; then
        _DOTSECENV_SOURCE_STACK=("${_DOTSECENV_SOURCE_STACK[@]:0:$((len - 1))}")
    else
        unset '_DOTSECENV_SOURCE_STACK[-1]'
    fi
}

_dotsecenv_stack_top() {
    local len=${#_DOTSECENV_SOURCE_STACK[@]}
    if [[ $len -gt 0 ]]; then
        echo "${_DOTSECENV_SOURCE_STACK[-1]}"
    fi
}

# Check if a file passes security checks
# Returns 0 if safe, 1 if unsafe
_dotsecenv_security_check() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    # Get file stats - detect stat variant
    # Note: Must initialize to avoid zsh printing existing values
    local file_owner="" file_perms=""
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
    echo "$dir" >>"$DOTSECENV_TRUSTED_DIRS_FILE"
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
    y | yes)
        _dotsecenv_trust_session "$dir"
        return 0
        ;;
    a | always)
        _dotsecenv_trust_always "$dir"
        return 0
        ;;
    n | no | *)
        _dotsecenv_deny_session "$dir"
        return 1
        ;;
    esac
}

# Parse a line from .secenv file
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
            elif [[ "$value" == \{dotsecenv/*\} ]]; then
                # Extract secret name (everything between first / and closing })
                local secret_name="${value#\{dotsecenv/}"
                secret_name="${secret_name%\}}"
                # Validate: no additional slashes, valid secret name format
                if [[ -z "$secret_name" ]]; then
                    # Empty name like {dotsecenv/} - treat same as {dotsecenv}
                    _DOTSECENV_PARSE_VALUE="$_DOTSECENV_PARSE_KEY"
                    _DOTSECENV_PARSE_TYPE="secret_same"
                elif [[ "$secret_name" == */* ]]; then
                    echo "dotsecenv: error: invalid syntax '$value' - only one '/' allowed" >&2
                    return 1
                elif [[ "$secret_name" =~ ^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)?$ ]]; then
                    _DOTSECENV_PARSE_VALUE="$secret_name"
                    _DOTSECENV_PARSE_TYPE="secret_named"
                else
                    echo "dotsecenv: error: invalid secret name '$secret_name' in '$value'" >&2
                    return 1
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

# Load a single .secenv file
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

            elif [[ "$phase" == "2" && ("$ptype" == "secret_same" || "$ptype" == "secret_named") ]]; then
                # Phase 2: load secrets via dotsecenv CLI
                local secret_name="$value"

                # Fetch secret from vault (capture stderr separately to preserve secret value)
                # Note: Initialize to empty to prevent zsh from printing existing values on re-declaration
                local secret_result="" secret_stderr_file=""
                secret_stderr_file=$(mktemp)
                if secret_result=$(dotsecenv secret get "$secret_name" 2>"$secret_stderr_file"); then
                    export "$key=$secret_result"
                    _dotsecenv_array_append "$vars_var" "$key"
                    _DOTSECENV_SECRETS_LOADED+=("$key")
                    # Show any warnings that were emitted
                    [[ -s "$secret_stderr_file" ]] && cat "$secret_stderr_file" >&2
                    # Warn if value contains newlines
                    if [[ "$secret_result" == *$'\n'* ]]; then
                        echo "dotsecenv: warning: $key contains newlines; always quote it: \"\$$key\"" >&2
                    fi
                else
                    echo "dotsecenv: error fetching secret '$secret_name' for $key:" >&2
                    cat "$secret_stderr_file" >&2
                fi
                rm -f "$secret_stderr_file"
            fi
        fi
    done <"$file"
}

# Unload variables for a directory and return list of unloaded keys
# Sets _DOTSECENV_UNLOADED_KEYS array with the keys that were unloaded
_dotsecenv_unload_dir() {
    local dir="$1"
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$dir")
    local vars_var="_DOTSECENV_LOADED_${dir_hash}"
    local secrets_var="_DOTSECENV_SECRETS_${dir_hash}"

    # Reset the unloaded keys tracking
    _DOTSECENV_UNLOADED_KEYS=()

    # Report secrets being unloaded before clearing them
    if eval "[[ \${#${secrets_var}[@]} -gt 0 ]]" 2>/dev/null; then
        local secrets_list="" secret_count=0
        eval "secret_count=\${#${secrets_var}[@]}"
        eval "secrets_list=\$(IFS=', '; echo \"\${${secrets_var}[*]}\")"
        echo "dotsecenv: unloaded $secret_count secret(s): $secrets_list" >&2
        unset "$secrets_var"
    fi

    # Check if the tracking variable exists and unload vars
    # Use eval for zsh/bash compatibility
    if eval "[[ \${#${vars_var}[@]} -gt 0 ]]" 2>/dev/null; then
        local var=""
        eval "for var in \"\${${vars_var}[@]}\"; do _DOTSECENV_UNLOADED_KEYS+=(\"\$var\"); unset \"\$var\"; done"
        unset "$vars_var"
    fi
}

# Re-fetch a specific secret key from a directory's .secenv file
# Used when restoring a shadowed value after popping a child directory
_dotsecenv_refetch_key() {
    local dir="$1"
    local target_key="$2"
    local file="$dir/.secenv"

    [[ -f "$file" ]] || return 1

    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        if _dotsecenv_parse_line "$line"; then
            local key="$_DOTSECENV_PARSE_KEY"
            local value="$_DOTSECENV_PARSE_VALUE"
            local ptype="$_DOTSECENV_PARSE_TYPE"

            if [[ "$key" == "$target_key" ]]; then
                if [[ "$ptype" == "secret_same" || "$ptype" == "secret_named" ]]; then
                    local secret_name="$value"
                    local secret_result="" secret_stderr_file=""
                    secret_stderr_file=$(mktemp)
                    if secret_result=$(dotsecenv secret get "$secret_name" 2>"$secret_stderr_file"); then
                        export "$key=$secret_result"
                        [[ -s "$secret_stderr_file" ]] && cat "$secret_stderr_file" >&2
                        if [[ "$secret_result" == *$'\n'* ]]; then
                            echo "dotsecenv: warning: $key contains newlines; always quote it: \"\$$key\"" >&2
                        fi
                    fi
                    rm -f "$secret_stderr_file"
                elif [[ "$ptype" == "plain" ]]; then
                    export "$key=$value"
                fi
                return 0
            fi
        fi
    done <"$file"
    return 1
}

# Check if a key is defined in a directory's .secenv file
_dotsecenv_dir_has_key() {
    local dir="$1"
    local target_key="$2"
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$dir")
    local vars_var="_DOTSECENV_LOADED_${dir_hash}"

    # Check if the key is in the loaded vars for this directory
    if eval "[[ \${#${vars_var}[@]} -gt 0 ]]" 2>/dev/null; then
        local var=""
        eval "for var in \"\${${vars_var}[@]}\"; do [[ \"\$var\" == \"$target_key\" ]] && return 0; done"
    fi
    return 1
}

# Main function to process directory change (tree-scoped loading)
# Arguments: old_dir, new_dir
# Note: old_dir kept for interface compatibility but unused (we use stack-based tracking)
_dotsecenv_on_cd() {
    # shellcheck disable=SC2034
    local old_dir="$1"
    local new_dir="$2"

    # =========================================================================
    # PHASE 1: POP - Unload directories we've left
    # Walk stack from top (deepest) to bottom, pop entries we're no longer under
    # =========================================================================
    # Note: Must initialize to avoid zsh printing existing values
    local i=0 stack_dir=""
    local stack_len=${#_DOTSECENV_SOURCE_STACK[@]}

    # Iterate from the end of the stack (deepest directory) backwards
    # Note: zsh arrays are 1-indexed, bash arrays are 0-indexed
    local start_idx=0 end_idx=0
    if [[ -n "$ZSH_VERSION" ]]; then
        start_idx=$stack_len
        end_idx=1
    else
        start_idx=$((stack_len - 1))
        end_idx=0
    fi

    for ((i = start_idx; i >= end_idx; i--)); do
        stack_dir="${_DOTSECENV_SOURCE_STACK[$i]}"

        if ! _dotsecenv_is_subdir "$stack_dir" "$new_dir"; then
            # We've left this directory tree - pop and unload
            _dotsecenv_stack_pop
            _dotsecenv_unload_dir "$stack_dir"

            # Re-fetch any keys that were shadowed by this directory
            # (i.e., keys that exist in a remaining ancestor)
            local unloaded_key
            for unloaded_key in "${_DOTSECENV_UNLOADED_KEYS[@]}"; do
                # Check remaining stack entries (ancestors) for this key
                # Note: Must initialize to avoid zsh printing existing values
                local j=0 ancestor_dir=""
                local inner_end_idx=$((end_idx))
                for ((j = i - 1; j >= inner_end_idx; j--)); do
                    ancestor_dir="${_DOTSECENV_SOURCE_STACK[$j]}"
                    if _dotsecenv_dir_has_key "$ancestor_dir" "$unloaded_key"; then
                        # Re-fetch from the ancestor's .secenv
                        _dotsecenv_refetch_key "$ancestor_dir" "$unloaded_key"
                        break
                    fi
                done
            done
        else
            # Still under this directory - stop popping
            break
        fi
    done

    # =========================================================================
    # PHASE 2: RELOAD check - Only reload if we returned from OUTSIDE the tree
    # (If we're navigating within the tree, e.g. subdir -> parent, don't reload)
    # =========================================================================
    stack_len=${#_DOTSECENV_SOURCE_STACK[@]}
    if [[ $stack_len -gt 0 ]]; then
        local top_dir="${_DOTSECENV_SOURCE_STACK[-1]}"
        if [[ "$new_dir" == "$top_dir" ]]; then
            # Only reload if we came from outside this directory's tree
            if [[ -n "$old_dir" ]] && ! _dotsecenv_is_subdir "$top_dir" "$old_dir"; then
                # We returned from outside - pop and reload fresh
                _dotsecenv_stack_pop
                _dotsecenv_unload_dir "$top_dir"
            else
                # Coming from a subdirectory - secrets already loaded, nothing to do
                return 0
            fi
        fi
    fi

    # =========================================================================
    # PHASE 3: Check if we're in a subtree with no new .secenv to load
    # =========================================================================
    local has_secenv=0
    [[ -f "$new_dir/.secenv" ]] && has_secenv=1

    stack_len=${#_DOTSECENV_SOURCE_STACK[@]}
    if [[ $stack_len -gt 0 && $has_secenv -eq 0 ]]; then
        # We're in a subtree of an existing source directory with no new .secenv
        # Secrets persist - nothing to do
        return 0
    fi

    # =========================================================================
    # PHASE 4: PUSH - Load .secenv if present
    # =========================================================================
    if [[ $has_secenv -eq 0 ]]; then
        return 0
    fi

    # Initialize the loaded vars array for this directory
    local dir_hash
    dir_hash=$(_dotsecenv_dir_hash "$new_dir")
    eval "_DOTSECENV_LOADED_${dir_hash}=()"

    # Security check for .secenv
    if ! _dotsecenv_security_check "$new_dir/.secenv"; then
        return 0
    fi

    # Trust check for .secenv
    local should_load=0
    _dotsecenv_is_trusted "$new_dir"
    local trust_status=$?

    if [[ $trust_status -eq 0 ]]; then
        should_load=1
    elif [[ $trust_status -eq 2 ]]; then
        # Denied this session
        return 0
    else
        # Not trusted, prompt user
        if _dotsecenv_prompt_trust "$new_dir"; then
            should_load=1
        fi
    fi

    if [[ $should_load -eq 0 ]]; then
        return 0
    fi

    # Phase 1: Load plain variables from .secenv
    _dotsecenv_load_file "$new_dir/.secenv" 1 "$new_dir"

    # Phase 2: Load secrets from .secenv
    _DOTSECENV_SECRETS_LOADED=()
    _dotsecenv_load_file "$new_dir/.secenv" 2 "$new_dir"

    if [[ ${#_DOTSECENV_SECRETS_LOADED[@]} -gt 0 ]]; then
        # Track secrets per directory for unload reporting
        local secrets_var="_DOTSECENV_SECRETS_${dir_hash}"
        eval "${secrets_var}=()"
        local secret_key
        for secret_key in "${_DOTSECENV_SECRETS_LOADED[@]}"; do
            _dotsecenv_array_append "$secrets_var" "$secret_key"
        done
        local keys_list
        keys_list=$(
            IFS=', '
            echo "${_DOTSECENV_SECRETS_LOADED[*]}"
        )
        echo "dotsecenv: loaded ${#_DOTSECENV_SECRETS_LOADED[@]} secret(s) from .secenv: $keys_list" >&2
    fi

    # Push this directory onto the stack if we loaded anything
    local vars_var="_DOTSECENV_LOADED_${dir_hash}"
    if eval "[[ \${#${vars_var}[@]} -gt 0 ]]" 2>/dev/null; then
        _dotsecenv_stack_push "$new_dir"
    fi
}

# Walk up from current directory and load ancestor .secenv files (root-first)
# Arguments: [boundary_dir]
#   boundary_dir: stop walking at this directory (default: git root, fallback: filesystem root)
_dotsecenv_load_ancestors() {
    local original_dir="$PWD"
    local boundary="${1:-}"

    # Determine boundary
    if [[ -z "$boundary" ]]; then
        boundary=$(git rev-parse --show-toplevel 2>/dev/null) || boundary=""
    fi

    # Walk up from current dir (exclusive) to boundary (inclusive), collect dirs with .secenv
    local -a ancestor_secenvs=()
    local dir="$original_dir"
    local parent=""
    while true; do
        parent=$(dirname "$dir")
        [[ "$parent" == "$dir" ]] && break # reached filesystem root
        dir="$parent"
        if [[ -f "$dir/.secenv" ]]; then
            ancestor_secenvs+=("$dir")
        fi
        [[ -n "$boundary" && "$dir" == "$boundary" ]] && break
    done

    # Filter out directories already on the stack
    local -a to_load=()
    local ancestor="" stack_entry="" already_loaded=0
    for ancestor in "${ancestor_secenvs[@]}"; do
        already_loaded=0
        for stack_entry in "${_DOTSECENV_SOURCE_STACK[@]}"; do
            [[ "$stack_entry" == "$ancestor" ]] && {
                already_loaded=1
                break
            }
        done
        [[ $already_loaded -eq 0 ]] && to_load+=("$ancestor")
    done

    if [[ ${#to_load[@]} -eq 0 ]]; then
        echo "dotsecenv: no new ancestor .secenv files found" >&2
        return 0
    fi

    # Process root-first (reverse the collected list) by cd-ing into each directory.
    # Actual cd is required so dotsecenv CLI resolves vault paths relative to the
    # .secenv directory. In zsh, cd triggers chpwd hook automatically. In bash,
    # PROMPT_COMMAND won't fire mid-function so we trigger the hook manually.
    # Note: zsh arrays are 1-indexed, bash arrays are 0-indexed
    local i=0 start_idx=0 end_idx=0
    if [[ -n "$ZSH_VERSION" ]]; then
        start_idx=${#to_load[@]}
        end_idx=1
    else
        start_idx=$((${#to_load[@]} - 1))
        end_idx=0
    fi

    for ((i = start_idx; i >= end_idx; i--)); do
        cd "${to_load[$i]}" || continue
        if [[ -z "$ZSH_VERSION" ]]; then
            _dotsecenv_chpwd_hook
        fi
    done

    # Return to the original directory
    cd "$original_dir" || return 1
    if [[ -z "$ZSH_VERSION" ]]; then
        _dotsecenv_chpwd_hook
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

# Reload all .secenv files - clears stack and re-fetches everything fresh
# Use when vault secrets have been updated and you want to refresh without cd-ing out
_dotsecenv_reload() {
    # Save current stack entries (ancestor → descendant order)
    local -a dirs_to_reload=("${_DOTSECENV_SOURCE_STACK[@]}")

    # Clear the entire stack and unload all variables
    while [[ ${#_DOTSECENV_SOURCE_STACK[@]} -gt 0 ]]; do
        local top="${_DOTSECENV_SOURCE_STACK[-1]}"
        _dotsecenv_stack_pop
        _dotsecenv_unload_dir "$top"
    done

    # Re-load each directory in original order (ancestor → descendant)
    local dir
    for dir in "${dirs_to_reload[@]}"; do
        if [[ -f "$dir/.secenv" ]]; then
            _dotsecenv_on_cd "" "$dir"
        fi
    done

    # Also pick up current dir if it now has .secenv and wasn't previously loaded
    if [[ -f "$PWD/.secenv" ]]; then
        local already_loaded=0
        for dir in "${dirs_to_reload[@]}"; do
            [[ "$dir" == "$PWD" ]] && {
                already_loaded=1
                break
            }
        done
        if [[ $already_loaded -eq 0 ]]; then
            _dotsecenv_on_cd "" "$PWD"
        fi
    fi
}

# Aliases - defined as functions to work in both bash and zsh
dse() {
    case "${1:-}" in
    reload)
        _dotsecenv_reload
        ;;
    get)
        shift
        dotsecenv secret get "$@"
        ;;
    cp)
        shift
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
        ;;
    up)
        shift
        _dotsecenv_load_ancestors "$@"
        ;;
    *)
        dotsecenv "$@"
        ;;
    esac
}

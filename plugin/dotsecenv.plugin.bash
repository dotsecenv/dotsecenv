#!/usr/bin/env bash
# dotsecenv shell plugin for bash
# Automatically loads .env and .secenv files when entering directories
#
# Installation:
#   Source this file in your .bashrc or .bash_profile:
#     source /path/to/dotsecenv.plugin.bash
#
#   Or use a plugin manager (see README.md)

# Guard against multiple loading
[[ -n "$_DOTSECENV_BASH_LOADED" ]] && return
_DOTSECENV_BASH_LOADED=1

# Determine plugin directory
_DOTSECENV_PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the shared core logic
if [[ -f "$_DOTSECENV_PLUGIN_DIR/_dotsecenv_core.sh" ]]; then
    source "$_DOTSECENV_PLUGIN_DIR/_dotsecenv_core.sh"
else
    echo "dotsecenv: error: _dotsecenv_core.sh not found" >&2
    return 1
fi

# Track the previous directory
_DOTSECENV_PREV_PWD=""

# Hook function for directory changes
_dotsecenv_chpwd_hook() {
    local old_dir="$_DOTSECENV_PREV_PWD"
    _DOTSECENV_PREV_PWD="$PWD"
    _dotsecenv_on_cd "$old_dir" "$PWD"
}

# Reload secrets in current directory
reloadsecenv() {
    _dotsecenv_reload
}

# Use PROMPT_COMMAND to detect directory changes (bash has no chpwd hook)
_dotsecenv_prompt_hook() {
    if [[ "$_DOTSECENV_PREV_PWD" != "$PWD" ]]; then
        _dotsecenv_chpwd_hook
    fi
}

# Append to PROMPT_COMMAND without overwriting existing hooks
if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="_dotsecenv_prompt_hook"
elif [[ "$PROMPT_COMMAND" != *"_dotsecenv_prompt_hook"* ]]; then
    PROMPT_COMMAND="_dotsecenv_prompt_hook;$PROMPT_COMMAND"
fi

# Process current directory on plugin load (initial shell startup)
_dotsecenv_chpwd_hook

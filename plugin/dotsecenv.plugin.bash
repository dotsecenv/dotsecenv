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

# Track the previous directory for change detection
_DOTSECENV_PREV_PWD=""

# Hook function called via PROMPT_COMMAND
_dotsecenv_prompt_command() {
    local old_dir="$_DOTSECENV_PREV_PWD"
    local new_dir="$PWD"

    # Update previous directory tracker
    _DOTSECENV_PREV_PWD="$PWD"

    # Skip if directory hasn't actually changed
    [[ "$old_dir" == "$new_dir" ]] && return

    # Process the directory change
    _dotsecenv_on_cd "$old_dir" "$new_dir"
}

# Register the hook via PROMPT_COMMAND
# Prepend our function to ensure it runs before other hooks
if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="_dotsecenv_prompt_command"
else
    # Check if already registered
    if [[ "$PROMPT_COMMAND" != *"_dotsecenv_prompt_command"* ]]; then
        PROMPT_COMMAND="_dotsecenv_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
    fi
fi

# Process current directory on plugin load (initial shell startup)
_dotsecenv_prompt_command

#!/usr/bin/env zsh
# dotsecenv shell plugin for zsh
# Automatically loads .env and .secenv files when entering directories
#
# Installation:
#   Source this file in your .zshrc:
#     source /path/to/dotsecenv.plugin.zsh
#
#   Or use a plugin manager (see README.md)

# Guard against multiple loading
[[ -n "$_DOTSECENV_ZSH_LOADED" ]] && return
_DOTSECENV_ZSH_LOADED=1

# Determine plugin directory
_DOTSECENV_PLUGIN_DIR="${0:A:h}"

# Source the shared core logic
if [[ -f "$_DOTSECENV_PLUGIN_DIR/_dotsecenv_core.sh" ]]; then
    source "$_DOTSECENV_PLUGIN_DIR/_dotsecenv_core.sh"
else
    echo "dotsecenv: error: _dotsecenv_core.sh not found" >&2
    return 1
fi

# Track the previous directory for change detection
typeset -g _DOTSECENV_PREV_PWD=""

# Hook function called on directory change
_dotsecenv_chpwd() {
    local old_dir="$_DOTSECENV_PREV_PWD"
    local new_dir="$PWD"

    # Update previous directory tracker
    _DOTSECENV_PREV_PWD="$PWD"

    # Skip if directory hasn't actually changed
    [[ "$old_dir" == "$new_dir" ]] && return

    # Process the directory change
    _dotsecenv_on_cd "$old_dir" "$new_dir"
}

# Register the hook
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _dotsecenv_chpwd

# Process current directory on plugin load (initial shell startup)
_dotsecenv_chpwd

# secretcp is defined in core.sh for copying secrets to clipboard

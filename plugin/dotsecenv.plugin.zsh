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

# Hook function for directory changes
_dotsecenv_chpwd_hook() {
    local old_dir="$_DOTSECENV_PREV_PWD"
    _DOTSECENV_PREV_PWD="$PWD"
    _dotsecenv_on_cd "$old_dir" "$PWD"
}

# Reload secrets in current directory (for when cd . doesn't trigger chpwd)
reloadsecenv() {
    _dotsecenv_on_cd "$PWD" "$PWD"
}

# Register the chpwd hook using zsh's hook system
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _dotsecenv_chpwd_hook

# Process current directory on plugin load (initial shell startup)
_dotsecenv_chpwd_hook

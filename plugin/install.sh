#!/usr/bin/env bash
# dotsecenv shell plugin installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | bash
#
# Options:
#   --shell=SHELL    Install for specific shell (bash, zsh, fish, or all). Default: all
#   --dir=DIR        Installation directory. Default: ~/.local/share/dotsecenv/plugin
#   --no-rc          Don't modify shell RC files
#   --uninstall      Remove installed plugins

set -euo pipefail

# Configuration
REPO_URL="https://github.com/dotsecenv/plugin.git"
REPO_BRANCH="main"
# The parent directory also holds the CLI's default vault, so the plugin gets its own subdirectory.
LEGACY_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dotsecenv"
DEFAULT_INSTALL_DIR="$LEGACY_DIR/plugin"
# Files this installer copies into the install directory.
PLUGIN_FILES=(dotsecenv.plugin.bash dotsecenv.plugin.zsh dotsecenv.fish _dotsecenv_core.sh)
# Comment the installer writes above each source line.
RC_MARKER="# dotsecenv shell plugin"

# Colors (if terminal supports them)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Logging functions
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse arguments
SHELL_TARGET="all"
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
MODIFY_RC=1
UNINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
    --shell=*)
        SHELL_TARGET="${1#*=}"
        ;;
    --dir=*)
        INSTALL_DIR="${1#*=}"
        ;;
    --no-rc)
        MODIFY_RC=0
        ;;
    --uninstall)
        UNINSTALL=1
        ;;
    -h | --help)
        cat <<EOF
dotsecenv shell plugin installer

Usage:
  install.sh [OPTIONS]

Options:
  --shell=SHELL    Install for specific shell (bash, zsh, fish, or all). Default: all
  --dir=DIR        Installation directory. Default: $DEFAULT_INSTALL_DIR
  --no-rc          Don't modify shell RC files
  --uninstall      Remove installed plugins
  -h, --help       Show this help message

Examples:
  install.sh                      # Install for all shells
  install.sh --shell=zsh          # Install only for zsh
  install.sh --uninstall          # Remove all plugins
EOF
        exit 0
        ;;
    *)
        error "Unknown option: $1"
        exit 1
        ;;
    esac
    shift
done

# Validate shell target
case "$SHELL_TARGET" in
bash | zsh | fish | all) ;;
*)
    error "Invalid shell: $SHELL_TARGET. Must be bash, zsh, fish, or all"
    exit 1
    ;;
esac

# Clone repository to temporary directory
TEMP_DIR=""
clone_repo() {
    if ! command -v git &>/dev/null; then
        error "git is not installed. Please install git first."
        exit 1
    fi

    TEMP_DIR=$(mktemp -d)
    info "Cloning repository..."
    if ! git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$TEMP_DIR" 2>/dev/null; then
        error "Failed to clone repository from $REPO_URL"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
}

# Cleanup temporary directory
cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Get shell RC file path
get_rc_file() {
    local shell="$1"
    case "$shell" in
    bash)
        if [[ -f "$HOME/.bash_profile" ]]; then
            echo "$HOME/.bash_profile"
        else
            echo "$HOME/.bashrc"
        fi
        ;;
    zsh)
        echo "${ZDOTDIR:-$HOME}/.zshrc"
        ;;
    fish)
        echo "${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"
        ;;
    esac
}

# Check if source line already exists in RC file
has_source_line() {
    local rc_file="$1"
    local plugin_path="$2"

    [[ -f "$rc_file" ]] && grep -qF "$plugin_path" "$rc_file"
}

# Add source line to RC file
add_source_line() {
    local shell="$1"
    local rc_file="$2"
    local plugin_path="$3"

    # Create RC file if it doesn't exist
    mkdir -p "$(dirname "$rc_file")"
    touch "$rc_file"

    case "$shell" in
    bash | zsh)
        echo "" >>"$rc_file"
        echo "$RC_MARKER" >>"$rc_file"
        echo "source \"$plugin_path\"" >>"$rc_file"
        ;;
    fish)
        echo "" >>"$rc_file"
        echo "$RC_MARKER" >>"$rc_file"
        echo "source \"$plugin_path\"" >>"$rc_file"
        ;;
    esac
}

# Install plugins for a specific shell
install_shell() {
    local shell="$1"
    local plugin_file
    local plugin_src
    local core_file="_dotsecenv_core.sh"

    case "$shell" in
    bash)
        plugin_file="dotsecenv.plugin.bash"
        plugin_src="$TEMP_DIR/$plugin_file"
        ;;
    zsh)
        plugin_file="dotsecenv.plugin.zsh"
        plugin_src="$TEMP_DIR/$plugin_file"
        ;;
    fish)
        plugin_file="dotsecenv.fish"
        plugin_src="$TEMP_DIR/conf.d/dotsecenv.fish"
        ;;
    esac

    info "Installing $shell plugin..."

    # Create installation directory
    mkdir -p "$INSTALL_DIR"

    # Copy plugin file
    cp "$plugin_src" "$INSTALL_DIR/$plugin_file"
    chmod +x "$INSTALL_DIR/$plugin_file"

    # Copy core file for bash/zsh (shared logic)
    if [[ "$shell" == "bash" || "$shell" == "zsh" ]]; then
        cp "$TEMP_DIR/$core_file" "$INSTALL_DIR/$core_file"
    fi

    if [[ ${MIGRATING:-0} -eq 1 ]]; then
        return 0
    fi

    success "Installed $shell plugin files"

    # Modify RC file
    if [[ $MODIFY_RC -eq 1 ]]; then
        local rc_file
        rc_file=$(get_rc_file "$shell")
        local plugin_path="$INSTALL_DIR/$plugin_file"

        if has_source_line "$rc_file" "$plugin_path"; then
            info "$shell plugin already configured in $rc_file"
        else
            add_source_line "$shell" "$rc_file" "$plugin_path"
            success "Added source line to $rc_file"
        fi
    else
        info "Skipping RC file modification (--no-rc)"
        echo "  To enable, add to your RC file:"
        echo "    source \"$INSTALL_DIR/$plugin_file\""
    fi
}

# True if dir is a git clone of the plugin repository.
is_plugin_clone() {
    local url
    [[ -d "$1/.git" ]] || return 1
    command -v git &>/dev/null || return 1
    url=$(git -C "$1" remote get-url origin 2>/dev/null) || return 1
    [[ "$url" == *dotsecenv/plugin || "$url" == *dotsecenv/plugin.git ]]
}

# True if the plugin was installed straight into LEGACY_DIR, next to the vault.
has_legacy_install() {
    local f
    [[ "$INSTALL_DIR" != "$LEGACY_DIR" ]] || return 1
    is_plugin_clone "$LEGACY_DIR" && return 0
    for f in "${PLUGIN_FILES[@]}"; do
        [[ -f "$LEGACY_DIR/$f" ]] && return 0
    done
    return 1
}

# Remove only what the plugin shipped from dir: the installer's copies and, for a
# plugin clone, its tracked files and .git. Anything else, such as a vault, stays.
remove_plugin_files() {
    local dir="$1" f
    [[ -d "$dir" ]] || return 0
    if is_plugin_clone "$dir"; then
        while IFS= read -r -d '' f; do
            rm -f "$dir/$f"
            if [[ "$f" == */* ]]; then
                (cd "$dir" && rmdir -p "$(dirname "$f")" 2>/dev/null) || true
            fi
        done < <(git -C "$dir" ls-files -z)
        rm -rf "${dir:?}/.git"
    fi
    for f in "${PLUGIN_FILES[@]}"; do
        rm -f "$dir/$f"
    done
}

# Point the installer's exact source lines for from_dir at to_dir. With an empty
# to_dir, delete them and the marker comment right above each. Other lines stay.
rewrite_source_lines() {
    local rc_file="$1" from_dir="$2" to_dir="$3" line f tmp marker=0 ours
    [[ -f "$rc_file" ]] || return 0
    tmp=$(mktemp)
    while IFS= read -r line || [[ -n "$line" ]]; do
        ours=0
        for f in "${PLUGIN_FILES[@]}"; do
            if [[ "$line" == "source \"$from_dir/$f\"" ]]; then
                ours=1
                [[ -n "$to_dir" ]] && line="source \"$to_dir/$f\""
                break
            fi
        done
        if [[ $marker -eq 1 && ! ($ours -eq 1 && -z "$to_dir") ]]; then
            printf '%s\n' "$RC_MARKER"
        fi
        marker=0
        if [[ "$line" == "$RC_MARKER" ]]; then
            marker=1
        elif [[ $ours -eq 0 || -n "$to_dir" ]]; then
            printf '%s\n' "$line"
        fi
    done <"$rc_file" >"$tmp"
    if [[ $marker -eq 1 ]]; then
        printf '%s\n' "$RC_MARKER" >>"$tmp"
    fi
    # cat keeps the rc file's mode, owner and symlink.
    cat "$tmp" >"$rc_file"
    rm -f "$tmp"
}

# Move an install from LEGACY_DIR to INSTALL_DIR and leave the rest of LEGACY_DIR alone.
migrate_legacy_install() {
    local shell rc_file
    has_legacy_install || return 0
    info "Moving the plugin from $LEGACY_DIR to $INSTALL_DIR..."
    # Install every shell so each rewritten source line has a file behind it.
    for shell in bash zsh fish; do
        MIGRATING=1 install_shell "$shell" >/dev/null
    done
    remove_plugin_files "$LEGACY_DIR"
    if [[ $MODIFY_RC -eq 1 ]]; then
        for rc_file in "$HOME/.bashrc" "$HOME/.bash_profile" "$(get_rc_file zsh)" "$(get_rc_file fish)"; do
            rewrite_source_lines "$rc_file" "$LEGACY_DIR" "$INSTALL_DIR"
        done
    else
        warn "Point any source lines for $LEGACY_DIR at $INSTALL_DIR"
    fi
    success "Moved the plugin to $INSTALL_DIR"
    echo ""
}

# Uninstall plugins
uninstall() {
    info "Uninstalling dotsecenv shell plugins..."

    if [[ -d "$INSTALL_DIR" ]]; then
        remove_plugin_files "$INSTALL_DIR"
        if rmdir "$INSTALL_DIR" 2>/dev/null; then
            success "Removed $INSTALL_DIR"
        else
            warn "Removed plugin files but kept $INSTALL_DIR: it holds files the plugin did not install"
        fi
    else
        info "No plugin files found at $INSTALL_DIR"
    fi
    if has_legacy_install; then
        remove_plugin_files "$LEGACY_DIR"
        success "Removed plugin files from $LEGACY_DIR"
    fi

    # Remove the installer's own source lines, for this and the old install path
    local rc_file
    for rc_file in "$HOME/.bashrc" "$HOME/.bash_profile" "$(get_rc_file zsh)" "$(get_rc_file fish)"; do
        if [[ -f "$rc_file" ]]; then
            rewrite_source_lines "$rc_file" "$INSTALL_DIR" ""
            rewrite_source_lines "$rc_file" "$LEGACY_DIR" ""
            success "Cleaned $rc_file"
        fi
    done

    success "Uninstallation complete"
}

# Main
main() {
    echo ""
    echo "dotsecenv shell plugin installer"
    echo "================================="
    echo ""

    if [[ $UNINSTALL -eq 1 ]]; then
        uninstall
        exit 0
    fi

    info "Installation directory: $INSTALL_DIR"
    info "Target shell(s): $SHELL_TARGET"
    echo ""

    # Clone the repository first
    clone_repo
    migrate_legacy_install

    case "$SHELL_TARGET" in
    all)
        install_shell "bash"
        echo ""
        install_shell "zsh"
        echo ""
        install_shell "fish"
        ;;
    *)
        install_shell "$SHELL_TARGET"
        ;;
    esac

    echo ""
    success "Installation complete!"
    echo ""
    echo "Please restart your shell or run:"
    case "$SHELL_TARGET" in
    bash)
        echo "  source $(get_rc_file bash)"
        ;;
    zsh)
        echo "  source $(get_rc_file zsh)"
        ;;
    fish)
        echo "  source $(get_rc_file fish)"
        ;;
    all)
        echo "  source your shell's RC file"
        ;;
    esac
    echo ""
}

main

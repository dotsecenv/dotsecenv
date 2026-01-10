#!/usr/bin/env bash
#
# sandbox.sh - Unified isolated environment helper for dotsecenv
#
# Creates a completely isolated sandbox environment for:
# - Demo recordings
# - E2E tests
# - Manual testing
#
# Usage:
#   sandbox.sh [OPTIONS]           Create and enter a new sandbox
#   sandbox.sh list                List persistent sessions
#   sandbox.sh enter <session>     Re-enter a persistent session
#   sandbox.sh destroy <session>   Clean up a persistent session
#   sandbox.sh destroy --all       Clean up all persistent sessions
#
set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLUGIN_DIR="$(dirname "$PROJECT_DIR")/plugin"
REGISTRY_DIR="${HOME}/.local/share/dotsecenv-sandbox"
REGISTRY_FILE="${REGISTRY_DIR}/sessions.json"

# =============================================================================
# Helper Functions
# =============================================================================

usage() {
    cat <<EOF
Usage: sandbox.sh [OPTIONS] | COMMAND [ARGS]

Create and manage isolated dotsecenv sandbox environments.

OPTIONS:
  --session NAME    Use specific session name (default: auto-generated)
  --persistent      Keep sandbox after shell exit (default: ephemeral)
  --no-keys         Skip GPG key generation
  --no-plugin       Skip plugin installation
  --shell SHELL     Shell to launch: bash, zsh, fish (default: zsh)
  --binary PATH     Path to dotsecenv binary (default: auto-detect from build)
  -h, --help        Show this help message

COMMANDS:
  list              List all persistent sessions
  enter <session>   Re-enter a persistent session
  destroy <session> Clean up a persistent session
  destroy --all     Clean up all persistent sessions

ENVIRONMENT:
  Creates a completely isolated environment:
  - HOME, GNUPGHOME, XDG_CONFIG_HOME, XDG_DATA_HOME, XDG_STATE_HOME, XDG_CACHE_HOME
  - GPG keys: RSA 3072, RSA 4096, ECDSA P-384, Ed25519
  - Fingerprints exported as: GPG_FP_RSA3072, GPG_FP_RSA4096, GPG_FP_P384, GPG_FP_ED25519
  - DEFAULT_GPG_KEY points to Ed25519 fingerprint

EXAMPLES:
  # Create ephemeral sandbox (deleted on exit)
  sandbox.sh

  # Create persistent sandbox with custom name
  sandbox.sh --session mytest --persistent

  # Create sandbox without GPG keys (faster)
  sandbox.sh --no-keys

  # Create sandbox with bash instead of zsh
  sandbox.sh --shell bash

  # Re-enter existing persistent session
  sandbox.sh enter mytest

  # Clean up a specific session
  sandbox.sh destroy mytest
EOF
}

log() {
    echo "==> $*" >&2
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

generate_session_name() {
    echo "sandbox-$(head -c 6 /dev/urandom | xxd -p)"
}

# =============================================================================
# Session Registry Functions
# =============================================================================

registry_init() {
    mkdir -p "$REGISTRY_DIR"
    if [[ ! -f "$REGISTRY_FILE" ]]; then
        echo '{}' > "$REGISTRY_FILE"
    fi
}

registry_add() {
    local name="$1"
    local path="$2"
    registry_init
    # Use portable JSON manipulation without jq
    local tmp
    tmp=$(mktemp)
    if command -v jq &>/dev/null; then
        jq --arg name "$name" --arg path "$path" '. + {($name): $path}' "$REGISTRY_FILE" > "$tmp"
    else
        # Fallback: simple string manipulation (works for our simple case)
        local content
        content=$(cat "$REGISTRY_FILE")
        if [[ "$content" == "{}" ]]; then
            echo "{\"$name\": \"$path\"}" > "$tmp"
        else
            # Insert before closing brace
            echo "${content%\}}, \"$name\": \"$path\"}" > "$tmp"
        fi
    fi
    mv "$tmp" "$REGISTRY_FILE"
}

registry_remove() {
    local name="$1"
    if [[ ! -f "$REGISTRY_FILE" ]]; then
        return
    fi
    if command -v jq &>/dev/null; then
        local tmp
        tmp=$(mktemp)
        jq --arg name "$name" 'del(.[$name])' "$REGISTRY_FILE" > "$tmp"
        mv "$tmp" "$REGISTRY_FILE"
    else
        # Fallback: recreate without the entry
        log "Warning: jq not installed, session registry cleanup may be incomplete"
    fi
}

registry_get() {
    local name="$1"
    if [[ ! -f "$REGISTRY_FILE" ]]; then
        return 1
    fi
    if command -v jq &>/dev/null; then
        local path
        path=$(jq -r --arg name "$name" '.[$name] // empty' "$REGISTRY_FILE")
        if [[ -n "$path" && -d "$path" ]]; then
            echo "$path"
            return 0
        fi
    fi
    return 1
}

registry_list() {
    registry_init
    if command -v jq &>/dev/null; then
        jq -r 'to_entries[] | "\(.key)\t\(.value)"' "$REGISTRY_FILE" 2>/dev/null | while IFS=$'\t' read -r name path; do
            if [[ -d "$path" ]]; then
                echo "$name  →  $path"
            else
                echo "$name  →  (missing: $path)"
            fi
        done
    else
        cat "$REGISTRY_FILE"
    fi
}

registry_all_paths() {
    if [[ ! -f "$REGISTRY_FILE" ]]; then
        return
    fi
    if command -v jq &>/dev/null; then
        jq -r 'to_entries[] | "\(.key)\t\(.value)"' "$REGISTRY_FILE" 2>/dev/null
    fi
}

# =============================================================================
# GPG Key Generation
# =============================================================================

generate_gpg_keys() {
    local gnupghome="$1"

    log "Generating GPG keys in $gnupghome"

    # Common batch options (exclude 3DES for GPG 2.4+)
    local prefs="Preferences: AES256 SHA512 Uncompressed"

    # RSA 3072
    log "  Creating RSA 3072 key..."
    GNUPGHOME="$gnupghome" gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 3072
$prefs
Name-Real: Test RSA 3072
Name-Email: test-rsa3072@sandbox.dotsecenv
%no-protection
%commit
EOF

    # RSA 4096
    log "  Creating RSA 4096 key..."
    GNUPGHOME="$gnupghome" gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
$prefs
Name-Real: Test RSA 4096
Name-Email: test-rsa4096@sandbox.dotsecenv
%no-protection
%commit
EOF

    # ECDSA P-384 (NIST curve)
    log "  Creating ECDSA P-384 key..."
    GNUPGHOME="$gnupghome" gpg --batch --gen-key <<EOF
Key-Type: ECDSA
Key-Curve: nistp384
$prefs
Name-Real: Test ECDSA P-384
Name-Email: test-p384@sandbox.dotsecenv
%no-protection
%commit
EOF

    # Ed25519 (modern, fast)
    log "  Creating Ed25519 key..."
    GNUPGHOME="$gnupghome" gpg --batch --gen-key <<EOF
Key-Type: EDDSA
Key-Curve: ed25519
$prefs
Name-Real: Test Ed25519
Name-Email: test-ed25519@sandbox.dotsecenv
%no-protection
%commit
EOF

    log "GPG keys generated successfully"
}

get_fingerprint() {
    local gnupghome="$1"
    local email="$2"
    GNUPGHOME="$gnupghome" gpg --list-keys --with-colons "$email" 2>/dev/null | \
        awk -F: '/^fpr:/{print $10; exit}'
}

# =============================================================================
# Plugin Installation
# =============================================================================

install_plugins() {
    local sandbox_home="$1"
    local xdg_data="$2"
    local xdg_config="$3"

    log "Installing dotsecenv plugins"

    local plugin_dest="$xdg_data/dotsecenv"
    mkdir -p "$plugin_dest"
    mkdir -p "$xdg_config/fish/conf.d"

    # Copy plugin files
    if [[ -d "$PLUGIN_DIR" ]]; then
        log "  Copying from $PLUGIN_DIR"
        cp "$PLUGIN_DIR/_dotsecenv_core.sh" "$plugin_dest/" 2>/dev/null || true
        cp "$PLUGIN_DIR/dotsecenv.plugin.bash" "$plugin_dest/" 2>/dev/null || true
        cp "$PLUGIN_DIR/dotsecenv.plugin.zsh" "$plugin_dest/" 2>/dev/null || true
        cp "$PLUGIN_DIR/conf.d/dotsecenv.fish" "$xdg_config/fish/conf.d/" 2>/dev/null || true
    else
        log "  Warning: Plugin directory not found at $PLUGIN_DIR"
        log "  Shell integration will not be available"
        return 1
    fi

    log "Plugins installed successfully"
    return 0
}

# =============================================================================
# Shell Configuration
# =============================================================================

generate_shell_configs() {
    local sandbox_home="$1"
    local session_name="$2"
    local fp_rsa3072="$3"
    local fp_rsa4096="$4"
    local fp_p384="$5"
    local fp_ed25519="$6"
    local has_plugin="$7"

    log "Generating shell configurations"

    local xdg_config="$sandbox_home/.config"
    local xdg_data="$sandbox_home/.local/share"

    # Common env vars for bash/zsh
    local env_vars
    env_vars=$(cat <<EOF
# Sandbox session: $session_name
export PATH="\$HOME/bin:\$PATH"
export XDG_CONFIG_HOME="\$HOME/.config"
export XDG_DATA_HOME="\$HOME/.local/share"
export XDG_STATE_HOME="\$HOME/.local/state"
export XDG_CACHE_HOME="\$HOME/.cache"
export GNUPGHOME="\$HOME/.gnupg"
export GPG_TTY=\$(tty)
EOF
)

    # GPG fingerprint exports (if keys were generated)
    local gpg_vars=""
    if [[ -n "$fp_ed25519" ]]; then
        gpg_vars=$(cat <<EOF

# GPG Key Fingerprints
export GPG_FP_RSA3072="$fp_rsa3072"
export GPG_FP_RSA4096="$fp_rsa4096"
export GPG_FP_P384="$fp_p384"
export GPG_FP_ED25519="$fp_ed25519"
export DEFAULT_GPG_KEY="\$GPG_FP_ED25519"
EOF
)
    fi

    # Plugin sourcing
    local bash_plugin=""
    local zsh_plugin=""
    local fish_plugin=""

    if [[ "$has_plugin" == "true" ]]; then
        bash_plugin='
# dotsecenv plugin
if [[ -f "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.bash" ]]; then
    source "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.bash"
fi'
        zsh_plugin='
# dotsecenv plugin
if [[ -f "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.zsh" ]]; then
    source "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.zsh"
fi'
        fish_plugin='
# dotsecenv plugin
if test -f $XDG_DATA_HOME/dotsecenv/conf.d/dotsecenv.fish
    source $XDG_DATA_HOME/dotsecenv/conf.d/dotsecenv.fish
end'
    fi

    # Session banner
    local banner
    banner=$(cat <<'EOF'

# Session info
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
printf "│ %-59s │\n" "Sandbox: SESSION_NAME"
printf "│ %-59s │\n" "HOME: $HOME"
EOF
)
    banner="${banner//SESSION_NAME/$session_name}"

    if [[ -n "$fp_ed25519" ]]; then
        banner+='
printf "│ %-59s │\n" "Default GPG: $DEFAULT_GPG_KEY"'
    fi
    banner+='
echo "└─────────────────────────────────────────────────────────────┘"
echo ""'

    # Write .bashrc
    cat > "$sandbox_home/.bashrc" <<EOF
$env_vars
$gpg_vars
$bash_plugin
$banner
EOF

    # Write .zshrc
    cat > "$sandbox_home/.zshrc" <<EOF
$env_vars
$gpg_vars
$zsh_plugin
$banner
EOF

    # Write fish config
    mkdir -p "$xdg_config/fish"
    cat > "$xdg_config/fish/config.fish" <<EOF
# Sandbox session: $session_name
fish_add_path \$HOME/bin
set -gx XDG_CONFIG_HOME \$HOME/.config
set -gx XDG_DATA_HOME \$HOME/.local/share
set -gx XDG_STATE_HOME \$HOME/.local/state
set -gx XDG_CACHE_HOME \$HOME/.cache
set -gx GNUPGHOME \$HOME/.gnupg
set -gx GPG_TTY (tty)
EOF

    if [[ -n "$fp_ed25519" ]]; then
        cat >> "$xdg_config/fish/config.fish" <<EOF

# GPG Key Fingerprints
set -gx GPG_FP_RSA3072 "$fp_rsa3072"
set -gx GPG_FP_RSA4096 "$fp_rsa4096"
set -gx GPG_FP_P384 "$fp_p384"
set -gx GPG_FP_ED25519 "$fp_ed25519"
set -gx DEFAULT_GPG_KEY \$GPG_FP_ED25519
EOF
    fi

    if [[ "$has_plugin" == "true" ]]; then
        cat >> "$xdg_config/fish/config.fish" <<EOF
$fish_plugin
EOF
    fi

    # Fish banner (different syntax)
    cat >> "$xdg_config/fish/config.fish" <<EOF

# Session info
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
printf "│ %-59s │\n" "Sandbox: $session_name"
printf "│ %-59s │\n" "HOME: \$HOME"
EOF
    if [[ -n "$fp_ed25519" ]]; then
        echo 'printf "│ %-59s │\n" "Default GPG: $DEFAULT_GPG_KEY"' >> "$xdg_config/fish/config.fish"
    fi
    cat >> "$xdg_config/fish/config.fish" <<EOF
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
EOF

    log "Shell configurations generated"
}

# =============================================================================
# Sandbox Creation
# =============================================================================

create_sandbox() {
    local session_name="$1"
    local persistent="$2"
    local no_keys="$3"
    local no_plugin="$4"
    local shell="$5"
    local binary_path="$6"

    # Create sandbox directory
    local sandbox_home
    sandbox_home=$(mktemp -d -t "dotsecenv-sandbox-XXXXXX")

    log "Creating sandbox: $session_name"
    log "  Location: $sandbox_home"

    # Create directory structure
    mkdir -p "$sandbox_home/.gnupg"
    mkdir -p "$sandbox_home/.config"
    mkdir -p "$sandbox_home/.local/share"
    mkdir -p "$sandbox_home/.local/state"
    mkdir -p "$sandbox_home/.cache"
    mkdir -p "$sandbox_home/bin"

    # Set permissions
    chmod 700 "$sandbox_home/.gnupg"

    # Deploy binary
    if [[ -n "$binary_path" && -f "$binary_path" ]]; then
        cp "$binary_path" "$sandbox_home/bin/dotsecenv"
        chmod +x "$sandbox_home/bin/dotsecenv"
        log "  Binary deployed: $sandbox_home/bin/dotsecenv"
    elif [[ -f "$PROJECT_DIR/bin/dotsecenv" ]]; then
        cp "$PROJECT_DIR/bin/dotsecenv" "$sandbox_home/bin/dotsecenv"
        chmod +x "$sandbox_home/bin/dotsecenv"
        log "  Binary deployed: $sandbox_home/bin/dotsecenv"
    else
        log "  Warning: No dotsecenv binary found. Run 'make build' first."
    fi

    # XDG paths
    local xdg_config="$sandbox_home/.config"
    local xdg_data="$sandbox_home/.local/share"

    # Generate GPG keys
    local fp_rsa3072="" fp_rsa4096="" fp_p384="" fp_ed25519=""
    if [[ "$no_keys" != "true" ]]; then
        generate_gpg_keys "$sandbox_home/.gnupg"
        fp_rsa3072=$(get_fingerprint "$sandbox_home/.gnupg" "test-rsa3072@sandbox.dotsecenv")
        fp_rsa4096=$(get_fingerprint "$sandbox_home/.gnupg" "test-rsa4096@sandbox.dotsecenv")
        fp_p384=$(get_fingerprint "$sandbox_home/.gnupg" "test-p384@sandbox.dotsecenv")
        fp_ed25519=$(get_fingerprint "$sandbox_home/.gnupg" "test-ed25519@sandbox.dotsecenv")
    fi

    # Install plugins
    local has_plugin="false"
    if [[ "$no_plugin" != "true" ]]; then
        if install_plugins "$sandbox_home" "$xdg_data" "$xdg_config"; then
            has_plugin="true"
        fi
    fi

    # Generate shell configs
    generate_shell_configs "$sandbox_home" "$session_name" \
        "$fp_rsa3072" "$fp_rsa4096" "$fp_p384" "$fp_ed25519" "$has_plugin"

    # Register persistent session
    if [[ "$persistent" == "true" ]]; then
        registry_add "$session_name" "$sandbox_home"
        log "Session registered as persistent"
    fi

    # Export sandbox path for caller
    echo "$sandbox_home"
}

enter_sandbox() {
    local sandbox_home="$1"
    local session_name="$2"
    local shell="$3"
    local persistent="$4"

    # Cleanup trap for ephemeral sessions
    if [[ "$persistent" != "true" ]]; then
        # shellcheck disable=SC2064
        trap "log 'Cleaning up ephemeral sandbox: $sandbox_home'; rm -rf '$sandbox_home'" EXIT
    fi

    log "Entering sandbox with $shell"
    log "  HOME=$sandbox_home"
    echo ""

    # Launch shell with complete isolation
    HOME="$sandbox_home" \
    GNUPGHOME="$sandbox_home/.gnupg" \
    XDG_CONFIG_HOME="$sandbox_home/.config" \
    XDG_DATA_HOME="$sandbox_home/.local/share" \
    XDG_STATE_HOME="$sandbox_home/.local/state" \
    XDG_CACHE_HOME="$sandbox_home/.cache" \
    SANDBOX_SESSION="$session_name" \
    "$shell" -i

    log "Exited sandbox"
}

# =============================================================================
# Commands
# =============================================================================

cmd_list() {
    log "Persistent sandbox sessions:"
    echo ""
    registry_list
}

cmd_enter() {
    local session_name="$1"
    local shell="$2"

    if [[ -z "$session_name" ]]; then
        error "Session name required. Usage: sandbox.sh enter <session>"
    fi

    local sandbox_home
    sandbox_home=$(registry_get "$session_name") || error "Session '$session_name' not found"

    if [[ ! -d "$sandbox_home" ]]; then
        error "Session directory no longer exists: $sandbox_home"
    fi

    log "Re-entering session: $session_name"
    enter_sandbox "$sandbox_home" "$session_name" "$shell" "true"
}

cmd_destroy() {
    local target="$1"

    if [[ "$target" == "--all" ]]; then
        log "Destroying all persistent sessions"
        registry_all_paths | while IFS=$'\t' read -r name path; do
            if [[ -n "$path" && -d "$path" ]]; then
                log "  Removing: $name ($path)"
                rm -rf "$path"
            fi
            registry_remove "$name"
        done
        # Clean registry
        echo '{}' > "$REGISTRY_FILE"
        log "All sessions destroyed"
    elif [[ -n "$target" ]]; then
        local sandbox_home
        sandbox_home=$(registry_get "$target") || error "Session '$target' not found"

        log "Destroying session: $target"
        if [[ -d "$sandbox_home" ]]; then
            rm -rf "$sandbox_home"
        fi
        registry_remove "$target"
        log "Session destroyed"
    else
        error "Session name or --all required. Usage: sandbox.sh destroy <session|--all>"
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    local session_name=""
    local persistent="false"
    local no_keys="false"
    local no_plugin="false"
    local shell="zsh"
    local binary_path=""
    local command=""
    local command_arg=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            list|enter|destroy)
                command="$1"
                shift
                command_arg="${1:-}"
                [[ -n "$command_arg" ]] && shift
                break
                ;;
            --session)
                session_name="$2"
                shift 2
                ;;
            --persistent)
                persistent="true"
                shift
                ;;
            --no-keys)
                no_keys="true"
                shift
                ;;
            --no-plugin)
                no_plugin="true"
                shift
                ;;
            --shell)
                shell="$2"
                shift 2
                ;;
            --binary)
                binary_path="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done

    # Validate shell
    case "$shell" in
        bash|zsh|fish) ;;
        *) error "Invalid shell: $shell. Must be bash, zsh, or fish." ;;
    esac

    # Execute command
    case "$command" in
        list)
            cmd_list
            ;;
        enter)
            cmd_enter "$command_arg" "$shell"
            ;;
        destroy)
            cmd_destroy "$command_arg"
            ;;
        "")
            # Default: create new sandbox
            [[ -z "$session_name" ]] && session_name=$(generate_session_name)

            local sandbox_home
            sandbox_home=$(create_sandbox "$session_name" "$persistent" "$no_keys" "$no_plugin" "$shell" "$binary_path")

            enter_sandbox "$sandbox_home" "$session_name" "$shell" "$persistent"
            ;;
    esac
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

# dotsecenv universal installer
# Usage:
#   curl -fsSL https://get.dotsecenv.com/install.sh | bash -s -- --version v1.2.3
#   curl -fsSL https://raw.githubusercontent.com/dotsecenv/dotsecenv/main/scripts/install.sh | bash

readonly GITHUB_ORG="dotsecenv"
readonly GITHUB_REPO="dotsecenv"
readonly GPG_KEY_URL="https://get.dotsecenv.com/key.asc"

# ---------------------------------------------------------------------------
# Color setup (conditional on tty)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    RESET=''
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
info()    { printf "${BLUE}==>${RESET} %s\n" "$*"; }
success() { printf "${GREEN}==>${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}warning:${RESET} %s\n" "$*" >&2; }
error()   { printf "${RED}error:${RESET} %s\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Defaults (overridable via env vars)
# ---------------------------------------------------------------------------
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-}"
INSTALL_SHELL_PLUGIN="${INSTALL_SHELL_PLUGIN:-1}"
INSTALL_TF_CREDENTIALS_HELPER="${INSTALL_TF_CREDENTIALS_HELPER:-1}"
INSTALL_COMPLETIONS="${INSTALL_COMPLETIONS:-1}"
INSTALL_MAN_PAGES="${INSTALL_MAN_PAGES:-1}"
SYSTEM_INSTALL="${SYSTEM_INSTALL:-0}"
VERIFY="${VERIFY:-1}"

TMPDIR_ROOT=""
PLUGIN_LOCATIONS=()

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    if [ -n "${TMPDIR_ROOT}" ] && [ -d "${TMPDIR_ROOT}" ]; then
        rm -rf "${TMPDIR_ROOT}"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Utility: sudo helpers
# ---------------------------------------------------------------------------
need_sudo() {
    local dir="$1"
    # Walk up to nearest existing ancestor to check writability
    while [ ! -d "$dir" ]; do
        dir="$(dirname "$dir")"
    done
    [ ! -w "$dir" ]
}

maybe_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        error "Root privileges required but sudo is not available"
    fi
}

# ---------------------------------------------------------------------------
# Utility: download helpers
# ---------------------------------------------------------------------------
DOWNLOADER=""

detect_downloader() {
    if command -v curl >/dev/null 2>&1; then
        DOWNLOADER="curl"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOADER="wget"
    else
        error "Either curl or wget is required"
    fi
}

download() {
    local url="$1" dest="$2"
    case "${DOWNLOADER}" in
        curl) curl -fsSL -o "$dest" "$url" ;;
        wget) wget -qO "$dest" "$url" ;;
    esac
}

download_to_stdout() {
    local url="$1"
    case "${DOWNLOADER}" in
        curl)
            if [ -n "${GITHUB_TOKEN:-}" ]; then
                curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" "$url"
            else
                curl -fsSL "$url"
            fi
            ;;
        wget)
            if [ -n "${GITHUB_TOKEN:-}" ]; then
                wget -qO- --header="Authorization: token ${GITHUB_TOKEN}" "$url"
            else
                wget -qO- "$url"
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
OS=""
ARCH=""

detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "${uname_s}" in
        Linux*)  OS="Linux" ;;
        Darwin*) OS="Darwin" ;;
        *)       error "Unsupported operating system: ${uname_s}" ;;
    esac
}

detect_arch() {
    local uname_m
    uname_m="$(uname -m)"
    case "${uname_m}" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)             error "Unsupported architecture: ${uname_m}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
resolve_version() {
    if [ "${VERSION}" = "latest" ]; then
        info "Resolving latest version from GitHub..."
        local api_url="https://api.github.com/repos/${GITHUB_ORG}/${GITHUB_REPO}/releases/latest"
        local response
        response="$(download_to_stdout "${api_url}")" || error "Failed to fetch latest release info"
        VERSION="$(printf '%s' "$response" | grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
        [ -n "${VERSION}" ] || error "Could not determine latest version"
    fi

    # Validate version format (vX.Y.Z)
    if ! printf '%s' "${VERSION}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+'; then
        error "Invalid version format: ${VERSION} (expected vX.Y.Z)"
    fi

    info "Version: ${VERSION}"
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
verify_checksums() {
    local archive="$1" checksums_file="$2"

    info "Verifying SHA256 checksum..."
    local expected actual archive_name
    archive_name="$(basename "$archive")"
    expected="$(awk -v name="${archive_name}" '$2 == name {print $1}' "$checksums_file")"
    [ -n "$expected" ] || error "Checksum not found for ${archive_name}"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    else
        warn "Neither sha256sum nor shasum found; skipping checksum verification"
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        error "Checksum mismatch: expected ${expected}, got ${actual}"
    fi
    success "Checksum verified"
}

verify_gpg() {
    local checksums_file="$1" signature_file="$2"

    if ! command -v gpg >/dev/null 2>&1; then
        warn "gpg not found; skipping GPG signature verification"
        return 0
    fi

    info "Verifying GPG signature..."
    local gnupg_tmp
    gnupg_tmp="$(mktemp -d)"

    download "${GPG_KEY_URL}" "${gnupg_tmp}/key.asc"
    gpg --homedir "${gnupg_tmp}" --batch --quiet --import "${gnupg_tmp}/key.asc" 2>/dev/null
    if gpg --homedir "${gnupg_tmp}" --batch --quiet --verify "$signature_file" "$checksums_file" 2>/dev/null; then
        success "GPG signature verified"
    else
        warn "GPG signature verification failed; continuing anyway"
    fi
    rm -rf "${gnupg_tmp}"
}

# ---------------------------------------------------------------------------
# Binary installation
# ---------------------------------------------------------------------------
resolve_install_dir() {
    if [ -n "${INSTALL_DIR}" ]; then
        return
    fi

    if [ "${SYSTEM_INSTALL}" -eq 1 ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
}

install_binary() {
    local tmp_dir="$1"
    local archive_name="dotsecenv_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    local archive_url="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION}/${archive_name}"
    local checksums_url="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION}/checksums.txt"
    local signature_url="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION}/checksums.txt.sig"

    info "Downloading dotsecenv ${VERSION} for ${OS}/${ARCH}..."
    download "${archive_url}" "${tmp_dir}/${archive_name}"

    if [ "${VERIFY}" = "1" ]; then
        download "${checksums_url}" "${tmp_dir}/checksums.txt"
        download "${signature_url}" "${tmp_dir}/checksums.txt.sig" 2>/dev/null || true
        verify_checksums "${tmp_dir}/${archive_name}" "${tmp_dir}/checksums.txt"
        if [ -f "${tmp_dir}/checksums.txt.sig" ]; then
            verify_gpg "${tmp_dir}/checksums.txt" "${tmp_dir}/checksums.txt.sig"
        fi
    fi

    info "Extracting archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"

    # Check existing installation
    if [ -x "${INSTALL_DIR}/dotsecenv" ]; then
        local existing_version
        existing_version="$("${INSTALL_DIR}/dotsecenv" version 2>/dev/null || true)"
        if printf '%s' "${existing_version}" | grep -q "${VERSION#v}"; then
            success "dotsecenv ${VERSION} is already installed"
            return 0
        fi
    fi

    info "Installing binary to ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}" 2>/dev/null || true
    if need_sudo "${INSTALL_DIR}"; then
        maybe_sudo install -m 755 "${tmp_dir}/dotsecenv" "${INSTALL_DIR}/dotsecenv"
    else
        install -m 755 "${tmp_dir}/dotsecenv" "${INSTALL_DIR}/dotsecenv"
    fi

    # Verify installation
    if [ -x "${INSTALL_DIR}/dotsecenv" ]; then
        success "Installed dotsecenv to ${INSTALL_DIR}/dotsecenv"
    else
        error "Installation failed: binary not found at ${INSTALL_DIR}/dotsecenv"
    fi

    # Check PATH
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            warn "${INSTALL_DIR} is not in your PATH"
            warn "Add this to your shell profile:"
            warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------------
is_system_install() {
    [ "${SYSTEM_INSTALL}" -eq 1 ]
}

install_completions() {
    local tmp_dir="$1"

    info "Installing shell completions..."

    local bash_comp_dir zsh_comp_dir fish_comp_dir
    if is_system_install; then
        local share_prefix="/usr/share"
        # macOS SIP prevents writes to /usr/share; use /usr/local/share instead
        [ "$(uname -s)" = "Darwin" ] && share_prefix="/usr/local/share"
        bash_comp_dir="${share_prefix}/bash-completion/completions"
        zsh_comp_dir="${share_prefix}/zsh/site-functions"
        fish_comp_dir="${share_prefix}/fish/vendor_completions.d"
    else
        bash_comp_dir="${HOME}/.local/share/bash-completion/completions"
        zsh_comp_dir="${HOME}/.local/share/zsh/site-functions"
        fish_comp_dir="${HOME}/.config/fish/completions"
    fi

    local installed=0
    for shell_type in bash zsh fish; do
        local src_file="${tmp_dir}/completions/dotsecenv.${shell_type}"
        [ -f "$src_file" ] || continue

        local dest_dir
        case "${shell_type}" in
            bash) dest_dir="${bash_comp_dir}" ;;
            zsh)  dest_dir="${zsh_comp_dir}" ;;
            fish) dest_dir="${fish_comp_dir}" ;;
        esac

        local dest_file="${dest_dir}/dotsecenv"
        [ "${shell_type}" = "zsh" ] && dest_file="${dest_dir}/_dotsecenv"
        [ "${shell_type}" = "fish" ] && dest_file="${dest_dir}/dotsecenv.fish"

        if need_sudo "${dest_dir}" 2>/dev/null; then
            maybe_sudo mkdir -p "${dest_dir}"
            maybe_sudo cp "${src_file}" "${dest_file}"
        else
            mkdir -p "${dest_dir}"
            cp "${src_file}" "${dest_file}"
        fi
        installed=1
    done

    if [ "${installed}" -eq 1 ]; then
        success "Shell completions installed"
    else
        warn "No completion files found in archive"
    fi
}

# ---------------------------------------------------------------------------
# Man pages
# ---------------------------------------------------------------------------
install_man_pages() {
    local tmp_dir="$1"

    info "Installing man pages..."

    local man_dir
    if is_system_install; then
        man_dir="/usr/local/share/man/man1"
    else
        man_dir="${HOME}/.local/share/man/man1"
    fi

    local found=0
    for man_file in "${tmp_dir}"/man/man1/*.1; do
        [ -f "$man_file" ] || continue
        found=1

        if need_sudo "${man_dir}" 2>/dev/null; then
            maybe_sudo mkdir -p "${man_dir}"
            maybe_sudo cp "${man_file}" "${man_dir}/"
        else
            mkdir -p "${man_dir}"
            cp "${man_file}" "${man_dir}/"
        fi
    done

    if [ "${found}" -eq 1 ]; then
        success "Man pages installed"
    else
        warn "No man pages found in archive"
    fi
}

# ---------------------------------------------------------------------------
# Plugin manager detection
# ---------------------------------------------------------------------------
DETECTED_MANAGERS=()

detect_plugin_managers() {
    # Oh My Zsh
    local omz_dir="${ZSH:-${HOME}/.oh-my-zsh}"
    if [ -d "${omz_dir}" ]; then
        DETECTED_MANAGERS+=("ohmyzsh")
    fi

    # Zinit
    local zinit_dir="${ZINIT_HOME:-${HOME}/.local/share/zinit}"
    if [ -d "${zinit_dir}" ]; then
        DETECTED_MANAGERS+=("zinit")
    fi

    # Antidote
    local antidote_dir="${ANTIDOTE_HOME:-${HOME}/.antidote}"
    if [ -d "${antidote_dir}" ]; then
        DETECTED_MANAGERS+=("antidote")
    fi

    # Oh My Bash
    local omb_dir="${OSH:-${HOME}/.oh-my-bash}"
    if [ -d "${omb_dir}" ]; then
        DETECTED_MANAGERS+=("ohmybash")
    fi

    # Fisher (fish)
    if [ -f "${HOME}/.config/fish/functions/fisher.fish" ]; then
        DETECTED_MANAGERS+=("fisher")
    fi

    # Oh My Fish
    if [ -d "${HOME}/.local/share/omf" ]; then
        DETECTED_MANAGERS+=("ohmyfish")
    fi
}

# ---------------------------------------------------------------------------
# Shell plugin installation
# ---------------------------------------------------------------------------
install_shell_plugin() {
    info "Installing shell plugin..."
    detect_plugin_managers

    local plugin_repo="https://github.com/${GITHUB_ORG}/plugin.git"
    local instructions=()

    if [ "${#DETECTED_MANAGERS[@]}" -eq 0 ]; then
        # No manager detected — fallback: clone to ~/.local/share
        local fallback_dir="${HOME}/.local/share/dotsecenv/plugin"
        if [ -d "${fallback_dir}" ]; then
            info "Plugin already cloned at ${fallback_dir}, updating..."
            git -C "${fallback_dir}" pull --quiet 2>/dev/null || true
        else
            git clone --quiet "${plugin_repo}" "${fallback_dir}"
        fi
        # Install fish conf.d file if fish config dir exists
        local fish_conf_dir="${HOME}/.config/fish/conf.d"
        if [ -d "${HOME}/.config/fish" ]; then
            mkdir -p "${fish_conf_dir}"
            if [ -f "${fallback_dir}/conf.d/dotsecenv.fish" ]; then
                ln -sf "${fallback_dir}/conf.d/dotsecenv.fish" "${fish_conf_dir}/dotsecenv.fish"
            fi
        fi

        PLUGIN_LOCATIONS+=("${fallback_dir}")
        success "Plugin cloned to ${fallback_dir}"
        instructions+=("Add to your ${BOLD}.zshrc${RESET} or ${BOLD}.bashrc${RESET}:")
        instructions+=("  source ~/.local/share/dotsecenv/plugin/dotsecenv.plugin.zsh  # for zsh")
        instructions+=("  source ~/.local/share/dotsecenv/plugin/dotsecenv.plugin.bash  # for bash")
        if [ -d "${HOME}/.config/fish" ]; then
            instructions+=("${BOLD}Fish:${RESET} conf.d/dotsecenv.fish has been linked automatically")
        else
            instructions+=("${BOLD}Fish:${RESET} Link or copy the conf.d file:")
            instructions+=("  ln -s ~/.local/share/dotsecenv/plugin/conf.d/dotsecenv.fish ~/.config/fish/conf.d/dotsecenv.fish")
        fi
    fi

    local mgr
    for mgr in "${DETECTED_MANAGERS[@]}"; do
        case "${mgr}" in
            ohmyzsh)
                local omz_custom="${ZSH_CUSTOM:-${ZSH:-${HOME}/.oh-my-zsh}/custom}"
                local omz_plugin_dir="${omz_custom}/plugins/dotsecenv"
                if [ -d "${omz_plugin_dir}" ]; then
                    info "Oh My Zsh plugin already installed, updating..."
                    git -C "${omz_plugin_dir}" pull --quiet 2>/dev/null || true
                else
                    git clone --quiet "${plugin_repo}" "${omz_plugin_dir}"
                fi
                PLUGIN_LOCATIONS+=("Oh My Zsh: ${omz_plugin_dir}")
                success "Oh My Zsh plugin installed"
                instructions+=("${BOLD}Oh My Zsh:${RESET} Add ${BOLD}dotsecenv${RESET} to plugins=(...) in your .zshrc")
                ;;
            zinit)
                PLUGIN_LOCATIONS+=("Zinit: add to .zshrc")
                success "Zinit detected"
                instructions+=("${BOLD}Zinit:${RESET} Add to your .zshrc:")
                instructions+=("  zinit light ${GITHUB_ORG}/plugin")
                ;;
            antidote)
                PLUGIN_LOCATIONS+=("Antidote: add to .zsh_plugins.txt")
                success "Antidote detected"
                instructions+=("${BOLD}Antidote:${RESET} Add to ~/.zsh_plugins.txt:")
                instructions+=("  ${GITHUB_ORG}/plugin")
                ;;
            ohmybash)
                local omb_dir="${OSH:-${HOME}/.oh-my-bash}"
                local omb_plugin_dir="${omb_dir}/custom/plugins/dotsecenv"
                if [ -d "${omb_plugin_dir}" ]; then
                    info "Oh My Bash plugin already installed, updating..."
                    git -C "${omb_plugin_dir}" pull --quiet 2>/dev/null || true
                else
                    git clone --quiet "${plugin_repo}" "${omb_plugin_dir}"
                fi
                PLUGIN_LOCATIONS+=("Oh My Bash: ${omb_plugin_dir}")
                success "Oh My Bash plugin installed"
                instructions+=("${BOLD}Oh My Bash:${RESET} Add ${BOLD}dotsecenv${RESET} to plugins=(...) in your .bashrc")
                ;;
            fisher)
                info "Installing plugin via Fisher..."
                fish -c "fisher install ${GITHUB_ORG}/plugin" 2>/dev/null || warn "Fisher install failed"
                PLUGIN_LOCATIONS+=("Fisher: installed")
                success "Fisher plugin installed"
                ;;
            ohmyfish)
                info "Installing plugin via Oh My Fish..."
                fish -c "omf install ${GITHUB_ORG}/plugin" 2>/dev/null || warn "Oh My Fish install failed"
                PLUGIN_LOCATIONS+=("Oh My Fish: installed")
                success "Oh My Fish plugin installed"
                ;;
        esac
    done

    if [ "${#instructions[@]}" -gt 0 ]; then
        printf "\n"
        info "Plugin setup instructions:"
        for line in "${instructions[@]}"; do
            printf "    %b\n" "$line"
        done
    fi
}

# ---------------------------------------------------------------------------
# Terraform credentials helper
# ---------------------------------------------------------------------------
install_tf_helper() {
    local tmp_dir="$1"

    info "Installing Terraform credentials helper..."

    local tf_plugin_dir
    if is_system_install; then
        local share_prefix="/usr/share"
        [ "$(uname -s)" = "Darwin" ] && share_prefix="/usr/local/share"
        tf_plugin_dir="${share_prefix}/terraform/plugins"
    else
        tf_plugin_dir="${HOME}/.terraform.d/plugins"
    fi
    local helper_src="${tmp_dir}/contrib/terraform-credentials-dotsecenv"

    if [ ! -f "${helper_src}" ]; then
        warn "Terraform credentials helper not found in archive; skipping"
        return 0
    fi

    if need_sudo "${tf_plugin_dir}" 2>/dev/null; then
        maybe_sudo mkdir -p "${tf_plugin_dir}"
        maybe_sudo install -m 755 "${helper_src}" "${tf_plugin_dir}/terraform-credentials-dotsecenv"
    else
        mkdir -p "${tf_plugin_dir}"
        install -m 755 "${helper_src}" "${tf_plugin_dir}/terraform-credentials-dotsecenv"
    fi
    success "Terraform credentials helper installed to ${tf_plugin_dir}"

    printf "\n"
    printf "${BLUE}==>${RESET} Add the following to your ${BOLD}~/.terraformrc${RESET}:\n"
    cat <<'TFEOF'

    credentials_helper "dotsecenv" {}

TFEOF
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    local share_prefix comp_dir man_dir tf_dir
    if is_system_install; then
        share_prefix="/usr/share"
        [ "$(uname -s)" = "Darwin" ] && share_prefix="/usr/local/share"
        comp_dir="${share_prefix}"
        man_dir="/usr/local/share/man/man1"
        tf_dir="${share_prefix}/terraform/plugins"
    else
        comp_dir="${HOME}/.local/share"
        man_dir="${HOME}/.local/share/man/man1"
        tf_dir="${HOME}/.terraform.d/plugins"
    fi

    printf "\n"
    printf "${GREEN}${BOLD}dotsecenv ${VERSION} installation complete!${RESET}\n"
    printf "\n"
    printf "  Binary:       ${INSTALL_DIR}/dotsecenv\n"
    [ "${INSTALL_COMPLETIONS}" = "1" ] && printf "  Completions:  ${comp_dir}/\n"
    [ "${INSTALL_MAN_PAGES}" = "1" ] && printf "  Man pages:    ${man_dir}/\n"
    if [ "${INSTALL_SHELL_PLUGIN}" = "1" ] && [ "${#PLUGIN_LOCATIONS[@]}" -gt 0 ]; then
        printf "  Shell plugin:\n"
        for loc in "${PLUGIN_LOCATIONS[@]}"; do
            printf "    - ${loc}\n"
        done
    fi
    [ "${INSTALL_TF_CREDENTIALS_HELPER}" = "1" ] && printf "  TF helper:    ${tf_dir}/\n"
    printf "\n"
    printf "  Get started:  ${BOLD}dotsecenv --help${RESET}\n"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                VERSION="$2"; shift 2 ;;
            --version=*)
                VERSION="${1#*=}"; shift ;;
            --install-dir)
                INSTALL_DIR="$2"; shift 2 ;;
            --install-dir=*)
                INSTALL_DIR="${1#*=}"; shift ;;
            --install-shell-plugin)
                INSTALL_SHELL_PLUGIN=1; shift ;;
            --no-install-shell-plugin)
                INSTALL_SHELL_PLUGIN=0; shift ;;
            --install-tf-credentials-helper)
                INSTALL_TF_CREDENTIALS_HELPER=1; shift ;;
            --no-install-tf-credentials-helper)
                INSTALL_TF_CREDENTIALS_HELPER=0; shift ;;
            --install-completions)
                INSTALL_COMPLETIONS=1; shift ;;
            --no-install-completions)
                INSTALL_COMPLETIONS=0; shift ;;
            --install-man-pages)
                INSTALL_MAN_PAGES=1; shift ;;
            --no-install-man-pages)
                INSTALL_MAN_PAGES=0; shift ;;
            --system)
                SYSTEM_INSTALL=1; shift ;;
            --verify)
                VERIFY=1; shift ;;
            --no-verify)
                VERIFY=0; shift ;;
            -h|--help)
                cat <<USAGE
dotsecenv installer

Usage:
  curl -fsSL https://get.dotsecenv.com/install.sh | bash
  curl -fsSL https://get.dotsecenv.com/install.sh | bash -s -- [OPTIONS]

Options:
  --version VERSION                  Install specific version (default: latest)
  --install-dir DIR                  Install binary to DIR (default: ~/.local/bin)
  --[no-]install-shell-plugin        Install shell plugin (default: yes)
  --[no-]install-tf-credentials-helper  Install Terraform helper (default: yes)
  --[no-]install-completions         Install shell completions (default: yes)
  --[no-]install-man-pages           Install man pages (default: yes)
  --system                           Install system-wide (/usr/local/bin, shared
                                     completions/man pages) instead of user home
  --[no-]verify                      Verify checksums and GPG (default: yes)
  -h, --help                         Show this help

Environment variables:
  VERSION, INSTALL_DIR, INSTALL_SHELL_PLUGIN, INSTALL_TF_CREDENTIALS_HELPER,
  INSTALL_COMPLETIONS, INSTALL_MAN_PAGES, SYSTEM_INSTALL, VERIFY
USAGE
                exit 0
                ;;
            *)
                error "Unknown option: $1 (use --help for usage)"
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    printf "${BOLD}dotsecenv installer${RESET}\n\n"

    detect_os
    detect_arch
    detect_downloader
    resolve_version
    resolve_install_dir

    TMPDIR_ROOT="$(mktemp -d)"
    local tmp_dir="${TMPDIR_ROOT}"

    install_binary "${tmp_dir}"

    if [ "${INSTALL_COMPLETIONS}" = "1" ]; then
        install_completions "${tmp_dir}"
    fi

    if [ "${INSTALL_MAN_PAGES}" = "1" ]; then
        install_man_pages "${tmp_dir}"
    fi

    if [ "${INSTALL_SHELL_PLUGIN}" = "1" ]; then
        install_shell_plugin
    fi

    if [ "${INSTALL_TF_CREDENTIALS_HELPER}" = "1" ]; then
        install_tf_helper "${tmp_dir}"
    fi

    print_summary
}

if [[ -z "${BASH_SOURCE[0]:-}" ]] || [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

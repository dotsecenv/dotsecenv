#!/usr/bin/env bash
# Plugin manager integration tests using Docker
#
# Usage:
#   ./tests/test_plugin_managers.sh [--manager=NAME] [--verbose]
#
# Managers: ohmyzsh, zinit, antidote, ohmybash, fisher, ohmyfish, all
#
# Requires: docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Options
VERBOSE=0
TARGET_MANAGER="all"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    --manager=*)
        TARGET_MANAGER="${1#*=}"
        ;;
    --verbose | -v)
        VERBOSE=1
        ;;
    -h | --help)
        echo "Plugin manager integration tests"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --manager=NAME   Test specific manager (ohmyzsh, zinit, antidote, ohmybash, fisher, ohmyfish, all)"
        echo "  --verbose, -v    Show verbose output"
        echo "  -h, --help       Show this help"
        exit 0
        ;;
    *)
        echo "Unknown option: $1" >&2
        exit 1
        ;;
    esac
    shift
done

# Logging
log() { echo -e "${BLUE}[TEST]${NC} $*"; }
pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++)) || true
}
fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++)) || true
}
debug() { [[ $VERBOSE -eq 1 ]] && echo "[DEBUG] $*" || true; }

# Check prerequisites
check_docker() {
    if ! command -v docker &>/dev/null; then
        echo "Error: docker is required but not installed" >&2
        exit 1
    fi
    if ! docker info &>/dev/null; then
        echo "Error: docker daemon is not running" >&2
        exit 1
    fi
}

# Build test image with common dependencies
build_base_image() {
    log "Building base test image..."

    docker build -t dotsecenv-plugin-test-base -f - "$PROJECT_ROOT" <<'DOCKERFILE'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# Install common dependencies
RUN apt-get update && apt-get install -y \
    bash \
    zsh \
    git \
    curl \
    ca-certificates \
    locales \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set up locale
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy plugin files
COPY . /opt/dotsecenv-plugin
RUN chown -R testuser:testuser /opt/dotsecenv-plugin

# Create mock dotsecenv CLI
RUN mkdir -p /usr/local/bin && \
    cat > /usr/local/bin/dotsecenv <<'EOF'
#!/bin/bash
if [[ "$1" == "secret" && "$2" == "get" ]]; then
    case "$3" in
        "TEST_SECRET") echo "secret-value-12345" ;;
        "DB_PASSWORD") echo "super-secret-password" ;;
        *) echo "Secret not found: $3" >&2; exit 1 ;;
    esac
else
    echo "dotsecenv mock: $*"
fi
EOF
RUN chmod +x /usr/local/bin/dotsecenv

USER testuser
WORKDIR /home/testuser
DOCKERFILE
}

# Build fish image (separate because fish needs special install)
build_fish_image() {
    log "Building fish test image..."

    docker build -t dotsecenv-plugin-test-fish -f - "$PROJECT_ROOT" <<'DOCKERFILE'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# Install dependencies including fish
RUN apt-get update && apt-get install -y \
    fish \
    git \
    curl \
    ca-certificates \
    locales \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set up locale
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Create test user
RUN useradd -m -s /usr/bin/fish testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy plugin files
COPY . /opt/dotsecenv-plugin
RUN chown -R testuser:testuser /opt/dotsecenv-plugin

# Create mock dotsecenv CLI
RUN mkdir -p /usr/local/bin && \
    cat > /usr/local/bin/dotsecenv <<'EOF'
#!/bin/bash
if [[ "$1" == "secret" && "$2" == "get" ]]; then
    case "$3" in
        "TEST_SECRET") echo "secret-value-12345" ;;
        "DB_PASSWORD") echo "super-secret-password" ;;
        *) echo "Secret not found: $3" >&2; exit 1 ;;
    esac
else
    echo "dotsecenv mock: $*"
fi
EOF
RUN chmod +x /usr/local/bin/dotsecenv

USER testuser
WORKDIR /home/testuser
DOCKERFILE
}

# ============================================================================
# Test: Oh My Zsh
# ============================================================================
test_ohmyzsh() {
    log "Testing Oh My Zsh plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-base bash -c '
        set -e

        # Install Oh My Zsh (unattended)
        export RUNZSH=no
        export CHSH=no
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

        # Clone plugin to custom plugins directory
        git clone /opt/dotsecenv-plugin ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/dotsecenv

        # Configure .zshrc to use the plugin
        sed -i "s/plugins=(git)/plugins=(git dotsecenv)/" ~/.zshrc

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Run zsh and test
        cd ~/testproject
        zsh -c "
            source ~/.zshrc
            _dotsecenv_on_cd \"\" \"$PWD\"
            if [[ \"\$TEST_SECRET\" == \"secret-value-12345\" ]]; then
                echo \"SUCCESS: Oh My Zsh plugin works\"
            else
                echo \"FAIL: TEST_SECRET=\$TEST_SECRET\"
                exit 1
            fi
        "
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Oh My Zsh plugin works"; then
        pass "Oh My Zsh plugin installation and functionality"
        debug "$output"
    else
        fail "Oh My Zsh plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Test: Zinit
# ============================================================================
test_zinit() {
    log "Testing Zinit plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-base bash -c '
        set -e

        # Install Zinit
        bash -c "$(curl --fail --show-error --silent --location https://raw.githubusercontent.com/zdharma-continuum/zinit/HEAD/scripts/install.sh)" -- --no-modify-rc

        # Create .zshrc with zinit loading our plugin from local path
        cat > ~/.zshrc <<EOF
source ~/.local/share/zinit/zinit.git/zinit.zsh
zinit light /opt/dotsecenv-plugin
EOF

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Run zsh and test
        cd ~/testproject
        zsh -c "
            source ~/.zshrc
            _dotsecenv_on_cd \"\" \"$PWD\"
            if [[ \"\$TEST_SECRET\" == \"secret-value-12345\" ]]; then
                echo \"SUCCESS: Zinit plugin works\"
            else
                echo \"FAIL: TEST_SECRET=\$TEST_SECRET\"
                exit 1
            fi
        "
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Zinit plugin works"; then
        pass "Zinit plugin installation and functionality"
        debug "$output"
    else
        fail "Zinit plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Test: Antidote
# ============================================================================
test_antidote() {
    log "Testing Antidote plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-base bash -c '
        set -e

        # Install Antidote
        git clone --depth=1 https://github.com/mattmc3/antidote.git ~/.antidote

        # Create plugins file
        echo "/opt/dotsecenv-plugin" > ~/.zsh_plugins.txt

        # Create .zshrc
        cat > ~/.zshrc <<EOF
source ~/.antidote/antidote.zsh
antidote load ~/.zsh_plugins.txt
EOF

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Run zsh and test
        cd ~/testproject
        zsh -c "
            source ~/.zshrc
            _dotsecenv_on_cd \"\" \"$PWD\"
            if [[ \"\$TEST_SECRET\" == \"secret-value-12345\" ]]; then
                echo \"SUCCESS: Antidote plugin works\"
            else
                echo \"FAIL: TEST_SECRET=\$TEST_SECRET\"
                exit 1
            fi
        "
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Antidote plugin works"; then
        pass "Antidote plugin installation and functionality"
        debug "$output"
    else
        fail "Antidote plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Test: Oh My Bash
# ============================================================================
test_ohmybash() {
    log "Testing Oh My Bash plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-base bash -c '
        set -e

        # Install Oh My Bash (unattended)
        export OSH_UNATTENDED=1
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh)"

        # Clone plugin to custom plugins directory
        mkdir -p ~/.oh-my-bash/custom/plugins
        cp -r /opt/dotsecenv-plugin ~/.oh-my-bash/custom/plugins/dotsecenv

        # Configure .bashrc to use the plugin
        # Oh My Bash uses OSH_PLUGINS array
        cat >> ~/.bashrc <<EOF

# Enable dotsecenv plugin
plugins+=(dotsecenv)
EOF

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Source and test
        cd ~/testproject
        source ~/.bashrc 2>/dev/null || true
        source ~/.oh-my-bash/custom/plugins/dotsecenv/_dotsecenv_core.sh
        source ~/.oh-my-bash/custom/plugins/dotsecenv/dotsecenv.plugin.bash
        _dotsecenv_chpwd_hook

        if [[ "$TEST_SECRET" == "secret-value-12345" ]]; then
            echo "SUCCESS: Oh My Bash plugin works"
        else
            echo "FAIL: TEST_SECRET=$TEST_SECRET"
            exit 1
        fi
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Oh My Bash plugin works"; then
        pass "Oh My Bash plugin installation and functionality"
        debug "$output"
    else
        fail "Oh My Bash plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Test: Fisher
# ============================================================================
test_fisher() {
    log "Testing Fisher plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-fish fish -c '
        # Install Fisher
        curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source
        fisher install jorgebucaran/fisher

        # Install plugin from local path
        fisher install /opt/dotsecenv-plugin

        # Verify plugin was installed
        if not functions -q _dotsecenv_on_cd
            echo "FAIL: Plugin functions not loaded"
            exit 1
        end

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Test the plugin
        cd ~/testproject
        _dotsecenv_on_cd "" (pwd)

        if test "$TEST_SECRET" = "secret-value-12345"
            echo "SUCCESS: Fisher plugin works"
        else
            echo "FAIL: TEST_SECRET=$TEST_SECRET"
            exit 1
        end
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Fisher plugin works"; then
        pass "Fisher plugin installation and functionality"
        debug "$output"
    else
        fail "Fisher plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Test: Oh My Fish
# ============================================================================
test_ohmyfish() {
    log "Testing Oh My Fish plugin installation..."
    ((TESTS_RUN++)) || true

    local output
    output=$(docker run --rm dotsecenv-plugin-test-fish fish -c '
        # Install Oh My Fish
        curl https://raw.githubusercontent.com/oh-my-fish/oh-my-fish/master/bin/install | fish --init-command "set -g NONINTERACTIVE 1"

        # Link plugin to OMF packages (simulating omf install)
        mkdir -p ~/.local/share/omf/pkg
        ln -s /opt/dotsecenv-plugin ~/.local/share/omf/pkg/dotsecenv

        # Source the plugin
        source /opt/dotsecenv-plugin/conf.d/dotsecenv.fish

        # Verify plugin was loaded
        if not functions -q _dotsecenv_on_cd
            echo "FAIL: Plugin functions not loaded"
            exit 1
        end

        # Create test directory with .secenv
        mkdir -p ~/testproject
        echo "TEST_SECRET={dotsecenv}" > ~/testproject/.secenv
        chmod 600 ~/testproject/.secenv

        # Pre-trust the directory
        mkdir -p ~/.config/dotsecenv
        echo "/home/testuser/testproject" > ~/.config/dotsecenv/trusted_dirs

        # Test the plugin
        cd ~/testproject
        _dotsecenv_on_cd "" (pwd)

        if test "$TEST_SECRET" = "secret-value-12345"
            echo "SUCCESS: Oh My Fish plugin works"
        else
            echo "FAIL: TEST_SECRET=$TEST_SECRET"
            exit 1
        end
    ' 2>&1)

    if echo "$output" | grep -q "SUCCESS: Oh My Fish plugin works"; then
        pass "Oh My Fish plugin installation and functionality"
        debug "$output"
    else
        fail "Oh My Fish plugin test failed"
        echo "$output"
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo ""
    echo "=================================================="
    echo "dotsecenv Plugin Manager Integration Tests"
    echo "=================================================="
    echo ""

    check_docker

    # Build base images
    build_base_image
    build_fish_image
    echo ""

    # Run tests based on target
    case "$TARGET_MANAGER" in
    ohmyzsh)
        test_ohmyzsh
        ;;
    zinit)
        test_zinit
        ;;
    antidote)
        test_antidote
        ;;
    ohmybash)
        test_ohmybash
        ;;
    fisher)
        test_fisher
        ;;
    ohmyfish)
        test_ohmyfish
        ;;
    all)
        test_ohmyzsh
        echo ""
        test_zinit
        echo ""
        test_antidote
        echo ""
        test_ohmybash
        echo ""
        test_fisher
        echo ""
        test_ohmyfish
        ;;
    *)
        echo "Unknown manager: $TARGET_MANAGER" >&2
        echo "Valid options: ohmyzsh, zinit, antidote, ohmybash, fisher, ohmyfish, all" >&2
        exit 1
        ;;
    esac

    # Summary
    echo ""
    echo "=================================================="
    echo "Test Results"
    echo "=================================================="
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    fi
}

main "$@"

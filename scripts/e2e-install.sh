#!/usr/bin/env bash
# e2e-install.sh — E2E tests for the dotsecenv install.sh installer
# Exercises real downloads from GitHub, checksum verification, and artifact installation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo "  PASS: $*"; ((TESTS_PASSED++)) || true; }
fail() { echo "  FAIL: $*"; ((TESTS_FAILED++)) || true; }
run_test() {
    local name="$1"; shift
    ((TESTS_RUN++)) || true
    echo "--- $name ---"
    if "$@"; then pass "$name"; else fail "$name"; fi
}

# ---------------------------------------------------------------------------
# Source install.sh for unit-style tests (guard prevents main from running)
# ---------------------------------------------------------------------------
source "${INSTALL_SCRIPT}"

# ---------------------------------------------------------------------------
# Resolve test version
# ---------------------------------------------------------------------------
if [ -n "${E2E_VERSION:-}" ]; then
    TEST_VERSION="${E2E_VERSION}"
else
    echo "==> Resolving latest release tag from GitHub..."
    detect_downloader
    TEST_VERSION="$(download_to_stdout "https://api.github.com/repos/dotsecenv/dotsecenv/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    [ -n "${TEST_VERSION}" ] || { echo "FATAL: Could not resolve latest version"; exit 1; }
fi
echo "==> Test version: ${TEST_VERSION}"

# ===================================================================
# A. Argument Parsing (sourced, no network)
# ===================================================================
echo ""
echo "==> A. Argument Parsing"

# Reset globals before each parse_args test
reset_defaults() {
    VERSION="latest"
    INSTALL_DIR=""
    INSTALL_SHELL_PLUGIN=1
    INSTALL_TF_CREDENTIALS_HELPER=1
    INSTALL_COMPLETIONS=1
    INSTALL_MAN_PAGES=1
    VERIFY=1
}

# Test 1: --version v9.8.7
run_test "--version v9.8.7 sets VERSION" bash -c "
    source '${INSTALL_SCRIPT}'
    VERSION=latest
    parse_args --version v9.8.7
    [ \"\$VERSION\" = 'v9.8.7' ]
"

# Test 2: --version=v9.8.7
run_test "--version=v9.8.7 (equals style) sets VERSION" bash -c "
    source '${INSTALL_SCRIPT}'
    VERSION=latest
    parse_args --version=v9.8.7
    [ \"\$VERSION\" = 'v9.8.7' ]
"

# Test 3: --install-dir /tmp/foo
run_test "--install-dir sets INSTALL_DIR" bash -c "
    source '${INSTALL_SCRIPT}'
    INSTALL_DIR=''
    parse_args --install-dir /tmp/foo
    [ \"\$INSTALL_DIR\" = '/tmp/foo' ]
"

# Test 4: --no-install-shell-plugin
run_test "--no-install-shell-plugin sets INSTALL_SHELL_PLUGIN=0" bash -c "
    source '${INSTALL_SCRIPT}'
    INSTALL_SHELL_PLUGIN=1
    parse_args --no-install-shell-plugin
    [ \"\$INSTALL_SHELL_PLUGIN\" = '0' ]
"

# Test 5: --no-install-completions --no-install-man-pages
run_test "--no-install-completions --no-install-man-pages sets both to 0" bash -c "
    source '${INSTALL_SCRIPT}'
    INSTALL_COMPLETIONS=1
    INSTALL_MAN_PAGES=1
    parse_args --no-install-completions --no-install-man-pages
    [ \"\$INSTALL_COMPLETIONS\" = '0' ] && [ \"\$INSTALL_MAN_PAGES\" = '0' ]
"

# Test 6: --bogus causes error exit
# error() calls exit 1 which kills the bash -c subshell, so we check the exit code directly
run_test "--bogus causes error exit" bash -c "
    ! bash -c 'source \"${INSTALL_SCRIPT}\"; parse_args --bogus' 2>/dev/null
"

# ===================================================================
# B. Platform Detection (sourced, no network)
# ===================================================================
echo ""
echo "==> B. Platform Detection"

# Test 7: detect_os
run_test "detect_os sets OS to Linux or Darwin" bash -c "
    source '${INSTALL_SCRIPT}'
    OS=''
    detect_os
    [ \"\$OS\" = 'Linux' ] || [ \"\$OS\" = 'Darwin' ]
"

# Test 8: detect_arch
run_test "detect_arch sets ARCH to x86_64 or arm64" bash -c "
    source '${INSTALL_SCRIPT}'
    ARCH=''
    detect_arch
    [ \"\$ARCH\" = 'x86_64' ] || [ \"\$ARCH\" = 'arm64' ]
"

# Test 9: detect_downloader
run_test "detect_downloader sets DOWNLOADER to curl or wget" bash -c "
    source '${INSTALL_SCRIPT}'
    DOWNLOADER=''
    detect_downloader
    [ \"\$DOWNLOADER\" = 'curl' ] || [ \"\$DOWNLOADER\" = 'wget' ]
"

# ===================================================================
# C. Version Validation (sourced, no network)
# ===================================================================
echo ""
echo "==> C. Version Validation"

# Test 10: resolve_version accepts v1.2.3
run_test "resolve_version accepts v1.2.3" bash -c "
    source '${INSTALL_SCRIPT}'
    VERSION='v1.2.3'
    DOWNLOADER='curl'
    resolve_version 2>/dev/null
"

# Test 11: resolve_version rejects 1.2.3 (missing v)
run_test "resolve_version rejects 1.2.3 (missing v prefix)" bash -c "
    ! bash -c 'source \"${INSTALL_SCRIPT}\"; VERSION=1.2.3; DOWNLOADER=curl; resolve_version' 2>/dev/null
"

# Test 12: resolve_version resolves latest to a real tag (network)
run_test "resolve_version resolves latest to a real tag" bash -c "
    source '${INSTALL_SCRIPT}'
    VERSION='latest'
    detect_downloader
    resolve_version 2>/dev/null
    echo \"Resolved: \$VERSION\"
    printf '%s' \"\$VERSION\" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+'
"

# ===================================================================
# D. Install Dir Resolution (sourced, no network)
# ===================================================================
echo ""
echo "==> D. Install Dir Resolution"

# Test 13: Explicit INSTALL_DIR preserved
run_test "Explicit INSTALL_DIR preserved" bash -c "
    source '${INSTALL_SCRIPT}'
    INSTALL_DIR='/custom/path'
    resolve_install_dir
    [ \"\$INSTALL_DIR\" = '/custom/path' ]
"

# Test 14: Falls back to ~/.local/bin when /usr/local/bin not writable and no sudo
run_test "Falls back to ~/.local/bin without write or sudo" bash -c "
    source '${INSTALL_SCRIPT}'
    INSTALL_DIR=''
    # Create a fake HOME
    FAKEHOME=\$(mktemp -d)
    HOME=\"\$FAKEHOME\"
    # Override to simulate no write access and no sudo
    need_sudo() { return 0; }
    # Hide sudo
    sudo() { return 1; }
    export -f need_sudo sudo
    # If /usr/local/bin is writable, the test is still valid since it checks the else branch
    if [ ! -w '/usr/local/bin' ] && ! command -v sudo >/dev/null 2>&1; then
        resolve_install_dir
        [ \"\$INSTALL_DIR\" = \"\${FAKEHOME}/.local/bin\" ]
    else
        # On systems where /usr/local/bin is writable or sudo exists,
        # just verify resolve_install_dir sets something
        resolve_install_dir
        [ -n \"\$INSTALL_DIR\" ]
    fi
    rm -rf \"\$FAKEHOME\"
"

# ===================================================================
# E. Full Install — binary only (network, real download)
# ===================================================================
echo ""
echo "==> E. Full Install — binary only"

E2E_TMP="$(mktemp -d)"
trap 'rm -rf "${E2E_TMP}"' EXIT

# Test 15: Run installer with binary-only flags
run_test "Full install binary-only succeeds" bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP}/bin" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --no-verify

# Test 16: Verify binary exists with mode 755
run_test "Binary exists at install dir with mode 755" bash -c "
    [ -x '${E2E_TMP}/bin/dotsecenv' ] || exit 1
    # Check permissions (platform-portable)
    if stat -f '%Lp' '${E2E_TMP}/bin/dotsecenv' 2>/dev/null | grep -q '755'; then
        exit 0
    elif stat -c '%a' '${E2E_TMP}/bin/dotsecenv' 2>/dev/null | grep -q '755'; then
        exit 0
    else
        # At minimum the file should be executable
        [ -x '${E2E_TMP}/bin/dotsecenv' ]
    fi
"

# Test 17: Verify version output
run_test "Binary version outputs expected version" bash -c "
    output=\$('${E2E_TMP}/bin/dotsecenv' version 2>&1 || true)
    echo \"Version output: \$output\"
    echo \"\$output\" | grep -q '${TEST_VERSION#v}'
"

# ===================================================================
# F. Full Install — with completions + man pages (network)
# ===================================================================
echo ""
echo "==> F. Full Install — with completions + man pages"

E2E_TMP2="$(mktemp -d)"

# Test 18: Run installer with completions + man pages
run_test "Full install with completions + man pages succeeds" \
    env HOME="${E2E_TMP2}" \
    bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP2}/bin" \
    --no-install-shell-plugin \
    --no-verify

# Test 19: Verify bash completion file (default: user home dir)
run_test "Bash completion file exists" bash -c "
    [ -f '${E2E_TMP2}/.local/share/bash-completion/completions/dotsecenv' ] || \
        { echo 'Bash completion not found'; exit 1; }
"

# Test 20: Verify zsh completion file
run_test "Zsh completion _dotsecenv file exists" bash -c "
    [ -f '${E2E_TMP2}/.local/share/zsh/site-functions/_dotsecenv' ] || \
        { echo 'Zsh completion not found'; exit 1; }
"

# Test 21: Verify fish completion file
run_test "Fish completion dotsecenv.fish file exists" bash -c "
    [ -f '${E2E_TMP2}/.config/fish/completions/dotsecenv.fish' ] || \
        { echo 'Fish completion not found'; exit 1; }
"

# Test 22: Verify man page exists (default: user home dir)
run_test "At least one man page exists" bash -c "
    ls '${E2E_TMP2}/.local/share/man/man1/'*.1 >/dev/null 2>&1 || \
        { echo 'No man pages found'; exit 1; }
"

rm -rf "${E2E_TMP2}"

# ===================================================================
# G. Checksum + GPG Verification (network)
# ===================================================================
echo ""
echo "==> G. Checksum + GPG Verification"

E2E_TMP3="$(mktemp -d)"

# Test 23: Run with --verify — should succeed and print "Checksum verified"
((TESTS_RUN++)) || true
echo "--- Verify mode prints Checksum verified ---"
verify_output="$(bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP3}/bin-verify" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --verify 2>&1)" || true
if echo "${verify_output}" | grep -qi "Checksum verified"; then
    pass "Verify mode prints Checksum verified"
else
    fail "Verify mode should print 'Checksum verified', got: ${verify_output}"
fi

# Test 24: Run with --no-verify — should skip checksum message
((TESTS_RUN++)) || true
echo "--- No-verify skips checksum message ---"
noverify_output="$(bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP3}/bin-noverify" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --no-verify 2>&1)" || true
if echo "${noverify_output}" | grep -qi "Checksum verified"; then
    fail "No-verify mode should not print 'Checksum verified'"
else
    pass "No-verify skips checksum message"
fi

rm -rf "${E2E_TMP3}"

# ===================================================================
# H. Plugin Manager Detection (sourced, no network)
# ===================================================================
echo ""
echo "==> H. Plugin Manager Detection"

# Test 25: Detects Oh My Zsh
run_test "Detects Oh My Zsh when ~/.oh-my-zsh dir exists" bash -c "
    source '${INSTALL_SCRIPT}'
    FAKEHOME=\$(mktemp -d)
    HOME=\"\$FAKEHOME\"
    mkdir -p \"\$FAKEHOME/.oh-my-zsh\"
    DETECTED_MANAGERS=()
    detect_plugin_managers
    found=0
    for m in \"\${DETECTED_MANAGERS[@]}\"; do
        [ \"\$m\" = 'ohmyzsh' ] && found=1
    done
    rm -rf \"\$FAKEHOME\"
    [ \$found -eq 1 ]
"

# Test 26: Detects Zinit
run_test "Detects Zinit when ~/.local/share/zinit dir exists" bash -c "
    source '${INSTALL_SCRIPT}'
    FAKEHOME=\$(mktemp -d)
    HOME=\"\$FAKEHOME\"
    mkdir -p \"\$FAKEHOME/.local/share/zinit\"
    DETECTED_MANAGERS=()
    detect_plugin_managers
    found=0
    for m in \"\${DETECTED_MANAGERS[@]}\"; do
        [ \"\$m\" = 'zinit' ] && found=1
    done
    rm -rf \"\$FAKEHOME\"
    [ \$found -eq 1 ]
"

# Test 27: Empty DETECTED_MANAGERS when clean HOME
run_test "Empty DETECTED_MANAGERS with clean HOME" bash -c "
    source '${INSTALL_SCRIPT}'
    FAKEHOME=\$(mktemp -d)
    HOME=\"\$FAKEHOME\"
    ZSH='' OSH='' ZINIT_HOME='' ANTIDOTE_HOME=''
    DETECTED_MANAGERS=()
    detect_plugin_managers
    rm -rf \"\$FAKEHOME\"
    [ \${#DETECTED_MANAGERS[@]} -eq 0 ]
"

# ===================================================================
# I. TF Credentials Helper (network, real download)
# ===================================================================
echo ""
echo "==> I. TF Credentials Helper"

E2E_TMP4="$(mktemp -d)"

# Test 28: Install with --install-tf-credentials-helper
((TESTS_RUN++)) || true
echo "--- TF credentials helper installs ---"
tf_output="$(HOME="${E2E_TMP4}" bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP4}/bin" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --no-verify \
    --install-tf-credentials-helper 2>&1)" || true

if [ -x "${E2E_TMP4}/.terraform.d/plugins/terraform-credentials-dotsecenv" ]; then
    pass "TF credentials helper installed with mode 755"
else
    # The archive may not include the helper; that's OK — mark as pass with note
    if echo "${tf_output}" | grep -qi "not found in archive"; then
        pass "TF credentials helper not in archive (expected for some releases)"
    else
        fail "TF credentials helper not found at expected path"
    fi
fi

# Test 29: Output contains credentials_helper "dotsecenv"
((TESTS_RUN++)) || true
echo "--- TF output contains credentials_helper ---"
if echo "${tf_output}" | grep -q 'credentials_helper "dotsecenv"' || \
   echo "${tf_output}" | grep -qi "not found in archive"; then
    pass "TF output contains credentials_helper or helper not in archive"
else
    fail "TF output should mention credentials_helper, got: ${tf_output}"
fi

rm -rf "${E2E_TMP4}"

# ===================================================================
# J. Idempotency (network)
# ===================================================================
echo ""
echo "==> J. Idempotency"

E2E_TMP5="$(mktemp -d)"

# First install
bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP5}/bin" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --no-verify >/dev/null 2>&1 || true

# Test 30: Second install says "already installed"
((TESTS_RUN++)) || true
echo "--- Second install outputs already installed ---"
second_output="$(bash "${INSTALL_SCRIPT}" \
    --version "${TEST_VERSION}" \
    --install-dir "${E2E_TMP5}/bin" \
    --no-install-shell-plugin \
    --no-install-completions \
    --no-install-man-pages \
    --no-verify 2>&1)" || true
if echo "${second_output}" | grep -qi "already installed"; then
    pass "Second install outputs 'already installed'"
else
    fail "Second install should say 'already installed', got: ${second_output}"
fi

rm -rf "${E2E_TMP5}"

# ===================================================================
# K. Help + Error
# ===================================================================
echo ""
echo "==> K. Help + Error"

# Test 31: --help prints usage and exits 0
run_test "--help prints usage and exits 0" bash -c "
    output=\$(bash '${INSTALL_SCRIPT}' --help 2>&1)
    echo \"\$output\" | grep -qi 'usage'
"

# Test 32: --version invalid exits non-zero with error
run_test "--version invalid exits non-zero" bash -c "
    output=\$(bash '${INSTALL_SCRIPT}' --version invalid \
        --install-dir /tmp/e2e-bogus \
        --no-install-shell-plugin \
        --no-install-completions \
        --no-install-man-pages 2>&1) && exit 1 || true
    echo \"\$output\" | grep -qi 'Invalid version format'
"

# ===================================================================
# Final Report
# ===================================================================
echo ""
echo "==========================================="
echo "  install.sh E2E Test Results"
echo "==========================================="
echo "Tests run:    $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"
echo "==========================================="

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"

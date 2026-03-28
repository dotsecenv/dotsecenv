#!/bin/bash
#
# e2e.sh - End-to-end integration tests for dotsecenv
#
# This script does not require network access. Set up the environment with:
#   make build
#
# The Makefile handles:
# - Creating isolated HOME, GNUPGHOME, XDG_* directories
# - Deploying the dotsecenv binary
# - Setting all environment variables
# - Cleanup on completion
#
set -e

BIN="bin/dotsecenv"

# Ensure the binary is executable
chmod +x "$BIN"

echo "==> Generating test keys in $GNUPGHOME"

# Generate two test keys (passwordless for CI)
# Using RSA4096 which is supported by dotsecenv
# Keys expire in 2y by default (fine for ephemeral test keys)
"$BIN" identity create --name "Test User One" --email "test1@dotsecenv.com" --algo RSA4096 --no-passphrase
"$BIN" identity create --name "Test User Two" --email "test2@dotsecenv.com" --algo RSA4096 --no-passphrase

# Capture fingerprints
KEY1=$(gpg --list-keys --with-colons test1@dotsecenv.com | awk -F: '/^fpr:/{print $10; exit}')
KEY2=$(gpg --list-keys --with-colons test2@dotsecenv.com | awk -F: '/^fpr:/{print $10; exit}')

echo "==> Key 1: $KEY1"
echo "==> Key 2: $KEY2"

echo "==> Initializing vaults"
# Create test vault directories (XDG paths are already isolated)
mkdir -p "$XDG_DATA_HOME/dotsecenv" .dotsecenv
"$BIN" init config
"$BIN" init vault -v .dotsecenv/vault
"$BIN" init vault -v "$XDG_DATA_HOME/dotsecenv/vault"

echo "==> Running e2e tests"
# Identities are auto-added by secret store and secret share
"$BIN" login "$KEY2"

echo abc | "$BIN" secret store SEC1 -v 1
"$BIN" secret get SEC1
"$BIN" secret share SEC1 "$KEY1"
"$BIN" secret get SEC1

"$BIN" login "$KEY1"
echo abc | "$BIN" secret store SEC2 -v 1
"$BIN" secret share SEC2 "$KEY2"
"$BIN" secret get SEC2
"$BIN" secret get SEC1

"$BIN" validate

echo "==> Testing non-TTY warning behavior"

# Test: non-TTY decryption should succeed but emit warning.
# The check uses /dev/tty (not stdout isatty), so we need a new session without
# a controlling terminal. setsid is available on Linux; on macOS the unit test
# covers this path via the injectable hasTTY field.
if command -v setsid >/dev/null 2>&1; then
    output=$(setsid "$BIN" secret get SEC1 2>&1)
    if ! echo "$output" | grep -q "non-interactive terminal"; then
        echo "FAIL: Expected non-interactive terminal warning" >&2
        echo "Got: $output" >&2
        exit 1
    fi

    if ! echo "$output" | grep -q "dotsecenv.com"; then
        echo "FAIL: Expected dotsecenv.com URL in warning" >&2
        echo "Got: $output" >&2
        exit 1
    fi
    echo "  non-TTY warning tests passed" >&2
else
    echo "  non-TTY warning test skipped (setsid not available, covered by unit tests)" >&2
fi

echo "==> E2E tests passed"

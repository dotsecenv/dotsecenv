#!/bin/bash
#
# e2e.sh - End-to-end integration tests for dotsecenv
#
# This script assumes it's running in an isolated environment set up by:
#   make build e2e
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
# Identities are auto-added by secret put and secret share
"$BIN" login "$KEY2"

echo abc | "$BIN" secret put SEC1 -v 1
"$BIN" secret get SEC1
"$BIN" secret share SEC1 "$KEY1"
"$BIN" secret get SEC1

"$BIN" login "$KEY1"
echo abc | "$BIN" secret put SEC2 -v 1
"$BIN" secret share SEC2 "$KEY2"
"$BIN" secret get SEC2
"$BIN" secret get SEC1

"$BIN" validate

echo "==> Testing require_tty_for_decryption behavior"

# Backup original config
cp "$HOME/.config/dotsecenv/config" "$HOME/.config/dotsecenv/config.bak"

# Enable require_tty_for_decryption by appending to existing behavior section
# First, remove the existing behavior section and add a complete one
sed -i.tmp '/^behavior:/,/^[^ ]/{ /^behavior:/d; /^  /d; }' "$HOME/.config/dotsecenv/config"
cat >> "$HOME/.config/dotsecenv/config" << 'EOF'
behavior:
  require_explicit_vault_upgrade: false
  restrict_to_configured_vaults: false
  require_tty_for_decryption: true
EOF

# Test: non-TTY decryption should be blocked
if "$BIN" secret get SEC1 </dev/null 2>&1; then
    echo "FAIL: Expected non-TTY decryption to be blocked"
    mv "$HOME/.config/dotsecenv/config.bak" "$HOME/.config/dotsecenv/config"
    exit 1
fi

# Verify error message contains expected text
output=$("$BIN" secret get SEC1 </dev/null 2>&1 || true)
if ! echo "$output" | grep -q "TTY required"; then
    echo "FAIL: Expected TTY required error"
    echo "Got: $output"
    mv "$HOME/.config/dotsecenv/config.bak" "$HOME/.config/dotsecenv/config"
    exit 1
fi

# Verify exit code is 8 (ExitAccessDenied)
"$BIN" secret get SEC1 </dev/null 2>&1 || exit_code=$?
if [ "${exit_code:-0}" != "8" ]; then
    echo "FAIL: Expected exit code 8, got ${exit_code:-0}"
    mv "$HOME/.config/dotsecenv/config.bak" "$HOME/.config/dotsecenv/config"
    exit 1
fi

# Restore original config
mv "$HOME/.config/dotsecenv/config.bak" "$HOME/.config/dotsecenv/config"

echo "  require_tty_for_decryption tests passed"

echo "==> E2E tests passed"

#!/bin/bash
#
# e2e.sh - End-to-end integration tests for dotsecenv
#
# This script assumes it's running in an isolated environment set up by:
#   make e2e
#
# The Makefile handles:
# - Creating isolated HOME, GNUPGHOME, XDG_* directories
# - Deploying the dotsecenv binary
# - Setting all environment variables
# - Cleanup on completion
#
set -e

BIN="dotsecenv"

echo "==> Generating test keys in $GNUPGHOME"

# Generate two test keys
# Preferences exclude S2 (3DES) to avoid "invalid item 'S2'" warning on GPG 2.4+
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 3072
Preferences: AES256 SHA512 Uncompressed
Name-Real: Test User One
Name-Email: test1@dotsecenv.com
%no-protection
%commit
EOF

gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 3072
Preferences: AES256 SHA512 Uncompressed
Name-Real: Test User Two
Name-Email: test2@dotsecenv.com
%no-protection
%commit
EOF

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

echo "==> E2E tests passed"

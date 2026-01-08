#!/bin/bash
set -e

# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="./dotsecenv"

# Create isolated test environment to avoid polluting user's config/data
TEST_HOME="$(mktemp -d)"
export XDG_CONFIG_HOME="$TEST_HOME/config"
export XDG_DATA_HOME="$TEST_HOME/data"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"

# Use existing GNUPGHOME if set, otherwise create isolated GPG home
# Avoid polluting user's keyrings during tests
if [ -z "$GNUPGHOME" ]; then
    GNUPGHOME="$TEST_HOME/gnupg"
    mkdir -p "$GNUPGHOME"
    chmod 700 "$GNUPGHOME"
    export GNUPGHOME
fi

# shellcheck disable=SC2064
trap "rm -rf $TEST_HOME" EXIT

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
# Create test vault directories (XDG paths are already isolated via TEST_HOME)
mkdir -p "$XDG_DATA_HOME/dotsecenv" .dotsecenv
"$BIN" init config
"$BIN" init vault -v .dotsecenv/vault
"$BIN" init vault -v "$XDG_DATA_HOME/dotsecenv/vault"

echo "==> Running e2e tests"
"$BIN" login "$KEY1"
"$BIN" vault identity add "$KEY1" --all
"$BIN" login "$KEY2"
"$BIN" vault identity add "$KEY2" --all

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

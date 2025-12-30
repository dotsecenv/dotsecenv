#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/bin/dotsecenv"

# Create isolated GPG home
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
# shellcheck disable=SC2064
trap "rm -rf $GNUPGHOME" EXIT

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
rm -f ~/.config/dotsecenv/config ~/.local/share/dotsecenv/vault .dotsecenv/vault
mkdir -p ~/.local/share/dotsecenv .dotsecenv
"$BIN" init config
"$BIN" init vault -v .dotsecenv/vault
"$BIN" init vault -v ~/.local/share/dotsecenv/vault

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

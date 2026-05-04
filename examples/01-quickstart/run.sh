#!/usr/bin/env bash
#
# 01-quickstart/run.sh
#
# Demonstrates the canonical dotsecenv workflow:
#   1. Generate an ephemeral GPG key (CI-only, no passphrase)
#   2. dotsecenv init config           -- create a config pointing at our vault
#   3. dotsecenv init vault            -- create the encrypted vault file
#   4. dotsecenv login <FINGERPRINT>   -- record a signed login proof in config
#   5. dotsecenv secret store NAME     -- encrypt and append a secret
#   6. dotsecenv secret get NAME       -- decrypt and print the secret
#   7. dotsecenv vault describe        -- show identities and secret keys
#   8. dotsecenv validate              -- structural sanity check
#
# Everything happens inside a tempdir; no file outside $TMP is written.
# See ../README.md ("Safety conventions") for the isolation rules.

set -euo pipefail

# --- locate the binary -------------------------------------------------------

if command -v dotsecenv >/dev/null 2>&1; then
  BIN="$(command -v dotsecenv)"
elif [[ -x "$(git rev-parse --show-toplevel 2>/dev/null)/bin/dotsecenv" ]]; then
  BIN="$(git rev-parse --show-toplevel)/bin/dotsecenv"
else
  cat >&2 <<'EOF'
error: dotsecenv binary not found.
  - Install via https://get.dotsecenv.com/install.sh, or
  - Run `make build` from the repo root and re-run this script.
EOF
  exit 1
fi
echo "==> using binary: $BIN"

# --- isolated tempdir --------------------------------------------------------

TMP="$(mktemp -d)"
# Always clean up: remove the tempdir and shut down the per-tempdir gpg-agent.
trap 'rm -rf "$TMP"; gpgconf --kill all >/dev/null 2>&1 || true' EXIT

export GNUPGHOME="$TMP/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

CONFIG="$TMP/config"
VAULT="$TMP/vault"

echo "==> tempdir: $TMP"
echo "==> GNUPGHOME: $GNUPGHOME"

# --- generate an ephemeral GPG key ------------------------------------------

# RSA4096 is the most portable choice across GPG versions on CI runners and
# old Linux distributions. ED25519 is preferable on a modern machine.
echo "==> generating CI-only RSA-4096 key (no passphrase)"
"$BIN" identity create \
  --algo RSA4096 \
  --name "Quickstart Demo" \
  --email "quickstart@example.invalid" \
  --no-passphrase \
  >"$TMP/keygen.log" 2>&1

# Pull the fingerprint of the just-created key out of the keyring.
FINGERPRINT="$(gpg --list-keys --with-colons quickstart@example.invalid \
  | awk -F: '/^fpr:/ { print $10; exit }')"
echo "==> fingerprint: $FINGERPRINT"

# --- dotsecenv setup --------------------------------------------------------

echo "==> dotsecenv init config (pointing -v at our isolated vault path)"
"$BIN" -c "$CONFIG" init config -v "$VAULT"

echo "==> dotsecenv init vault"
"$BIN" -c "$CONFIG" init vault -v "$VAULT"

echo "==> dotsecenv login (records a signed login proof in the config)"
"$BIN" -c "$CONFIG" login "$FINGERPRINT"

# --- the actual secret roundtrip --------------------------------------------

echo "==> dotsecenv secret store DATABASE_PASSWORD"
# Read the value from stdin; that is the only way to write to a vault.
echo "my-database-password" | "$BIN" -c "$CONFIG" secret store DATABASE_PASSWORD

echo "==> dotsecenv secret get DATABASE_PASSWORD"
"$BIN" -c "$CONFIG" secret get DATABASE_PASSWORD

echo "==> dotsecenv secret get  (no args -> list keys, never values)"
"$BIN" -c "$CONFIG" secret get

# --- inspect & validate -----------------------------------------------------

echo "==> dotsecenv vault describe"
"$BIN" -c "$CONFIG" vault describe

echo "==> dotsecenv validate"
"$BIN" -c "$CONFIG" validate

echo
echo "==> done. Tempdir $TMP will be removed on exit."

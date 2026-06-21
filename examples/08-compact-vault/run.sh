#!/usr/bin/env bash
#
# 08-compact-vault/run.sh
#
# Demonstrates `dotsecenv vault compact`: dropping superseded secret-value
# versions while keeping every identity and every current identity's newest
# readable value.
#
# dotsecenv vaults are append-only. Every `secret store` adds a new value
# record; the old ones stay. Over time a vault accumulates superseded versions
# that no current identity needs. Compaction reads the access lists (never
# decrypts), keeps the newest value each current identity can read, and drops
# the rest. Deleted secrets are removed whole.
#
# Flow:
#   1. Alice and Bob each get a key in one shared keyring (demo simplification).
#   2. Alice inits the vault and stores several versions of two secrets, sharing
#      them with Bob so the latest value covers both identities.
#   3. Alice stores then forgets a throwaway secret, leaving a tombstone.
#   4. `vault compact --json` shows the plan (a dry run that writes nothing).
#   5. Back up, then `vault compact --yes` rewrites the vault.
#   6. validate + describe confirm the vault is intact and `secret get` still
#      returns the latest value.
#
# Everything runs against no-passphrase demo keys in a throwaway tempdir.

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
trap 'rm -rf "$TMP"; gpgconf --kill all >/dev/null 2>&1 || true' EXIT

GNUPGHOME="$TMP/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
export GNUPGHOME

CONFIG="$TMP/config"
VAULT="$TMP/vault"

echo "==> tempdir: $TMP"

# --- generate two identities -------------------------------------------------

echo "==> generate Alice and Bob keys"
"$BIN" identity create --algo RSA4096 --name "Alice (demo)" \
  --email "alice@example.invalid" --no-passphrase >"$TMP/alice-keygen.log" 2>&1
"$BIN" identity create --algo RSA4096 --name "Bob (demo)" \
  --email "bob@example.invalid" --no-passphrase >"$TMP/bob-keygen.log" 2>&1

ALICE_FP="$(gpg --list-keys --with-colons alice@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
BOB_FP="$(gpg --list-keys --with-colons bob@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
echo "==> Alice: $ALICE_FP"
echo "==> Bob:   $BOB_FP"

# --- bootstrap the vault as Alice -------------------------------------------

"$BIN" -c "$CONFIG" init config -v "$VAULT" >/dev/null
"$BIN" -c "$CONFIG" init vault  -v "$VAULT" >/dev/null
"$BIN" -c "$CONFIG" login "$ALICE_FP" >/dev/null

# `secret share` below adds Bob to the vault's identities the first time he is
# named as a recipient, so the vault tracks both keys as current.

# --- manufacture a bloated vault --------------------------------------------

echo
echo "==> store several versions of DB_PASSWORD and AWS_KEY"
echo "db-v1" | "$BIN" -c "$CONFIG" secret store DB_PASSWORD
echo "db-v2" | "$BIN" -c "$CONFIG" secret store DB_PASSWORD
echo "db-v3" | "$BIN" -c "$CONFIG" secret store DB_PASSWORD

echo "aws-v1" | "$BIN" -c "$CONFIG" secret store AWS_KEY
echo "aws-v2" | "$BIN" -c "$CONFIG" secret store AWS_KEY
echo "aws-v3" | "$BIN" -c "$CONFIG" secret store AWS_KEY
echo "aws-v4" | "$BIN" -c "$CONFIG" secret store AWS_KEY

# Share the latest of each with Bob. `secret store` encrypts only to the
# logged-in identity, so we share last to make the newest value readable by
# both Alice and Bob — then compaction collapses each secret to that one value.
echo "==> share the latest DB_PASSWORD and AWS_KEY with Bob"
"$BIN" -c "$CONFIG" secret share DB_PASSWORD "$BOB_FP" >/dev/null
"$BIN" -c "$CONFIG" secret share AWS_KEY "$BOB_FP" >/dev/null

echo "==> store then forget a throwaway secret (leaves a tombstone)"
echo "tmp" | "$BIN" -c "$CONFIG" secret store TEMP_TOKEN
"$BIN" -c "$CONFIG" secret forget TEMP_TOKEN >/dev/null

echo
echo "==> vault before compaction:"
"$BIN" -c "$CONFIG" vault describe
echo "    JSON lines (1 header + records): $(grep -c '^{' "$VAULT")"

# --- show the compaction plan (dry run, no write) ---------------------------

echo
echo "==> compaction plan (dry run; --json without --yes writes nothing):"
"$BIN" -c "$CONFIG" vault compact --json

# --- back up and apply ------------------------------------------------------

echo
echo "==> back up the vault, then compact"
cp "$VAULT" "$VAULT.bak"
"$BIN" -c "$CONFIG" vault compact --yes

echo
echo "==> vault after compaction:"
"$BIN" -c "$CONFIG" vault describe
echo "    JSON lines (1 header + records): $(grep -c '^{' "$VAULT")"

# --- verify -----------------------------------------------------------------

echo
echo "==> validate the compacted vault"
"$BIN" -c "$CONFIG" validate >/dev/null && echo "    validate: OK"

echo
echo "==> secret get still returns the latest value"
echo "    DB_PASSWORD expected: db-v3"
echo -n "    actual:              "
"$BIN" -c "$CONFIG" secret get DB_PASSWORD
echo "    AWS_KEY expected:     aws-v4"
echo -n "    actual:              "
"$BIN" -c "$CONFIG" secret get AWS_KEY

echo
echo "==> TEMP_TOKEN was deleted, so compaction removed it entirely:"
"$BIN" -c "$CONFIG" vault describe | grep -q TEMP_TOKEN \
  && echo "    TEMP_TOKEN still present (unexpected)" \
  || echo "    TEMP_TOKEN absent (as expected)"

echo
echo "==> done. Backup at $VAULT.bak; tempdir $TMP removed on exit."

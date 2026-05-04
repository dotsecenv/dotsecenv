#!/usr/bin/env bash
#
# 02-team-share-revoke/run.sh
#
# Demonstrates dotsecenv's multi-recipient sharing model end-to-end.
#
# Real production use puts each identity on a different machine. To make that
# faithful in a single shell, we run with TWO independent $GNUPGHOME
# directories and keep each user's secret key isolated to their own home.
# We then export only the *public* key when one user wants to share with the
# other (the same dance you would do via `gpg --export | gpg --import` between
# laptops).
#
# Flow:
#   1. ALICE's GNUPGHOME has only Alice's key. Alice initializes the vault
#      and stores API_KEY=v1.
#   2. Alice imports BOB's public key into her keyring (so dotsecenv can
#      encrypt to him) and `secret share`s the secret with Bob.
#   3. BOB's GNUPGHOME (which has only Bob's key) decrypts the secret. He sees
#      v1 because he was a recipient at the time it was stored.
#   4. Alice revokes Bob, then rotates API_KEY=v2. Because dotsecenv vaults
#      are append-only, all the old v1 entries are still there — but the new
#      v2 entry is encrypted only to Alice.
#   5. Bob can still decrypt the v1 entries (history doesn't get rewritten);
#      Bob CANNOT decrypt v2.
#
# This is the right mental model for production:
#   - `secret revoke FP` removes that fingerprint from the recipient set going
#     forward, but it does NOT destroy ciphertext that was already encrypted
#     to them.
#   - To make a secret unreadable to a former recipient, ROTATE it (overwrite
#     with a new value via `secret store`). That new entry is encrypted to
#     the current recipient set only.

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

ALICE_GNUPG="$TMP/alice-gnupg"
BOB_GNUPG="$TMP/bob-gnupg"
mkdir -p "$ALICE_GNUPG" "$BOB_GNUPG"
chmod 700 "$ALICE_GNUPG" "$BOB_GNUPG"

CONFIG="$TMP/config"
VAULT="$TMP/vault"

echo "==> tempdir: $TMP"

# --- generate Alice in her own keyring ---------------------------------------

echo "==> [Alice's keyring] generate Alice's key"
GNUPGHOME="$ALICE_GNUPG" "$BIN" identity create \
  --algo RSA4096 \
  --name "Alice (demo)" \
  --email "alice@example.invalid" \
  --no-passphrase \
  >"$TMP/alice-keygen.log" 2>&1

ALICE_FP="$(GNUPGHOME="$ALICE_GNUPG" gpg --list-keys --with-colons \
  alice@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
echo "==> Alice fingerprint: $ALICE_FP"

# --- generate Bob in his own keyring ----------------------------------------

echo "==> [Bob's keyring] generate Bob's key"
GNUPGHOME="$BOB_GNUPG" "$BIN" identity create \
  --algo RSA4096 \
  --name "Bob (demo)" \
  --email "bob@example.invalid" \
  --no-passphrase \
  >"$TMP/bob-keygen.log" 2>&1

BOB_FP="$(GNUPGHOME="$BOB_GNUPG" gpg --list-keys --with-colons \
  bob@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
echo "==> Bob fingerprint:   $BOB_FP"

# --- Bob exports his public key; Alice imports it ---------------------------

# In production: Bob runs `gpg --armor --export FP`, sends the output by email
# or chat, and Alice imports it. Same effect as the pipe below.
GNUPGHOME="$BOB_GNUPG" gpg --armor --export "$BOB_FP" \
  | GNUPGHOME="$ALICE_GNUPG" gpg --import 2>"$TMP/alice-import.log"

echo "==> Alice imported Bob's public key"

# --- bootstrap the vault as Alice -------------------------------------------

echo
echo "==> [Alice] init config + vault, login, store API_KEY=v1"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" init config -v "$VAULT" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" init vault  -v "$VAULT" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" login "$ALICE_FP" >/dev/null
echo "v1-shared" | GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" secret store API_KEY

echo "==> [Alice] share API_KEY with Bob"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" secret share API_KEY "$BOB_FP"

echo
echo "==> Vault now has both identities and one shared secret:"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" vault describe

# --- Bob reads the shared secret with his own keyring -----------------------

echo
echo "==> [Bob] login with Bob's keyring and decrypt API_KEY"
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$CONFIG" login "$BOB_FP" >/dev/null
echo "    expected: v1-shared"
echo -n "    actual:   "
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$CONFIG" secret get API_KEY

# --- revoke Bob and rotate --------------------------------------------------

echo
echo "==> [Alice] revoke Bob from API_KEY, then rotate API_KEY=v2"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" login "$ALICE_FP" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" secret revoke API_KEY "$BOB_FP"
echo "v2-rotated" | GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" secret store API_KEY

echo
echo "==> [Alice] reads the latest value (expected: v2-rotated)"
echo -n "    actual:   "
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$CONFIG" secret get API_KEY

# --- Bob tries again --------------------------------------------------------

echo
echo "==> [Bob] tries to read after revoke + rotate."
echo "    The append-only vault still contains the v1 entries Bob was a"
echo "    recipient of. dotsecenv falls back to the most recent entry Bob"
echo "    can still decrypt — so 'secret get' prints v1, NOT v2."
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$CONFIG" login "$BOB_FP" >/dev/null
echo -n "    actual:   "
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$CONFIG" secret get API_KEY

echo
echo "==> [Bob] secret get --all shows every entry he can decrypt."
echo "    Notice v2-rotated is absent: it was only ever encrypted to Alice."
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$CONFIG" secret get API_KEY --all

echo
echo "==> done. Tempdir $TMP will be removed on exit."

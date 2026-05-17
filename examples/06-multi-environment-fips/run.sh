#!/usr/bin/env bash
#
# 06-multi-environment-fips/run.sh
#
# A 3-environment dotsecenv setup (development / staging / production)
# with FIPS 186-5-compliant identities and per-environment access
# control. Each environment lives in its own vault file; each
# environment has its own GPG identity subset.
#
# Identity matrix:
#   Alice (developer): development, staging
#   Bob   (developer): development
#   Ops   (production):           staging, production
#
# All three identities are generated with ECC P-384, which satisfies
# the FIPS 186-5 approved_algorithms allow-list in
# policy.d/00-corp-fips.yaml. To make policy actively enforced on a
# real machine, install that fragment to /etc/dotsecenv/policy.d/.
# See this directory's README.md for the install command and the
# distinction between FIPS 186-5 algorithm enforcement (policy.d) and
# FIPS 140-3 module validation (GOFIPS140 build flag).
#
# What this script does NOT cover:
#   - Installing /etc/dotsecenv/policy.d/ (requires root; out of scope
#     for a single-shell demo).
#   - FIPS 140-3 module locking (GOFIPS140=v1.26.0 build flag;
#     compile-time concern, not run time).

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
OPS_GNUPG="$TMP/ops-gnupg"
mkdir -p "$ALICE_GNUPG" "$BOB_GNUPG" "$OPS_GNUPG"
chmod 700 "$ALICE_GNUPG" "$BOB_GNUPG" "$OPS_GNUPG"

VAULT_DEV="$TMP/vault-dev"
VAULT_STAGING="$TMP/vault-staging"
VAULT_PROD="$TMP/vault-prod"
ALICE_CONFIG="$TMP/config-alice.yaml"
BOB_CONFIG="$TMP/config-bob.yaml"
OPS_CONFIG="$TMP/config-ops.yaml"

echo "==> tempdir: $TMP"

# --- generate three FIPS 186-5 identities (ECC P-384) ------------------------

echo "==> Generating ECC P-384 identities (FIPS 186-5 approved)"

GNUPGHOME="$ALICE_GNUPG" "$BIN" identity create --algo P384 \
  --name "Alice (demo)" --email "alice@example.invalid" --no-passphrase \
  >"$TMP/alice-keygen.log" 2>&1
GNUPGHOME="$BOB_GNUPG" "$BIN" identity create --algo P384 \
  --name "Bob (demo)" --email "bob@example.invalid" --no-passphrase \
  >"$TMP/bob-keygen.log" 2>&1
GNUPGHOME="$OPS_GNUPG" "$BIN" identity create --algo P384 \
  --name "Ops (demo)" --email "ops@example.invalid" --no-passphrase \
  >"$TMP/ops-keygen.log" 2>&1

ALICE_FP="$(GNUPGHOME="$ALICE_GNUPG" gpg --list-keys --with-colons \
  alice@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
BOB_FP="$(GNUPGHOME="$BOB_GNUPG" gpg --list-keys --with-colons \
  bob@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"
OPS_FP="$(GNUPGHOME="$OPS_GNUPG" gpg --list-keys --with-colons \
  ops@example.invalid | awk -F: '/^fpr:/ { print $10; exit }')"

echo "    Alice (dev + staging):       $ALICE_FP"
echo "    Bob   (dev only):            $BOB_FP"
echo "    Ops   (staging + production): $OPS_FP"

# --- exchange public keys ----------------------------------------------------
#
# In production, public keys travel between machines by email, chat, or a
# keyserver. Each user's GNUPGHOME ends up with the public keys of every
# recipient they need to encrypt to. In this demo we collapse that into
# straight `gpg --export | gpg --import` pipes.

# Alice encrypts to Bob (dev vault) and Ops (staging vault).
GNUPGHOME="$BOB_GNUPG" gpg --armor --export "$BOB_FP" \
  | GNUPGHOME="$ALICE_GNUPG" gpg --import 2>/dev/null
GNUPGHOME="$OPS_GNUPG" gpg --armor --export "$OPS_FP" \
  | GNUPGHOME="$ALICE_GNUPG" gpg --import 2>/dev/null

# --- Alice bootstraps vault-dev and vault-staging ----------------------------

echo
echo "==> Alice creates vault-dev (recipients: Alice + Bob)"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  init config -v "$VAULT_DEV" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  init vault -v "$VAULT_DEV" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  login "$ALICE_FP" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  identity add "$BOB_FP" -v "$VAULT_DEV" >/dev/null
echo "postgres://dev.local/app" \
  | GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
      secret store DATABASE_URL -v "$VAULT_DEV"

echo "==> Alice creates vault-staging (recipients: Alice + Ops)"
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  init vault -v "$VAULT_STAGING" >/dev/null
GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
  identity add "$OPS_FP" -v "$VAULT_STAGING" >/dev/null
echo "postgres://staging.internal/app" \
  | GNUPGHOME="$ALICE_GNUPG" "$BIN" -c "$ALICE_CONFIG" \
      secret store DATABASE_URL -v "$VAULT_STAGING"

# --- Ops bootstraps vault-prod (no developer recipients) ---------------------

echo "==> Ops creates vault-prod (recipients: Ops only)"
GNUPGHOME="$OPS_GNUPG" "$BIN" -c "$OPS_CONFIG" \
  init config -v "$VAULT_PROD" >/dev/null
GNUPGHOME="$OPS_GNUPG" "$BIN" -c "$OPS_CONFIG" \
  init vault -v "$VAULT_PROD" >/dev/null
GNUPGHOME="$OPS_GNUPG" "$BIN" -c "$OPS_CONFIG" \
  login "$OPS_FP" >/dev/null
echo "postgres://prod.internal/app" \
  | GNUPGHOME="$OPS_GNUPG" "$BIN" -c "$OPS_CONFIG" \
      secret store DATABASE_URL -v "$VAULT_PROD"

# --- Bob bootstraps his own config (dev only) --------------------------------

GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$BOB_CONFIG" \
  init config -v "$VAULT_DEV" >/dev/null
GNUPGHOME="$BOB_GNUPG" "$BIN" -c "$BOB_CONFIG" \
  login "$BOB_FP" >/dev/null

# --- access matrix -----------------------------------------------------------

attempt() {
  local gnupg="$1"; local cfg="$2"; local vault="$3"
  if GNUPGHOME="$gnupg" "$BIN" -c "$cfg" \
       secret get DATABASE_URL -v "$vault" >/dev/null 2>&1; then
    printf "%-8s" "OK"
  else
    printf "%-8s" "denied"
  fi
}

echo
echo "==> Access matrix (each user attempts to decrypt DATABASE_URL in each vault)"
printf "    %-6s  %-8s%-8s%-8s\n" "USER" "DEV" "STAGING" "PROD"

printf "    %-6s  " "Alice"
attempt "$ALICE_GNUPG" "$ALICE_CONFIG" "$VAULT_DEV"
attempt "$ALICE_GNUPG" "$ALICE_CONFIG" "$VAULT_STAGING"
attempt "$ALICE_GNUPG" "$ALICE_CONFIG" "$VAULT_PROD"
echo

printf "    %-6s  " "Bob"
attempt "$BOB_GNUPG" "$BOB_CONFIG" "$VAULT_DEV"
attempt "$BOB_GNUPG" "$BOB_CONFIG" "$VAULT_STAGING"
attempt "$BOB_GNUPG" "$BOB_CONFIG" "$VAULT_PROD"
echo

printf "    %-6s  " "Ops"
attempt "$OPS_GNUPG" "$OPS_CONFIG" "$VAULT_DEV"
attempt "$OPS_GNUPG" "$OPS_CONFIG" "$VAULT_STAGING"
attempt "$OPS_GNUPG" "$OPS_CONFIG" "$VAULT_PROD"
echo

cat <<'EOF'

    Expected:
        Alice   OK      OK      denied
        Bob     OK      denied  denied
        Ops     denied  OK      OK

The "denied" cells are the cryptographic enforcement at work. A user
whose fingerprint is not on a vault's recipient list has no GPG
session key for that vault's entries, regardless of file access.

EOF

# --- FIPS 186-5 policy installation hint ------------------------------------

cat <<EOF
==> FIPS 186-5 policy fragment ships at policy.d/00-corp-fips.yaml.
    Identities in this demo (ECC P-384) already comply. To enforce
    compliance on a real machine for every user of the binary:

      sudo install -o root -g root -m 0644 \\
        policy.d/00-corp-fips.yaml /etc/dotsecenv/policy.d/00-corp-fips.yaml
      dotsecenv policy validate
      # expect exit code 0 and: policy valid (1 fragment(s) in /etc/dotsecenv/policy.d)

    FIPS 140-3 module validation is a separate, build-time concern:
      GOFIPS140=v1.26.0 go build -o dotsecenv ./cmd/dotsecenv
    See https://dotsecenv.com/concepts/compliance/#module-locking
    for the validated-module discussion.

==> done. Tempdir $TMP will be removed on exit.
EOF

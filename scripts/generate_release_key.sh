#!/bin/bash
set -e

# Generates the dotsecenv CI release-signing GPG key.
#
# Key shape: signature-only, no subkeys. Just a single RSA-4096 primary
# with [SC] (sign + certify) capability. Signing the primary is what
# all our release ops do — archive signatures (GoReleaser), checksums.txt,
# deb/rpm/arch package signatures, the homebrew cask commit, plugin
# publish commits and tags. None of these are encryption operations, so
# we don't generate an encryption subkey.
#
# This avoids a footgun where `git commit -S` against the primary keyid
# fails with "No secret key" when the key was exported via
# --export-secret-subkeys (primary secret stripped). With a no-subkey
# key, `--export-secret-keys` is the only sensible export and the
# primary's secret is always present in CI.

# Use a temporary keyring to avoid polluting the user's
export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"

echo "Generating Key in temporary keyring: $GNUPGHOME"

echo "Enter Passphrase (stdin):"
read -r PASSPHRASE

if [ -z "$PASSPHRASE" ]; then
  echo "Error: Passphrase cannot be empty"
  exit 1
fi

# Batch config. Ref:
# https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
cat > "$GNUPGHOME/params" <<EOF
%echo Generating dotsecenv release-signing key
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Preferences: AES256 SHA512 Uncompressed
Name-Real: DotSecEnv Releases
Name-Comment: Automated Release Signing Key
Name-Email: release@dotsecenv.com
Expire-Date: 2y
Passphrase: $PASSPHRASE
%commit
%echo done
EOF

gpg --batch --generate-key "$GNUPGHOME/params"

echo ""
echo "=================================================================="
echo "PUBLIC KEY (publish this to https://get.dotsecenv.com/key.asc)"
echo "=================================================================="
gpg --armor --export "release@dotsecenv.com"

echo ""
echo "=================================================================="
echo "PRIVATE KEY BLOCK (set as GPG_PRIVATE_KEY secret)"
echo "=================================================================="
gpg --armor --export-secret-keys "release@dotsecenv.com"

echo ""
echo "=================================================================="
echo "Cleaning up..."
rm -rf "$GNUPGHOME"
echo "Done."

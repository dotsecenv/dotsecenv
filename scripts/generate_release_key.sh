#!/bin/bash
set -e

# Create a temporary directory for the keyring to avoid polluting the user's keyring
export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"

echo "Generating Key in temporary keyring: $GNUPGHOME"

echo "Enter Passphrase (stdin):"
read -r PASSPHRASE

if [ -z "$PASSPHRASE" ]; then
  echo "Error: Passphrase cannot be empty"
  exit 1
fi

# Create batch configuration file
# Ref: https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
cat > "$GNUPGHOME/params" <<EOF
%echo Generating a basic OpenPGP key
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: DotSecEnv Releases
Name-Comment: Automated Release Signing Key
Name-Email: release@dotsecenv.com
Expire-Date: 2y
Passphrase: $PASSPHRASE
%commit
%echo done
EOF

# Generate the key
gpg --batch --generate-key "$GNUPGHOME/params"

echo ""
echo "=================================================================="
echo "PRIVATE KEY BLOCK (Copy this to GPG_PRIVATE_KEY)"
echo "=================================================================="
gpg --armor --export-secret-keys "release@dotsecenv.com"

echo ""
echo "=================================================================="
echo "Cleaning up..."
rm -rf "$GNUPGHOME"
echo "Done."

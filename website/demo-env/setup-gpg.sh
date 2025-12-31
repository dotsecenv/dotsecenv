#!/bin/bash
# Generate a test GPG key for demo purposes
# Usage: setup-gpg.sh [directory]

set -e

WORK_DIR=
if [ -n "$1" ] && [ -d "$1" ]; then
    WORK_DIR="$1"
fi
if [ -z "$WORK_DIR" ]; then
    WORK_DIR=$(mktemp -d)
    echo "Warning: working directory not set or '$1' is not a directory, using temp directory '$WORK_DIR'" >&2
fi

BATCH_FILE="$WORK_DIR/gpg-batch"
IDENTITY="justaademo@dotsecenv.com"

cat > "$BATCH_FILE" <<EOF
%echo Generating demo GPG key...
Key-Type: RSA
Key-Length: 2048
Preferences: AES256 SHA512 Uncompressed
Name-Real: DotSecEnv Demo
Name-Email: $IDENTITY
Expire-Date: 0
%no-protection
%commit
%echo Done
EOF

gpg --batch --generate-key "$BATCH_FILE"
rm -f "$BATCH_FILE"

echo ""
echo "GPG key created for $IDENTITY:"
gpg --list-keys --keyid-format long

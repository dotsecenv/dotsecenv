#!/bin/bash
set -euo pipefail

# Arguments
BINARY_PATH="$1"

# Environment variables expected:
# - APPLE_CERTIFICATE_P12_BASE64
# - APPLE_CERTIFICATE_PASSWORD
# - APPLE_API_KEY_P8_BASE64
# - APPLE_API_KEY_ID
# - APPLE_API_ISSUER_ID
# - APPLE_TEAM_ID
# - RUNNER_TEMP

# Paths for cleanup
KEYCHAIN_PATH="$RUNNER_TEMP/signing.keychain-db"
CERT_PATH="$RUNNER_TEMP/certificate.p12"
API_KEY_DIR="$HOME/.private_keys"
API_KEY_PATH="$API_KEY_DIR/AuthKey_${APPLE_API_KEY_ID}.p8"
NOTARIZE_ZIP="$RUNNER_TEMP/notarize.zip"

# Cleanup function - runs on exit, error, or interrupt
cleanup() {
  echo "==> Cleaning up sensitive files..."
  rm -f "$CERT_PATH" "$API_KEY_PATH" "$NOTARIZE_ZIP" 2>/dev/null || true
  if security list-keychains | grep -q "$KEYCHAIN_PATH"; then
    security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
  fi
  echo "==> Cleanup complete"
}
trap cleanup EXIT

echo "==> Setting up keychain..."
KEYCHAIN_PASSWORD=$(openssl rand -base64 32)

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

echo "==> Importing certificate..."
echo "$APPLE_CERTIFICATE_P12_BASE64" | base64 --decode > "$CERT_PATH"
security import "$CERT_PATH" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -A -t cert -f pkcs12 \
  -k "$KEYCHAIN_PATH"
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security list-keychain -d user -s "$KEYCHAIN_PATH"

echo "==> Setting up API key..."
mkdir -p "$API_KEY_DIR"
echo "$APPLE_API_KEY_P8_BASE64" | base64 --decode > "$API_KEY_PATH"

echo "==> Finding signing identity..."
SIGNING_IDENTITY=$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" \
  | grep "Developer ID Application" \
  | grep "$APPLE_TEAM_ID" \
  | head -1 \
  | sed 's/.*"\(.*\)".*/\1/')

if [ -z "$SIGNING_IDENTITY" ]; then
  echo "ERROR: Could not find Developer ID Application certificate for team $APPLE_TEAM_ID"
  exit 1
fi
echo "Using identity: $SIGNING_IDENTITY"

echo "==> Code signing binary..."
codesign --force --options runtime \
  --sign "$SIGNING_IDENTITY" \
  --timestamp \
  "$BINARY_PATH"

echo "==> Verifying signature..."
codesign --verify --verbose "$BINARY_PATH"

echo "==> Creating zip for notarization..."
ditto -c -k --keepParent "$BINARY_PATH" "$NOTARIZE_ZIP"

echo "==> Submitting for notarization..."
xcrun notarytool submit "$NOTARIZE_ZIP" \
  --key "$API_KEY_PATH" \
  --key-id "$APPLE_API_KEY_ID" \
  --issuer "$APPLE_API_ISSUER_ID" \
  --wait \
  --timeout 30m

echo "==> Notarization complete!"
# Cleanup runs automatically via trap

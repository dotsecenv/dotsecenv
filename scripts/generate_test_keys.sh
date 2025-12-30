#!/bin/bash
set -e

# Create a temporary directory for the GPG home
TEMP_DIR=$(mktemp -d)
export GNUPGHOME="$TEMP_DIR"

echo "Generating keys in temporary directory: $TEMP_DIR"

# helper to generate key
generate_key() {
    local algo="$1"
    local name="$2"
    local email="$3"

    echo "Generating $name ($algo)..."
    
    cat > "$TEMP_DIR/params" <<EOF
Key-Type: $algo
Key-Length: 3072
Key-Usage: sign
Subkey-Type: $algo
Subkey-Length: 3072
Subkey-Usage: encrypt
Preferences: AES256 SHA512 Uncompressed
Name-Real: $name
Name-Email: $email
Expire-Date: 0
%no-protection
%commit
EOF

   # Adjust for ECC
   if [[ "$algo" == "ECDSA" ]] || [[ "$algo" == "EdDSA" ]] || [[ "$algo" == "P-384" ]] || [[ "$algo" == "P-521" ]] || [[ "$algo" == "Ed25519" ]]; then
       # For ECC, we need to specify curve in Key-Curve instead of Key-Length
       # But gpg batch mode for ECC is a bit specific. 
       # Key-Type: ECDSA or EdDSA (or RSA, DSA)
       # Key-Curve: P-384 etc.
       
       # Extract curve
       local type="ECDSA"
       local curve="P-384"
       
       if [[ "$algo" == "P-384" ]]; then
           type="ECDSA"
           curve="nistp384"
       elif [[ "$algo" == "P-521" ]]; then
           type="ECDSA"
           curve="nistp521"
       elif [[ "$algo" == "Ed25519" ]]; then
           type="EdDSA"
           curve="Ed25519"
       fi

       cat > "$TEMP_DIR/params" <<EOF
Key-Type: $type
Key-Curve: $curve
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: $curve
Subkey-Usage: encrypt
Preferences: AES256 SHA512 Uncompressed
Name-Real: $name
Name-Email: $email
Expire-Date: 0
%no-protection
%commit
EOF
   else
       # Default (RSA mainly)
       cat > "$TEMP_DIR/params" <<EOF
Key-Type: $algo
Key-Length: 3072
Key-Usage: sign
Subkey-Type: $algo
Subkey-Length: 3072
Subkey-Usage: encrypt
Preferences: AES256 SHA512 Uncompressed
Name-Real: $name
Name-Email: $email
Expire-Date: 0
%no-protection
%commit
EOF
   fi
   
   # Special case for RSA 4096
   if [[ "$name" == *"4096"* ]]; then
        cat > "$TEMP_DIR/params" <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Preferences: AES256 SHA512 Uncompressed
Name-Real: $name
Name-Email: $email
Expire-Date: 0
%no-protection
%commit
EOF
   fi

    gpg --batch --generate-key "$TEMP_DIR/params"
}

# Generate RSA 3072
generate_key "RSA" "Test RSA 3072" "rsa3072@example.com"

# Generate RSA 4096
generate_key "RSA" "Test RSA 4096" "rsa4096@example.com"

# Generate ECC P-384
generate_key "P-384" "Test ECC P-384" "p384@example.com"

# Generate ECC P-521
generate_key "P-521" "Test ECC P-521" "p521@example.com"

echo ""
echo "Keys generated successfully."
echo "Public keys:"
gpg --list-keys

echo ""
echo "Secret keys:"
gpg --list-secret-keys

echo ""
echo "To export these keys:"
echo "export GNUPGHOME=$TEMP_DIR"
echo "gpg --export -a > public_keys.asc"
echo "gpg --export-secret-keys -a > secret_keys.asc"

echo ""
echo "Directory $TEMP_DIR preserved for manual inspection."

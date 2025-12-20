package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ComputeHash computes a cryptographic hash of the data based on the algorithm bits.
// Uses SHA-512 for keys >= 256 bits (RSA 4096, ECC P-521), SHA-256 for smaller keys.
// This follows security best practices for matching hash strength to key strength.
func ComputeHash(data []byte, algorithmBits int) string {
	if algorithmBits >= 256 {
		// Use SHA-512 for stronger keys
		hash := sha512.Sum512(data)
		return hex.EncodeToString(hash[:])
	}
	// Use SHA-256 for standard keys
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ComputeIdentityHash computes the canonical hash for an identity.
// The canonical format includes all identity fields in a deterministic order:
// added_at:algorithm:algorithm_bits:curve:created_at:expires_at:fingerprint:public_key:signed_by:uid
func ComputeIdentityHash(identity *Identity) string {
	expiresAtStr := ""
	if identity.ExpiresAt != nil {
		expiresAtStr = identity.ExpiresAt.Format(time.RFC3339Nano)
	}

	// Reconstruct the canonical data with all fields
	canonicalData := fmt.Sprintf("%s:%s:%d:%s:%s:%s:%s:%s:%s:%s",
		identity.AddedAt.Format(time.RFC3339Nano),
		identity.Algorithm,
		identity.AlgorithmBits,
		identity.Curve,
		identity.CreatedAt.Format(time.RFC3339Nano),
		expiresAtStr,
		identity.Fingerprint,
		identity.PublicKey,
		identity.SignedBy,
		identity.UID)

	return ComputeHash([]byte(canonicalData), identity.AlgorithmBits)
}

// VerifyIdentitySignature verifies the cryptographic signature of an identity.
// It performs a two-step verification:
// 1. Computes the hash of canonical data and verifies it matches the stored hash
// 2. Verifies the signature of the hash using the signer's public key
//
// Returns true if both verifications pass, false otherwise.
func VerifyIdentitySignature(identity *Identity, signer *Identity) (bool, error) {
	if signer == nil {
		return false, fmt.Errorf("signing identity not found: %s", identity.SignedBy)
	}

	// Step 1: Compute hash of canonical data and verify it matches stored hash
	computedHash := ComputeIdentityHash(identity)

	if computedHash != identity.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, identity.Hash)
	}

	// Step 2: Verify signature of the hash using the signer's public key
	return VerifySignatureWithPublicKey(signer.PublicKey, []byte(identity.Hash), identity.Signature)
}

// VerifySignatureWithPublicKey performs cryptographic verification of a detached signature.
// The signature is stored as hex-encoded binary (created by gpg --detach-sign).
// The public key is base64-encoded and stored in the vault's identities list.
//
// Verification process:
//  1. Decode the public key from base64 encoding
//  2. Parse the public key using ProtonMail's openpgp library
//  3. Decode the signature from hex encoding
//  4. Use openpgp.CheckDetachedSignature to verify the signature against the data
//
// This approach catches:
//   - Any modification to the signed data (verification fails)
//   - Forged signatures (verification fails without correct private key)
//   - Corrupted or tampered signatures (invalid hex or parsing errors)
//   - Invalid public key encoding or format
//
// Implementation uses github.com/ProtonMail/go-crypto/openpgp which:
//   - Supports both armored and binary public key formats
//   - Verifies detached signatures in OpenPGP format
//   - Does not require external GPG process
//   - Is compatible with standard GPG detached signatures
func VerifySignatureWithPublicKey(publicKeyBase64 string, data []byte, signatureHex string) (bool, error) {
	// Decode the public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key from base64: %v", err)
	}

	// Parse the public key using ProtonMail's openpgp
	keyReader := bytes.NewReader(publicKeyBytes)
	keyEntities, err := openpgp.ReadArmoredKeyRing(keyReader)
	if err != nil {
		// If armored format fails, try binary format
		keyReader = bytes.NewReader(publicKeyBytes)
		keyEntities, err = openpgp.ReadKeyRing(keyReader)
		if err != nil {
			return false, fmt.Errorf("failed to parse public key: %v", err)
		}
	}

	if len(keyEntities) == 0 {
		return false, fmt.Errorf("no public keys found in key data")
	}

	// Decode signature from hex
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature from hex: %v", err)
	}

	// Verify the signature against the data
	// The signature should be a detached signature (binary format)
	sigReader := bytes.NewReader(sigBytes)
	dataReader := bytes.NewReader(data)

	// CheckDetachedSignature expects an EntityList (KeyRing interface)
	_, err = openpgp.CheckDetachedSignature(keyEntities, dataReader, sigReader, &packet.Config{})
	if err == nil {
		return true, nil // Signature verified
	}

	return false, fmt.Errorf("signature verification failed: %v", err)
}

// IsValidHex checks if a string is valid hexadecimal encoding.
// Returns true if the string contains only hex characters (0-9, a-f, A-F)
// and has an even length.
func IsValidHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, ch := range s {
		isDigit := ch >= '0' && ch <= '9'
		isHexLower := ch >= 'a' && ch <= 'f'
		isHexUpper := ch >= 'A' && ch <= 'F'
		if !isDigit && !isHexLower && !isHexUpper {
			return false
		}
	}
	return true
}

// IsValidBase64 checks if a string is valid base64 encoding (loose check).
// Returns true if the string contains only valid base64 characters
// (A-Z, a-z, 0-9, +, /, =).
func IsValidBase64(s string) bool {
	for _, ch := range s {
		isUpper := ch >= 'A' && ch <= 'Z'
		isLower := ch >= 'a' && ch <= 'z'
		isDigit := ch >= '0' && ch <= '9'
		if !isUpper && !isLower && !isDigit && ch != '+' && ch != '/' && ch != '=' {
			return false
		}
	}
	return true
}

// ValidateIdentity performs comprehensive validation of an identity.
// It checks:
//   - Required fields are present (Signature, PublicKey)
//   - Signature is valid hex encoding
//   - Signature is cryptographically valid
//
// Returns nil if valid, or an error describing the validation failure.
func ValidateIdentity(identity *Identity, signer *Identity) error {
	if identity.Signature == "" {
		return fmt.Errorf("missing signature field")
	}
	if identity.PublicKey == "" {
		return fmt.Errorf("missing public_key field")
	}
	if !IsValidHex(identity.Signature) {
		return fmt.Errorf("signature is not valid hex encoding")
	}

	// Cryptographically verify the signature
	valid, err := VerifyIdentitySignature(identity, signer)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("signature verification failed - possible tampering")
	}

	return nil
}

// ValidateIdentitiesOrder checks that identities are sorted by AddedAt (most recent last).
// This is required for append-only vault operations.
func ValidateIdentitiesOrder(identities []Identity) error {
	if len(identities) <= 1 {
		return nil
	}

	for i := 0; i < len(identities)-1; i++ {
		current := identities[i].AddedAt
		next := identities[i+1].AddedAt
		if current.After(next) {
			return fmt.Errorf("identities not sorted by added_at (most recent last): identity[%d]=%s, identity[%d]=%s",
				i, current.Format(time.RFC3339), i+1, next.Format(time.RFC3339))
		}
	}

	return nil
}

// GetIdentitySigningData returns the canonical data string used for signing an identity.
// This is the data that should be hashed and signed when creating an identity signature.
func GetIdentitySigningData(identity *Identity) string {
	expiresAtStr := ""
	if identity.ExpiresAt != nil {
		expiresAtStr = identity.ExpiresAt.Format(time.RFC3339Nano)
	}

	return fmt.Sprintf("%s:%s:%d:%s:%s:%s:%s:%s:%s:%s",
		identity.AddedAt.Format(time.RFC3339Nano),
		identity.Algorithm,
		identity.AlgorithmBits,
		identity.Curve,
		identity.CreatedAt.Format(time.RFC3339Nano),
		expiresAtStr,
		identity.Fingerprint,
		identity.PublicKey,
		identity.SignedBy,
		identity.UID)
}

// NormalizeFingerprint normalizes a GPG fingerprint to uppercase without spaces.
func NormalizeFingerprint(fingerprint string) string {
	// Remove spaces and convert to uppercase
	return strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))
}

// CompareFingerprints compares two fingerprints for equality, ignoring case and spaces.
func CompareFingerprints(fp1, fp2 string) bool {
	return NormalizeFingerprint(fp1) == NormalizeFingerprint(fp2)
}

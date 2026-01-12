package vault

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// ComputeSecretHash computes the canonical hash for a secret.
// The canonical format includes: added_at:key:signed_by
func ComputeSecretHash(secret *Secret, algorithmBits int) string {
	// Canonical data format: secret:added_at:key:signed_by
	canonicalData := fmt.Sprintf("secret:%s:%s:%s",
		secret.AddedAt.Format(time.RFC3339Nano),
		secret.Key,
		secret.SignedBy)

	return identity.ComputeHash([]byte(canonicalData), algorithmBits)
}

// ComputeSecretValueHash computes the canonical hash for a secret value.
// The canonical format includes: added_at:available_to:signed_by:value
// The available_to list is joined with commas for deterministic representation.
func ComputeSecretValueHash(value *SecretValue, secretKey string, algorithmBits int) string {
	// Join recipients with commas for deterministic representation
	availableTo := strings.Join(value.AvailableTo, ",")
	// Canonical data format: value:added_at:secret_key:available_to:signed_by:value:deleted
	canonicalData := fmt.Sprintf("value:%s:%s:%s:%s:%s:%t",
		value.AddedAt.Format(time.RFC3339Nano),
		secretKey,
		availableTo,
		value.SignedBy,
		value.Value,
		value.Deleted)

	return identity.ComputeHash([]byte(canonicalData), algorithmBits)
}

// VerifySecretSignature verifies the cryptographic signature of a secret.
// It performs a two-step verification:
// 1. Computes the hash of canonical data and verifies it matches the stored hash
// 2. Verifies the signature of the hash using the signer's public key
//
// Returns true if both verifications pass, false otherwise.
func VerifySecretSignature(secret *Secret, signingIdentity *Identity) (bool, error) {
	// Step 1: Verify hash (tampering detection)
	computedHash := ComputeSecretHash(secret, signingIdentity.AlgorithmBits)
	if computedHash != secret.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, secret.Hash)
	}

	// Step 2: Verify signature of hash (identity verification)
	return identity.VerifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(secret.Hash), secret.Signature)
}

// VerifySecretValueSignature verifies the cryptographic signature of a secret value.
// It performs a two-step verification:
// 1. Computes the hash of canonical data and verifies it matches the stored hash
// 2. Verifies the signature of the hash using the signer's public key
//
// Returns true if both verifications pass, false otherwise.
func VerifySecretValueSignature(value *SecretValue, secretKey string, signingIdentity *Identity) (bool, error) {
	// Step 1: Verify hash (tampering detection)
	computedHash := ComputeSecretValueHash(value, secretKey, signingIdentity.AlgorithmBits)
	if computedHash != value.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, value.Hash)
	}

	// Step 2: Verify signature of hash (identity verification)
	return identity.VerifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(value.Hash), value.Signature)
}

// ValidateSecret performs comprehensive validation of a secret.
// It checks:
//   - Required fields are present (Signature, SignedBy)
//   - Signature is valid hex encoding
//   - Signature is cryptographically valid
//   - All secret values are valid
//
// Returns nil if valid, or an error describing the validation failure.
func ValidateSecret(secret *Secret, signingIdentity *Identity) error {
	if secret.Signature == "" {
		return fmt.Errorf("missing signature field")
	}
	if secret.SignedBy == "" {
		return fmt.Errorf("missing signed_by field")
	}
	if !identity.IsValidHex(secret.Signature) {
		return fmt.Errorf("signature is not valid hex encoding")
	}

	// Cryptographically verify the signature
	valid, err := VerifySecretSignature(secret, signingIdentity)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("signature verification failed - possible tampering")
	}

	return nil
}

// ValidateSecretValue performs comprehensive validation of a secret value.
// It checks:
//   - Required fields are present (Signature, SignedBy)
//   - Signature is valid hex encoding
//   - Value is valid base64 encoding
//   - Signature is cryptographically valid
//
// Returns nil if valid, or an error describing the validation failure.
func ValidateSecretValue(value *SecretValue, secretKey string, signingIdentity *Identity) error {
	if value.Signature == "" {
		return fmt.Errorf("missing signature field")
	}
	if value.SignedBy == "" {
		return fmt.Errorf("missing signed_by field")
	}
	if !identity.IsValidHex(value.Signature) {
		return fmt.Errorf("signature is not valid hex encoding")
	}
	if !identity.IsValidBase64(value.Value) {
		return fmt.Errorf("value is not valid base64 encoding")
	}

	// Cryptographically verify the signature
	valid, err := VerifySecretValueSignature(value, secretKey, signingIdentity)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("signature verification failed - possible tampering")
	}

	return nil
}

// ValidateSecretsOrder checks that secrets values are sorted by AddedAt (most recent last).
// This is required for append-only vault operations.
func ValidateSecretsOrder(secrets []Secret) error {
	for i, secret := range secrets {
		if len(secret.Values) <= 1 {
			continue
		}

		for j := 0; j < len(secret.Values)-1; j++ {
			current := secret.Values[j].AddedAt
			next := secret.Values[j+1].AddedAt
			if current.After(next) {
				return fmt.Errorf("secret[%d] values not sorted by added_at (most recent last): value[%d]=%s, value[%d]=%s",
					i, j, current.Format(time.RFC3339), j+1, next.Format(time.RFC3339))
			}
		}
	}

	return nil
}

// ValidateAvailableToOrder checks that available_to fingerprints are sorted alphabetically.
// This ensures deterministic output for version control.
func ValidateAvailableToOrder(value *SecretValue) error {
	if len(value.AvailableTo) <= 1 {
		return nil
	}

	sortedFPs := make([]string, len(value.AvailableTo))
	copy(sortedFPs, value.AvailableTo)
	sort.Strings(sortedFPs)

	for i, fp := range value.AvailableTo {
		if fp != sortedFPs[i] {
			return fmt.Errorf("available_to fingerprints not sorted alphabetically at index %d", i)
		}
	}

	return nil
}

// GetSecretSigningData returns the canonical data string used for signing a secret.
// This is the data that should be hashed and signed when creating a secret signature.
func GetSecretSigningData(secret *Secret) string {
	return fmt.Sprintf("%s:%s:%s",
		secret.AddedAt.Format(time.RFC3339Nano),
		secret.Key,
		secret.SignedBy)
}

// GetSecretValueSigningData returns the canonical data string used for signing a secret value.
// This is the data that should be hashed and signed when creating a secret value signature.
func GetSecretValueSigningData(value *SecretValue) string {
	availableTo := strings.Join(value.AvailableTo, ",")
	return fmt.Sprintf("%s:%s:%s:%s",
		value.AddedAt.Format(time.RFC3339Nano),
		availableTo,
		value.SignedBy,
		value.Value)
}

// SortAvailableTo sorts the available_to fingerprints alphabetically (in-place).
// This should be called before signing to ensure deterministic output.
func SortAvailableTo(value *SecretValue) {
	sort.Strings(value.AvailableTo)
}

// ValidateSecretMetadata checks that all available_to fingerprints reference valid identities.
func ValidateSecretMetadata(secret *Secret, vault *Vault) error {
	// Build a map of valid fingerprints from identities
	validFPs := make(map[string]bool)
	for _, identity := range vault.Identities {
		validFPs[identity.Fingerprint] = true
	}

	// Check that all available_to fingerprints are valid
	for i, value := range secret.Values {
		for _, fp := range value.AvailableTo {
			if !validFPs[fp] {
				return fmt.Errorf("unknown fingerprint in values[%d].available_to: %s", i, fp)
			}
		}
	}

	return nil
}

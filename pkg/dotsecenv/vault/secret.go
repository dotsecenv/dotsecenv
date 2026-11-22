package vault

import (
	"fmt"
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

	// Step 2: Verify signature of hash (identity verification) with the key
	// the signer's fingerprint names
	if err := identity.VerifyKeyFingerprint(signingIdentity); err != nil {
		return false, err
	}
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

	// Step 2: Verify signature of hash (identity verification) with the key
	// the signer's fingerprint names
	if err := identity.VerifyKeyFingerprint(signingIdentity); err != nil {
		return false, err
	}
	return identity.VerifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(value.Hash), value.Signature)
}

// VerifySecretValue checks the hash and signature of a secret definition and
// of one of its values. Each signer must be an identity in v whose own entry
// verifies against its signer in v, and every key involved must match its
// fingerprint. That makes a valid signature proof that a holder of the named
// key signed, so the chain of identity signers is not followed further.
func (v Vault) VerifySecretValue(secret *Secret, value *SecretValue) error {
	signer, err := v.verifiedSigner(secret.SignedBy)
	if err != nil {
		return fmt.Errorf("secret definition: %w", err)
	}
	if ok, err := VerifySecretSignature(secret, signer); !ok {
		return fmt.Errorf("secret definition: %w", err)
	}
	signer, err = v.verifiedSigner(value.SignedBy)
	if err != nil {
		return fmt.Errorf("value added %s: %w", value.AddedAt.Format(time.RFC3339), err)
	}
	if ok, err := VerifySecretValueSignature(value, secret.Key, signer); !ok {
		return fmt.Errorf("value added %s: %w", value.AddedAt.Format(time.RFC3339), err)
	}
	return nil
}

// verifiedSigner returns the identity in v with fingerprint fp after checking
// its entry's hash and signature against the identity that signed it.
func (v Vault) verifiedSigner(fp string) (*Identity, error) {
	signer := v.GetIdentityByFingerprint(fp)
	if signer == nil {
		return nil, fmt.Errorf("signer %s is not an identity in the vault", fp)
	}
	if ok, err := identity.VerifyIdentitySignature(signer, v.GetIdentityByFingerprint(signer.SignedBy)); !ok {
		return nil, fmt.Errorf("identity %s: %w", fp, err)
	}
	return signer, nil
}

package gpg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// VerifySignature verifies a hex-encoded signature with a base64-encoded public key.
func VerifySignature(publicKeyBase64 string, data []byte, signatureHex string) (bool, error) {
	// Decode base64 public key to binary
	keyBinary, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key from base64: %w", err)
	}

	// Decode hex signature to binary
	signatureBinary, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature from hex: %w", err)
	}

	// Parse the public key
	publicKey, err := crypto.NewKey(keyBinary)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Use RFC9580 profile for consistency across all cryptographic operations
	pgp := crypto.PGPWithProfile(profile.RFC9580())

	// Create verifier
	verifier, err := pgp.Verify().VerificationKey(publicKey).New()
	if err != nil {
		return false, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Verify the signature (with encoding 0 for raw binary)
	verifyResult, err := verifier.VerifyDetached(data, signatureBinary, 0)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	// Check if there was a signature error
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		return false, sigErr
	}

	return true, nil
}

// VerifyIdentityHash verifies that an identity's hash matches its canonical data.
func VerifyIdentityHash(id *identity.Identity) (bool, error) {
	computedHash := identity.ComputeIdentityHash(id)
	if computedHash != id.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s", computedHash, id.Hash)
	}
	return true, nil
}

// VerifySecretHash verifies that a secret's hash matches its canonical data.
func VerifySecretHash(secret *vault.Secret, algorithmBits int) (bool, error) {
	computedHash := vault.ComputeSecretHash(secret, algorithmBits)
	if computedHash != secret.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s", computedHash, secret.Hash)
	}
	return true, nil
}

// VerifySecretValueHash verifies that a secret value's hash matches its canonical data.
func VerifySecretValueHash(value *vault.SecretValue, algorithmBits int) (bool, error) {
	computedHash := vault.ComputeSecretValueHash(value, algorithmBits)
	if computedHash != value.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s", computedHash, value.Hash)
	}
	return true, nil
}

// FullIdentityVerification performs complete verification of an identity:
// 1. Verifies the hash matches the canonical data
// 2. Verifies the signature using the signer's public key
func FullIdentityVerification(id *identity.Identity, signerPublicKeyBase64 string) error {
	// Step 1: Verify hash
	if valid, err := VerifyIdentityHash(id); !valid {
		return fmt.Errorf("identity hash verification failed: %w", err)
	}

	// Step 2: Verify signature
	valid, err := VerifySignature(signerPublicKeyBase64, []byte(id.Hash), id.Signature)
	if err != nil {
		return fmt.Errorf("identity signature verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("identity signature is invalid")
	}

	return nil
}

// FullSecretVerification performs complete verification of a secret:
// 1. Verifies the hash matches the canonical data
// 2. Verifies the signature using the signer's public key
func FullSecretVerification(secret *vault.Secret, signerPublicKeyBase64 string, algorithmBits int) error {
	// Step 1: Verify hash
	if valid, err := VerifySecretHash(secret, algorithmBits); !valid {
		return fmt.Errorf("secret hash verification failed: %w", err)
	}

	// Step 2: Verify signature
	valid, err := VerifySignature(signerPublicKeyBase64, []byte(secret.Hash), secret.Signature)
	if err != nil {
		return fmt.Errorf("secret signature verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("secret signature is invalid")
	}

	return nil
}

// FullSecretValueVerification performs complete verification of a secret value:
// 1. Verifies the hash matches the canonical data
// 2. Verifies the signature using the signer's public key
func FullSecretValueVerification(value *vault.SecretValue, signerPublicKeyBase64 string, algorithmBits int) error {
	// Step 1: Verify hash
	if valid, err := VerifySecretValueHash(value, algorithmBits); !valid {
		return fmt.Errorf("secret value hash verification failed: %w", err)
	}

	// Step 2: Verify signature
	valid, err := VerifySignature(signerPublicKeyBase64, []byte(value.Hash), value.Signature)
	if err != nil {
		return fmt.Errorf("secret value signature verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("secret value signature is invalid")
	}

	return nil
}

package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
	"gopkg.in/yaml.v3"
)

// ValidationError represents a validation error with context
type ValidationError struct {
	Level   string // "GLOBAL", "IDENTITY", "SECRET", "STRUCTURE"
	Message string
	Path    string // For errors in specific items
}

// validateYAMLStructure checks YAML formatting requirements
func validateYAMLStructure(filePath string) []ValidationError {
	var errors []ValidationError

	content, err := os.ReadFile(filePath)
	if err != nil {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("failed to read file: %v", err),
			Path:    filePath,
		})
		return errors
	}

	lines := strings.Split(string(content), "\n")

	// Check 1: 2-space indentation
	for i, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue // Skip empty lines and comments
		}

		// Count leading spaces
		leadingSpaces := 0
		for _, ch := range line {
			if ch == ' ' {
				leadingSpaces++
			} else if ch == '\t' {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: "YAML uses tabs instead of spaces",
					Path:    fmt.Sprintf("line %d", i+1),
				})
				break
			} else {
				break
			}
		}

		// Leading spaces should be multiples of 2
		if leadingSpaces > 0 && leadingSpaces%2 != 0 {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("invalid indentation: %d spaces (should be multiple of 2)", leadingSpaces),
				Path:    fmt.Sprintf("line %d", i+1),
			})
		}
	}

	return errors
}

// validateYAMLFieldOrder checks that YAML fields are in alphabetical order within their sections
func validateYAMLFieldOrder(filePath string) []ValidationError {
	var errors []ValidationError

	content, err := os.ReadFile(filePath)
	if err != nil {
		return errors
	}

	// Use yaml.v3 Node to preserve key order in the file
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("failed to parse YAML: %v", err),
			Path:    filePath,
		})
		return errors
	}

	// Get top-level keys in order from the file
	if node.Kind != yaml.MappingNode || len(node.Content) == 0 {
		return errors
	}

	topLevelKeys := make([]string, 0)
	// YAML nodes store content as key-value pairs: [key1, val1, key2, val2, ...]
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode {
			topLevelKeys = append(topLevelKeys, node.Content[i].Value)
		}
	}

	// Check if keys are in alphabetical order
	sortedKeys := make([]string, len(topLevelKeys))
	copy(sortedKeys, topLevelKeys)
	sort.Strings(sortedKeys)

	for i, key := range topLevelKeys {
		if i < len(sortedKeys) && key != sortedKeys[i] {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("top-level fields not in alphabetical order: found '%s', expected '%s'", topLevelKeys[i], sortedKeys[i]),
				Path:    "root",
			})
			break
		}
	}

	return errors
}

// validateVaultData checks vault logical structure
func validateVaultData(vaultData vault.Vault, manager *vault.Manager) []ValidationError {
	var errors []ValidationError

	// Check 1: Identities sorted by added_at (most recent last = ascending order)
	if len(vaultData.Identities) > 1 {
		for i := 0; i < len(vaultData.Identities)-1; i++ {
			current := vaultData.Identities[i].AddedAt
			next := vaultData.Identities[i+1].AddedAt
			if current.After(next) {
				errors = append(errors, ValidationError{
					Level:   "IDENTITY",
					Message: fmt.Sprintf("identities not sorted by added_at (most recent last): identity[%d]=%s, identity[%d]=%s", i, current, i+1, next),
					Path:    fmt.Sprintf("identities (%s, %s)", vaultData.Identities[i].UID, vaultData.Identities[i+1].UID),
				})
				break
			}
		}
	}

	// Check 2: Required fields in identities
	for i, identity := range vaultData.Identities {
		if identity.Signature == "" {
			errors = append(errors, ValidationError{
				Level:   "IDENTITY",
				Message: "missing signature field",
				Path:    fmt.Sprintf("identities[%d] (%s)", i, identity.UID),
			})
		}
		if identity.PublicKey == "" {
			errors = append(errors, ValidationError{
				Level:   "IDENTITY",
				Message: "missing public_key field",
				Path:    fmt.Sprintf("identities[%d] (%s)", i, identity.UID),
			})
		}

		// Check 3: Verify identity signatures are valid (cryptographic verification)
		if identity.Signature != "" {
			if !isValidHex(identity.Signature) {
				errors = append(errors, ValidationError{
					Level:   "IDENTITY",
					Message: "identity signature is not valid hex encoding",
					Path:    fmt.Sprintf("identities[%d] (%s)", i, identity.UID),
				})
			} else {
				// Cryptographically verify the signature
				valid, err := verifyIdentitySignature(&vaultData.Identities[i], &vaultData)
				if err != nil {
					errors = append(errors, ValidationError{
						Level:   "IDENTITY",
						Message: fmt.Sprintf("failed to verify identity signature: %v", err),
						Path:    fmt.Sprintf("identities[%d] (%s)", i, identity.UID),
					})
				} else if !valid {
					errors = append(errors, ValidationError{
						Level:   "IDENTITY",
						Message: "identity signature verification failed - possible tampering",
						Path:    fmt.Sprintf("identities[%d] (%s)", i, identity.UID),
					})
				}
			}
		}
	}

	// Check 3: Required fields in secrets and secret values
	for i, secret := range vaultData.Secrets {
		if secret.Signature == "" {
			errors = append(errors, ValidationError{
				Level:   "SECRET",
				Message: "secret has missing signature field",
				Path:    fmt.Sprintf("secrets[%d] (%s)", i, secret.Key),
			})
		}

		// Check secret value sorting (most recent last = ascending by added_at)
		if len(secret.Values) > 1 {
			for j := 0; j < len(secret.Values)-1; j++ {
				current := secret.Values[j].AddedAt
				next := secret.Values[j+1].AddedAt
				if current.After(next) {
					errors = append(errors, ValidationError{
						Level:   "SECRET",
						Message: fmt.Sprintf("secret values not sorted by added_at (most recent last): value[%d]=%s, value[%d]=%s", j, current, j+1, next),
						Path:    fmt.Sprintf("secrets[%d].values (%s)", i, secret.Key),
					})
					break
				}
			}
		}

		// Check each secret value
		for j, value := range secret.Values {
			if value.Signature == "" {
				errors = append(errors, ValidationError{
					Level:   "SECRET",
					Message: "secret value has missing signature field",
					Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
				})
			}

			// Check signed_by field is present and valid
			if value.SignedBy == "" {
				errors = append(errors, ValidationError{
					Level:   "SECRET",
					Message: "secret value has missing signed_by field",
					Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
				})
			}

			// Check available_to fingerprints are sorted alphabetically
			if len(value.AvailableTo) > 1 {
				sortedFPs := make([]string, len(value.AvailableTo))
				copy(sortedFPs, value.AvailableTo)
				sort.Strings(sortedFPs)

				for k, fp := range value.AvailableTo {
					if fp != sortedFPs[k] {
						errors = append(errors, ValidationError{
							Level:   "SECRET",
							Message: fmt.Sprintf("available_to fingerprints not sorted alphabetically at index %d", k),
							Path:    fmt.Sprintf("secrets[%d].values[%d].available_to (%s)", i, j, secret.Key),
						})
						break
					}
				}
			}
		}
	}

	// Check 4: Verify secret signatures are valid
	for i, secret := range vaultData.Secrets {
		// Verify signing identity exists
		signingIdentity := manager.GetIdentityByFingerprint(secret.SignedBy)
		if signingIdentity == nil {
			errors = append(errors, ValidationError{
				Level:   "SECRET",
				Message: fmt.Sprintf("signing identity not found: %s", secret.SignedBy),
				Path:    fmt.Sprintf("secrets[%d] (%s)", i, secret.Key),
			})
			continue
		}

		// Check secret signature is valid hex and cryptographically valid
		if secret.Signature != "" {
			if !isValidHex(secret.Signature) {
				errors = append(errors, ValidationError{
					Level:   "SECRET",
					Message: "secret signature is not valid hex encoding",
					Path:    fmt.Sprintf("secrets[%d] (%s)", i, secret.Key),
				})
			} else {
				// Cryptographically verify the signature
				valid, err := verifySecretSignature(&vaultData.Secrets[i], signingIdentity)
				if err != nil {
					errors = append(errors, ValidationError{
						Level:   "SECRET",
						Message: fmt.Sprintf("failed to verify secret signature: %v", err),
						Path:    fmt.Sprintf("secrets[%d] (%s)", i, secret.Key),
					})
				} else if !valid {
					errors = append(errors, ValidationError{
						Level:   "SECRET",
						Message: "secret signature verification failed - possible tampering",
						Path:    fmt.Sprintf("secrets[%d] (%s)", i, secret.Key),
					})
				}
			}
		}

		// Check each secret value signature is valid hex and cryptographically valid
		for j, value := range secret.Values {
			// Verify signing identity exists for this value
			valueSigningIdentity := manager.GetIdentityByFingerprint(value.SignedBy)
			if valueSigningIdentity == nil && value.SignedBy != "" {
				errors = append(errors, ValidationError{
					Level:   "SECRET",
					Message: fmt.Sprintf("signing identity not found for value: %s", value.SignedBy),
					Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
				})
				continue
			}

			if value.Signature != "" {
				if !isValidHex(value.Signature) {
					errors = append(errors, ValidationError{
						Level:   "SECRET",
						Message: "secret value signature is not valid hex encoding",
						Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
					})
				} else if valueSigningIdentity != nil {
					// Cryptographically verify the value signature
					valid, err := verifySecretValueSignature(&vaultData.Secrets[i].Values[j], secret.Key, valueSigningIdentity)
					if err != nil {
						errors = append(errors, ValidationError{
							Level:   "SECRET",
							Message: fmt.Sprintf("failed to verify secret value signature: %v", err),
							Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
						})
					} else if !valid {
						errors = append(errors, ValidationError{
							Level:   "SECRET",
							Message: "secret value signature verification failed - possible tampering",
							Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
						})
					}
				}
			}
		}
	}

	return errors
}

// validateSecretEncryption checks that all secret values can be decrypted
func validateSecretEncryption(vaultData vault.Vault) []ValidationError {
	var errors []ValidationError

	for i, secret := range vaultData.Secrets {
		for j, value := range secret.Values {
			// Try to base64 decode the value
			// This is a basic sanity check - actual decryption would require the private key
			if !isValidBase64(value.Value) {
				errors = append(errors, ValidationError{
					Level:   "SECRET",
					Message: "secret value is not valid base64",
					Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
				})
			}
		}
	}

	return errors
}

// validateSecretMetadata checks that all secrets have valid fingerprints in available_to
func validateSecretMetadata(vaultData vault.Vault) []ValidationError {
	var errors []ValidationError

	// Build a map of valid fingerprints from identities
	validFPs := make(map[string]bool)
	for _, identity := range vaultData.Identities {
		validFPs[identity.Fingerprint] = true
	}

	// Check that all available_to fingerprints are valid
	for i, secret := range vaultData.Secrets {
		for j, value := range secret.Values {
			for _, fp := range value.AvailableTo {
				if !validFPs[fp] {
					errors = append(errors, ValidationError{
						Level:   "SECRET",
						Message: fmt.Sprintf("unknown fingerprint in available_to: %s", fp),
						Path:    fmt.Sprintf("secrets[%d].values[%d] (%s)", i, j, secret.Key),
					})
				}
			}
		}
	}

	return errors
}

// validateVaultFileStructure checks the vault file structure (comments and entry references)
func validateVaultFileStructure(header *vault.Header, lines []string) []ValidationError {
	var errors []ValidationError

	if len(lines) < 3 {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("vault file too short: expected at least 3 lines, got %d", len(lines)),
			Path:    "vault file",
		})
		return errors
	}

	// Check header marker (line 1, index 0)
	if err := vault.ValidateHeaderMarker(lines[0]); err != nil {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("invalid header marker: %v", err),
			Path:    "line 1",
		})
	}

	// Check version from header JSON (line 2, index 1)
	if header != nil && (header.Version < vault.MinSupportedVersion || header.Version > vault.LatestFormatVersion) {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("unsupported vault format version %d (supported: v%d-v%d)", header.Version, vault.MinSupportedVersion, vault.LatestFormatVersion),
			Path:    "line 2 (header JSON)",
		})
	}

	// Check data marker (line 3, index 2)
	if lines[2] != vault.DataMarker {
		errors = append(errors, ValidationError{
			Level:   "STRUCTURE",
			Message: fmt.Sprintf("invalid data marker: expected %q, got %q", vault.DataMarker, lines[2]),
			Path:    "line 3",
		})
	}

	// Check that value entries match their header references
	for secretKey, index := range header.Secrets {
		for i, valueLine := range index.Values {
			if valueLine < 1 || valueLine > len(lines) {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("value line number %d out of range (file has %d lines)", valueLine, len(lines)),
					Path:    fmt.Sprintf("header.secrets[%s].values[%d]", secretKey, i),
				})
				continue
			}

			// Parse the entry at that line to verify secret key matches
			lineContent := lines[valueLine-1] // lines are 1-indexed
			entry, err := vault.UnmarshalEntry([]byte(lineContent))
			if err != nil {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("failed to parse entry at line %d: %v", valueLine, err),
					Path:    fmt.Sprintf("header.secrets[%s].values[%d]", secretKey, i),
				})
				continue
			}

			if entry.Type != vault.EntryTypeValue {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("line %d is not a value entry (type=%s)", valueLine, entry.Type),
					Path:    fmt.Sprintf("header.secrets[%s].values[%d]", secretKey, i),
				})
				continue
			}

			if entry.SecretKey != secretKey {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("value entry at line %d has secret=%q but header maps it to secret=%q", valueLine, entry.SecretKey, secretKey),
					Path:    fmt.Sprintf("header.secrets[%s].values[%d]", secretKey, i),
				})
			}
		}
	}

	return errors
}

// validateHeaderLineNumbers checks that header line numbers are valid
func validateHeaderLineNumbers(header *vault.Header) []ValidationError {
	var errors []ValidationError

	if header == nil {
		return errors
	}

	// Check 1: Identity line numbers are valid (positive, unique)
	// Note: uniqueness is guaranteed by the map, but we check for positive values
	// and collect for cross-reference validation
	allLineNumbers := make(map[int]string) // line -> description (for duplicate check)

	for fp, line := range header.Identities {
		if line < 1 {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("identity has invalid line number %d (must be >= 1)", line),
				Path:    fmt.Sprintf("header.identities[%s]", fp),
			})
		}
		if existing, exists := allLineNumbers[line]; exists {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("duplicate line number %d: used by %s and identity %s", line, existing, fp),
				Path:    "header",
			})
		}
		allLineNumbers[line] = fmt.Sprintf("identity %s", fp)
	}

	// Check 2: Secret definition and value line numbers
	for key, index := range header.Secrets {
		// Check definition line
		if index.Definition < 1 {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("secret has invalid definition line number %d (must be >= 1)", index.Definition),
				Path:    fmt.Sprintf("header.secrets[%s].secret", key),
			})
		}
		if existing, exists := allLineNumbers[index.Definition]; exists {
			errors = append(errors, ValidationError{
				Level:   "STRUCTURE",
				Message: fmt.Sprintf("duplicate line number %d: used by %s and secret %s definition", index.Definition, existing, key),
				Path:    "header",
			})
		}
		allLineNumbers[index.Definition] = fmt.Sprintf("secret %s definition", key)

		// Check value line numbers are strictly ascending (array order IS preserved from JSON)
		for i, valueLine := range index.Values {
			if valueLine < 1 {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("secret value has invalid line number %d (must be >= 1)", valueLine),
					Path:    fmt.Sprintf("header.secrets[%s].values[%d]", key, i),
				})
			}
			if existing, exists := allLineNumbers[valueLine]; exists {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("duplicate line number %d: used by %s and secret %s value[%d]", valueLine, existing, key, i),
					Path:    "header",
				})
			}
			allLineNumbers[valueLine] = fmt.Sprintf("secret %s value[%d]", key, i)

			// Check strictly ascending within the values array
			if i > 0 && index.Values[i-1] >= valueLine {
				errors = append(errors, ValidationError{
					Level:   "STRUCTURE",
					Message: fmt.Sprintf("secret value line numbers not strictly ascending: values[%d]=%d >= values[%d]=%d", i-1, index.Values[i-1], i, valueLine),
					Path:    fmt.Sprintf("header.secrets[%s].values", key),
				})
			}
		}
	}

	return errors
}

// isValidHex checks if a string is valid hex encoding
func isValidHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

// isValidBase64 checks if a string is valid base64 (loose check)
func isValidBase64(s string) bool {
	// Base64 characters are A-Z, a-z, 0-9, +, /, and = for padding
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

// ComputeHash computes a cryptographic hash of the data based on the algorithm bits
// Uses SHA-512 for keys >= 256 bits (RSA 4096, ECC P-521), SHA-256 for smaller keys
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

// ComputeIdentityHash computes the canonical hash for an identity
func ComputeIdentityHash(identity *vault.Identity) string {
	expiresAtStr := ""
	if identity.ExpiresAt != nil {
		expiresAtStr = identity.ExpiresAt.Format(time.RFC3339Nano)
	}

	// Reconstruct the canonical data with all fields: type:added_at:algorithm:algorithm_bits:curve:created_at:expires_at:fingerprint:public_key:signed_by:uid
	canonicalData := fmt.Sprintf("identity:%s:%s:%d:%s:%s:%s:%s:%s:%s:%s",
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

// verifyIdentitySignature verifies the cryptographic signature of an identity
func verifyIdentitySignature(identity *vault.Identity, vaultData *vault.Vault) (bool, error) {
	// Look up the signer's identity
	signingIdentity := vaultData.GetIdentityByFingerprint(identity.SignedBy)
	if signingIdentity == nil {
		return false, fmt.Errorf("signing identity not found: %s", identity.SignedBy)
	}

	// Step 1: Compute hash of canonical data and verify it matches stored hash
	computedHash := ComputeIdentityHash(identity)

	if computedHash != identity.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, identity.Hash)
	}

	// Step 2: Verify signature of the hash using the signer's public key
	return verifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(identity.Hash), identity.Signature)
}

// verifySecretSignature verifies the cryptographic signature of a secret
func verifySecretSignature(secret *vault.Secret, signingIdentity *vault.Identity) (bool, error) {
	// Reconstruct the canonical data with all fields: type:added_at:key:signed_by
	canonicalData := fmt.Sprintf("secret:%s:%s:%s",
		secret.AddedAt.Format(time.RFC3339Nano),
		secret.Key,
		secret.SignedBy)

	// Step 1: Verify hash (tampering detection)
	computedHash := ComputeHash([]byte(canonicalData), signingIdentity.AlgorithmBits)
	if computedHash != secret.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, secret.Hash)
	}

	// Step 2: Verify signature of hash (identity verification)
	return verifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(secret.Hash), secret.Signature)
}

// verifySecretValueSignature verifies the cryptographic signature of a secret value
func verifySecretValueSignature(value *vault.SecretValue, secretKey string, signingIdentity *vault.Identity) (bool, error) {
	// Reconstruct the canonical data with all fields: type:added_at:secret_key:available_to:signed_by:value:deleted
	// Join recipients with commas for deterministic representation (same as signing)
	availableTo := strings.Join(value.AvailableTo, ",")
	canonicalData := fmt.Sprintf("value:%s:%s:%s:%s:%s:%t",
		value.AddedAt.Format(time.RFC3339Nano),
		secretKey,
		availableTo,
		value.SignedBy,
		value.Value,
		value.Deleted)

	// Step 1: Verify hash (tampering detection)
	computedHash := ComputeHash([]byte(canonicalData), signingIdentity.AlgorithmBits)
	if computedHash != value.Hash {
		return false, fmt.Errorf("hash mismatch: computed %s, stored %s (data tampering detected)", computedHash, value.Hash)
	}

	// Step 2: Verify signature of hash (identity verification)
	return verifySignatureWithPublicKey(signingIdentity.PublicKey, []byte(value.Hash), value.Signature)
}

// verifySignatureWithPublicKey performs cryptographic verification of a detached signature.
// The signature is stored as hex-encoded binary (created by gpg --detach-sign).
// The public key is base64-encoded and stored in the vault's identities list.
//
// Verification process:
// 1. Decode the public key from base64 encoding
// 2. Parse the public key using ProtonMail's openpgp library
// 3. Decode the signature from hex encoding
// 4. Use openpgp.CheckDetachedSignature to verify the signature against the data
//
// This approach catches:
// - Any modification to the signed data (verification fails)
// - Forged signatures (verification fails without correct private key)
// - Corrupted or tampered signatures (invalid hex or parsing errors)
// - Invalid public key encoding or format
//
// Implementation uses github.com/ProtonMail/go-crypto/openpgp which:
// - Supports both armored and binary public key formats
// - Verifies detached signatures in OpenPGP format
// - Does not require external GPG process
// - Is compatible with standard GPG detached signatures
func verifySignatureWithPublicKey(publicKeyBase64 string, data []byte, signatureHex string) (bool, error) {
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

/*
SIGNATURE VERIFICATION APPROACH

This validator performs CRYPTOGRAPHIC SIGNATURE VERIFICATION using ProtonMail's go-crypto library.
All signatures are verified against the data using the public keys stored in the vault.
No external GPG process is required.

VERIFICATION IMPLEMENTATION:
- Uses github.com/ProtonMail/go-crypto/openpgp for signature verification
- Supports both armored and binary public key formats
- Verifies detached signatures created by gpg --detach-sign
- Handles multiple identities within a single key entity

WHAT IS VALIDATED:
- Signatures are cryptographically valid (matches data + public key)
- Signatures are valid hex encoding (required for storage format)
- Signing identities exist in the vault
- Signing identity references match the signed_by fields
- Public key can be parsed and used for verification

VERIFICATION PROCESS:

IDENTITY SIGNATURES:
- Signed by: the identity itself (self-signed)
- Data signed: canonical representation with all fields
- Verification: cryptographic check using identity's own public key
- Format: hex-encoded detached signature created by gpg --detach-sign

SECRET SIGNATURES:
- Signed by: the identity that created the secret (specified in secret.signed_by)
- Data signed: canonical metadata (created_at:key:signed_by)
- Verification: cryptographic check using signing identity's public key
- Format: hex-encoded detached signature created by gpg --detach-sign

SECRET VALUE SIGNATURES:
- Signed by: same identity as parent secret (specified in value.signed_by)
- Data signed: canonical metadata (added_at:available_to:signed_by:value)
- Verification: cryptographic check using signing identity's public key
- Format: hex-encoded detached signature created by gpg --detach-sign

TAMPERING DETECTION:
This approach catches:
- Any modification to the data (hash verification)
- Any modification to the signature (cryptographic verification fails)
- Forged signatures (verification fails without correct private key)
- Missing or invalid references to signing identities
- Missing required signature fields
- Corrupted or invalid base64-encoded public keys
- Corrupted or invalid hex-encoded signatures

SECURITY PROPERTIES:
- Two-layer verification: hash field provides tampering detection
- Signature field provides cryptographic proof of identity
- Requires actual private key for signing (stored in GPG keyring)
- Verification uses only public key data from vault
- No external GPG process required - pure Go implementation
*/

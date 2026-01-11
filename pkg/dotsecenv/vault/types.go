package vault

import (
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// Type aliases
type Identity = identity.Identity

// SecretValue represents an encrypted secret value with access control.
// Each secret can have multiple values (versions), each with its own
// list of identities that can decrypt it.
type SecretValue struct {
	AddedAt     time.Time `json:"added_at"`
	AvailableTo []string  `json:"available_to"` // List of fingerprints that can decrypt
	Deleted     bool      `json:"deleted,omitempty"`
	Hash        string    `json:"hash"`
	Signature   string    `json:"signature"`
	SignedBy    string    `json:"signed_by"`
	Value       string    `json:"value"` // Base64-encoded encrypted value
}

// Secret represents a secret with its encrypted values.
// Secrets are identified by a key (name) and can have multiple
// versioned values for different sets of recipients.
type Secret struct {
	AddedAt   time.Time     `json:"added_at"`
	Hash      string        `json:"hash"`
	Key       string        `json:"key"`
	Signature string        `json:"signature"`
	SignedBy  string        `json:"signed_by"`
	Values    []SecretValue `json:"values"`
}

// Vault represents the complete vault file structure.
// A vault contains identities (public keys) and secrets (encrypted values).
type Vault struct {
	Identities []Identity `json:"identities,omitempty"`
	Secrets    []Secret   `json:"secrets,omitempty"`
}

// VaultEntry represents a single vault configuration entry
type VaultEntry struct {
	Path     string `json:"path"`
	Optional bool   `json:"optional,omitempty"` // If true, missing vault is not an error
}

// VaultConfig represents parsed vault configuration
type VaultConfig struct {
	Entries                     []VaultEntry
	RequireExplicitVaultUpgrade bool // If true, don't auto-upgrade vaults
}

// NewVault creates an empty vault.
func NewVault() Vault {
	return Vault{
		Identities: []Identity{},
		Secrets:    []Secret{},
	}
}

// GetIdentityByFingerprint finds an identity by its GPG fingerprint.
// Returns nil if no identity with the given fingerprint exists.
func (v Vault) GetIdentityByFingerprint(fingerprint string) *Identity {
	for i := range v.Identities {
		if v.Identities[i].Fingerprint == fingerprint {
			return &v.Identities[i]
		}
	}
	return nil
}

// GetSecretByKey finds a secret by its key (name).
// Lookup is case-insensitive - keys are normalized before comparison.
// Returns nil if no secret with the given key exists.
func (v Vault) GetSecretByKey(key string) *Secret {
	for i := range v.Secrets {
		if CompareSecretKeys(v.Secrets[i].Key, key) {
			return &v.Secrets[i]
		}
	}
	return nil
}

// CanIdentityAccessSecret checks if an identity can access any value of a secret.
// It searches from most recent to oldest value.
func (v Vault) CanIdentityAccessSecret(fingerprint, secretKey string) bool {
	secret := v.GetSecretByKey(secretKey)
	if secret == nil {
		return false
	}

	// Check from most recent to oldest
	for i := len(secret.Values) - 1; i >= 0; i-- {
		for _, fp := range secret.Values[i].AvailableTo {
			if fp == fingerprint {
				return true
			}
		}
	}
	return false
}

// IsDeleted returns true if the secret's latest value is a deletion marker.
func (s Secret) IsDeleted() bool {
	if len(s.Values) == 0 {
		return false
	}
	return s.Values[len(s.Values)-1].Deleted
}

// GetAccessibleSecretValue returns the most recent secret value accessible to the identity.
// Returns nil if identity cannot access any version of the secret.
// Returns nil if the secret is deleted (latest value has Deleted=true).
// If strict is true, only returns a value if the identity has access to the LATEST value.
func (v Vault) GetAccessibleSecretValue(fingerprint, secretKey string, strict bool) *SecretValue {
	secret := v.GetSecretByKey(secretKey)
	if secret == nil {
		return nil
	}

	if len(secret.Values) == 0 {
		return nil
	}

	// If secret is deleted, return nil
	if secret.IsDeleted() {
		return nil
	}

	// In strict mode, only check the latest value
	if strict {
		latestValue := &secret.Values[len(secret.Values)-1]
		for _, fp := range latestValue.AvailableTo {
			if fp == fingerprint {
				return latestValue
			}
		}
		return nil
	}

	// Non-strict mode: check from most recent to oldest (fallback behavior)
	for i := len(secret.Values) - 1; i >= 0; i-- {
		for _, fp := range secret.Values[i].AvailableTo {
			if fp == fingerprint {
				return &secret.Values[i]
			}
		}
	}
	return nil
}

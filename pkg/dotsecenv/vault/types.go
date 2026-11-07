package vault

import (
	"slices"
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

// CanIdentityAccessSecret reports whether an identity is a recipient of any
// live value of a secret (see LiveValues).
func (v Vault) CanIdentityAccessSecret(fingerprint, secretKey string) bool {
	secret := v.GetSecretByKey(secretKey)
	if secret == nil {
		return false
	}
	for _, value := range secret.LiveValues() {
		if slices.Contains(value.AvailableTo, fingerprint) {
			return true
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

// LiveStart returns the index of the first value after the most recent
// deletion marker; every value before it is deleted. It is 0 for a secret that
// was never deleted and len(s.Values) when the latest value is a deletion
// marker.
func (s Secret) LiveStart() int {
	for i := len(s.Values) - 1; i >= 0; i-- {
		if s.Values[i].Deleted {
			return i + 1
		}
	}
	return 0
}

// LiveValues returns the values after the most recent deletion marker. Reads
// stop there, so a secret stored again after a deletion behaves as if it never
// existed before it.
func (s Secret) LiveValues() []SecretValue {
	return s.Values[s.LiveStart():]
}

// GetAccessibleSecretValue returns the most recent live value the identity is a
// recipient of, falling back to older live values when the identity is not on
// the latest one. It returns nil when the secret is missing or deleted, or when
// no live value is encrypted to the identity.
func (v Vault) GetAccessibleSecretValue(fingerprint, secretKey string) *SecretValue {
	secret := v.GetSecretByKey(secretKey)
	if secret == nil {
		return nil
	}
	live := secret.LiveValues()
	for i := len(live) - 1; i >= 0; i-- {
		if slices.Contains(live[i].AvailableTo, fingerprint) {
			return &live[i]
		}
	}
	return nil
}

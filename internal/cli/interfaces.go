package cli

import (
	"io"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// VaultResolver defines the interface for vault operations required by the CLI
type VaultResolver interface {
	GetIdentityByFingerprint(fingerprint string) *vault.Identity
	AddSecret(secret vault.Secret, index int) error
	SaveAll() error
	GetSecretFromAnyVault(key string, stderr io.Writer) (*vault.SecretValue, error)
	GetAccessibleSecretFromAnyVault(key, fingerprint string, strict bool) (*vault.SecretValue, error)
	GetSecretByKeyFromVault(index int, key string) *vault.Secret
	FindSecretVaultIndex(key string) int
	GetVaultManager(index int) *vault.Manager
	AddIdentity(identity vault.Identity, index int) error
	GetConfig() vault.VaultConfig
	GetVaultPaths() []string
	GetAvailableVaultPathsWithIndices() []vault.VaultPathWithIndex
	IsPathInConfig(path string) bool
	IdentityExistsInVault(fingerprint string, index int) bool
	SaveVault(index int) error
	CloseAll() error
	GetLoadError(index int) error
	GetSecret(index int, key string) (*vault.SecretValue, error)
	OpenVaultsFromPaths(paths []string, stderr io.Writer) error
	OpenVaults(stderr io.Writer) error
	VaultCount() int
}

package vault

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// VaultResolver manages multiple vault files
type VaultResolver struct {
	vaults     []*Manager // 0-indexed list of managers, nil if failed to load
	loadErrors map[int]error
	config     VaultConfig
	mu         sync.RWMutex
}

// NewVaultResolver creates a new vault resolver from configuration
func NewVaultResolver(config VaultConfig) *VaultResolver {
	return &VaultResolver{
		vaults:     make([]*Manager, len(config.Entries)),
		loadErrors: make(map[int]error),
		config:     config,
	}
}

// OpenVaults opens all vault files in the configuration
// Returns error if no vaults could be opened
func (vr *VaultResolver) OpenVaults(stderr io.Writer) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if len(vr.config.Entries) == 0 {
		return fmt.Errorf("no vaults configured")
	}

	var vaultsOpened int
	var errors []string

	for i, entry := range vr.config.Entries {
		// First check if the vault file exists and is not empty
		fileInfo, err := os.Stat(entry.Path)
		if err != nil {
			errmsg := fmt.Sprintf("vault '%s': no such file or directory", entry.Path)
			vr.loadErrors[i] = fmt.Errorf("no such file or directory")
			errors = append(errors, errmsg)

			if stderr != nil {
				_, _ = fmt.Fprintf(stderr, "warning: %s\n", errmsg)
			}
			continue
		}

		// Check if file is empty (not a valid vault)
		if fileInfo.Size() == 0 {
			errmsg := fmt.Sprintf("vault '%s': file is empty (invalid vault structure)", entry.Path)
			vr.loadErrors[i] = fmt.Errorf("file is empty (invalid vault structure)")
			errors = append(errors, errmsg)
			if stderr != nil {
				_, _ = fmt.Fprintf(stderr, "warning: %s\n", errmsg)
			}
			continue
		}

		manager := NewManager(entry.Path)

		// Try to open the vault
		if err := manager.OpenAndLock(); err != nil {
			errmsg := fmt.Sprintf("vault '%s': %v", entry.Path, err)
			vr.loadErrors[i] = err
			errors = append(errors, errmsg)

			if stderr != nil {
				_, _ = fmt.Fprintf(stderr, "warning: %s\n", errmsg)
			}
			continue
		}

		// Successfully opened this vault
		vr.vaults[i] = manager
		vaultsOpened++
	}

	// If no vaults were successfully opened, return error
	if vaultsOpened == 0 {
		if len(errors) > 0 {
			return fmt.Errorf("no vault files could be opened:\n  - %s", strings.Join(errors, "\n  - "))
		}
		return fmt.Errorf("no vault files could be opened from configuration")
	}

	return nil
}

// OpenVaultsFromPaths opens vaults from explicit -v command-line paths
// Replaces the current configuration with these paths
func (vr *VaultResolver) OpenVaultsFromPaths(paths []string, stderr io.Writer) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if len(paths) == 0 {
		return fmt.Errorf("no vault paths specified")
	}

	// Update config
	vr.config = VaultConfig{}
	for _, path := range paths {
		vr.config.Entries = append(vr.config.Entries, VaultEntry{Path: ExpandPath(path)})
	}

	// Reset state
	vr.vaults = make([]*Manager, len(vr.config.Entries))
	vr.loadErrors = make(map[int]error)

	// Open vaults
	for i, entry := range vr.config.Entries {
		if _, err := os.Stat(entry.Path); err != nil {
			return fmt.Errorf("vault file not found: %s", entry.Path)
		}

		manager := NewManager(entry.Path)
		if err := manager.OpenAndLock(); err != nil {
			return fmt.Errorf("failed to open vault %s: %v", entry.Path, err)
		}

		vr.vaults[i] = manager
	}

	return nil
}

// GetLoadError returns the error encountered when loading a vault at index
func (vr *VaultResolver) GetLoadError(index int) error {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return vr.loadErrors[index]
}

// GetSecret retrieves a secret from a specific vault index (0-based)
func (vr *VaultResolver) GetSecret(index int, key string) (*SecretValue, error) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	// Normalize key for lookup (graceful fallback for legacy keys)
	key = NormalizeKeyForLookup(key)

	if index < 0 || index >= len(vr.vaults) {
		return nil, fmt.Errorf("vault index %d out of range", index)
	}

	manager := vr.vaults[index]
	if manager == nil {
		path := vr.config.Entries[index].Path
		return nil, fmt.Errorf("Vault %d (%s): failed to load", index+1, path)
	}

	secret := manager.GetSecretByKey(key)
	if secret == nil {
		return nil, fmt.Errorf("secret '%s' not found in vault %d", key, index+1)
	}

	if len(secret.Values) == 0 {
		return nil, fmt.Errorf("secret '%s' has no values in vault %d", key, index+1)
	}
	return &secret.Values[len(secret.Values)-1], nil
}

// GetSecretFromAnyVault retrieves a secret value from any vault, searching in order
func (vr *VaultResolver) GetSecretFromAnyVault(key string, stderr io.Writer) (*SecretValue, error) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	for _, manager := range vr.vaults {
		if manager == nil {
			continue
		}

		secret := manager.GetSecretByKey(key)
		if secret != nil && len(secret.Values) > 0 {
			return &secret.Values[len(secret.Values)-1], nil
		}
	}

	return nil, fmt.Errorf("secret '%s' not found in any vault", key)
}

// GetAccessibleSecretFromAnyVault retrieves the most recent accessible secret value from any vault, searching in order.
// If strict is true, only returns a value if the identity has access to the LATEST value of the secret.
func (vr *VaultResolver) GetAccessibleSecretFromAnyVault(key, fingerprint string, strict bool) (*SecretValue, error) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	for _, manager := range vr.vaults {
		if manager == nil {
			continue
		}

		val := manager.GetAccessibleSecretValue(fingerprint, key, strict)
		if val != nil {
			return val, nil
		}
	}

	return nil, fmt.Errorf("secret '%s' not found or not accessible in any vault", key)
}

// AddIdentity adds an identity to all open vaults (or a specific vault if index >= 0)
func (vr *VaultResolver) AddIdentity(identity Identity, index int) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if index >= 0 {
		if index >= len(vr.vaults) {
			return fmt.Errorf("vault index %d out of range", index)
		}
		manager := vr.vaults[index]
		if manager == nil {
			return fmt.Errorf("vault not available")
		}
		if manager.IsReadOnly() {
			return fmt.Errorf("is read-only")
		}
		manager.AddIdentity(identity)
		return nil
	}

	// Add to all writable vaults
	for _, manager := range vr.vaults {
		if manager != nil && !manager.IsReadOnly() {
			manager.AddIdentity(identity)
		}
	}
	return nil
}

// AddSecret adds a secret to a specific vault index (0-based)
func (vr *VaultResolver) AddSecret(secret Secret, index int) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if index < 0 || index >= len(vr.vaults) {
		return fmt.Errorf("vault index %d out of range", index)
	}

	manager := vr.vaults[index]
	if manager == nil {
		return fmt.Errorf("vault not available")
	}
	if manager.IsReadOnly() {
		return fmt.Errorf("is read-only")
	}

	manager.AddSecret(secret)
	return nil
}

// GetIdentityByFingerprint finds an identity by fingerprint in any vault
func (vr *VaultResolver) GetIdentityByFingerprint(fingerprint string) *Identity {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	for _, manager := range vr.vaults {
		if manager != nil {
			identity := manager.GetIdentityByFingerprint(fingerprint)
			if identity != nil {
				return identity
			}
		}
	}
	return nil
}

// SaveAll saves all open vaults
func (vr *VaultResolver) SaveAll() error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	for i, manager := range vr.vaults {
		if manager == nil || manager.IsReadOnly() {
			continue
		}
		if err := manager.Save(); err != nil {
			return fmt.Errorf("failed to save vault %d: %w", i+1, err)
		}
	}
	return nil
}

// CloseAll closes all open vaults
func (vr *VaultResolver) CloseAll() error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	var lastErr error
	for i, manager := range vr.vaults {
		if manager == nil {
			continue
		}
		if err := manager.Unlock(); err != nil {
			lastErr = fmt.Errorf("failed to close vault %d: %w", i+1, err)
		}
	}
	return lastErr
}

// GetConfig returns the vault configuration
func (vr *VaultResolver) GetConfig() VaultConfig {
	return vr.config
}

// GetVaultManager returns the vault manager for a specific index
func (vr *VaultResolver) GetVaultManager(index int) *Manager {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	if index < 0 || index >= len(vr.vaults) {
		return nil
	}
	return vr.vaults[index]
}

// GetSecretByKeyFromVault gets a secret by key from a specific vault index
// Used for operations that need to modify a secret in place
func (vr *VaultResolver) GetSecretByKeyFromVault(index int, key string) *Secret {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	if index < 0 || index >= len(vr.vaults) {
		return nil
	}
	manager := vr.vaults[index]
	if manager == nil {
		return nil
	}

	return manager.GetSecretByKey(key)
}

// GetVaultPaths returns all vault paths in configuration order
func (vr *VaultResolver) GetVaultPaths() []string {
	var paths []string
	for _, entry := range vr.config.Entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

// VaultCount returns the number of vaults in the resolver.
func (vr *VaultResolver) VaultCount() int {
	return len(vr.vaults)
}

// IsPathInConfig checks if a vault path is configured
func (vr *VaultResolver) IsPathInConfig(path string) bool {
	expanded := ExpandPath(path)
	for _, entry := range vr.config.Entries {
		if ExpandPath(entry.Path) == expanded {
			return true
		}
	}
	return false
}

// IdentityExistsInVault checks if an identity exists in a specific vault index
func (vr *VaultResolver) IdentityExistsInVault(fingerprint string, index int) bool {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	if index < 0 || index >= len(vr.vaults) {
		return false
	}
	manager := vr.vaults[index]
	if manager == nil {
		return false
	}

	return manager.GetIdentityByFingerprint(fingerprint) != nil
}

// SaveVault saves a specific vault by index
func (vr *VaultResolver) SaveVault(index int) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if index < 0 || index >= len(vr.vaults) {
		return fmt.Errorf("vault index %d out of range", index)
	}
	manager := vr.vaults[index]
	if manager == nil {
		return fmt.Errorf("vault not available")
	}

	if manager.IsReadOnly() {
		return fmt.Errorf("is read-only")
	}

	if err := manager.Save(); err != nil {
		return fmt.Errorf("failed to save vault %d: %w", index+1, err)
	}

	return nil
}

// FindSecretVaultIndex finds the first vault index containing the secret key
// Returns -1 if not found
func (vr *VaultResolver) FindSecretVaultIndex(key string) int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	for i, manager := range vr.vaults {
		if manager != nil && manager.GetSecretByKey(key) != nil {
			return i
		}
	}
	return -1
}

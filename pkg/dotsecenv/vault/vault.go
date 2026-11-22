package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Manager handles vault file operations with locking
type Manager struct {
	path                        string
	readOnly                    bool
	requireExplicitVaultUpgrade bool    // if true, don't auto-upgrade vaults
	writer                      *Writer // holds the locked vault file while open
	vault                       Vault   // cached vault for fast access
}

// NewManager creates a new vault manager for the specified path.
// requireExplicitUpgrade controls whether vaults are auto-upgraded (false) or only warned about (true).
func NewManager(path string, requireExplicitUpgrade bool) *Manager {
	return &Manager{
		path:                        path,
		requireExplicitVaultUpgrade: requireExplicitUpgrade,
	}
}

// OpenAndLock opens the vault file and locks it for exclusive access
// Creates the file with defaults if it doesn't exist
func (m *Manager) OpenAndLock() error {
	// Ensure parent directories exist
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		// If we can't create directory, we likely can't write.
		// Continue anyway, the open will fail appropriately.
		_ = err
	}

	file, err := m.openLocked()
	if err != nil {
		return err
	}

	// Initialize the writer (which handles loading). It takes over the lock.
	// Use read-only writer if we're in read-only mode to avoid temp file creation
	writer, err := newWriter(m.path, m.readOnly, file)
	if err != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return fmt.Errorf("failed to initialize vault: %w", err)
	}
	m.writer = writer

	// Check and upgrade vault if needed (only for read-write mode)
	if !m.readOnly {
		upgraded, err := CheckAndUpgradeVault(writer, m.path, m.requireExplicitVaultUpgrade)
		if err != nil {
			_ = m.Unlock()
			return fmt.Errorf("failed to check/upgrade vault: %w", err)
		}
		if upgraded {
			// Reload writer after upgrade to get fresh state
			if err := writer.Reload(); err != nil {
				_ = m.Unlock()
				return fmt.Errorf("failed to reload vault after upgrade: %w", err)
			}
		}
	}

	// Load vault into memory for fast access
	vault, err := writer.ReadVault()
	if err != nil {
		_ = m.Unlock()
		return fmt.Errorf("failed to load vault: %w", err)
	}
	m.vault = vault

	return nil
}

// openLocked opens and locks the vault file: shared for read-only access,
// exclusive for read-write. A writer may rename a new file over the path while
// this process waits for the lock, so it retries until the locked file is the
// one the path names.
func (m *Manager) openLocked() (*os.File, error) {
	for {
		// Determine if we should open read-only
		var flags int
		if _, err := os.Stat(m.path); os.IsNotExist(err) {
			// File doesn't exist, create it
			flags = os.O_CREATE | os.O_RDWR
		} else {
			// File exists, open it
			flags = os.O_RDWR
		}

		file, err := os.OpenFile(m.path, flags, 0600)
		if err != nil {
			// If failed with permission error and we tried RW, try ReadOnly
			if os.IsPermission(err) && (flags&os.O_RDWR != 0) {
				file, err = os.OpenFile(m.path, os.O_RDONLY, 0)
				if err == nil {
					m.readOnly = true
				}
			}
			if err != nil {
				return nil, fmt.Errorf("failed to open vault file: %w", err)
			}
		}

		if err := lockFile(file, !m.readOnly); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("failed to lock vault file: %w", err)
		}

		held, err := file.Stat()
		if err == nil {
			var current os.FileInfo
			current, err = os.Stat(m.path)
			if err == nil && os.SameFile(held, current) {
				return file, nil
			}
		}
		_ = unlockFile(file)
		_ = file.Close()
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat vault file: %w", err)
		}
	}
}

// IsReadOnly returns true if the vault is opened in read-only mode
func (m *Manager) IsReadOnly() bool {
	return m.readOnly
}

// Version returns the vault format version
func (m *Manager) Version() int {
	if m.writer == nil {
		return 0
	}
	return m.writer.Version()
}

// Unlock releases the lock and closes the vault file
func (m *Manager) Unlock() error {
	if m.writer == nil || m.writer.lock == nil {
		return nil
	}
	file := m.writer.lock
	m.writer = nil
	_ = unlockFile(file)
	return file.Close()
}

// Get returns the vault data
func (m *Manager) Get() Vault {
	return m.vault
}

// Path returns the vault file path
func (m *Manager) Path() string {
	return m.path
}

// GetHeader returns the vault header for validation
// Returns nil if the vault hasn't been loaded yet
func (m *Manager) GetHeader() *Header {
	if m.writer == nil {
		return nil
	}
	return m.writer.header
}

// GetLines returns the raw lines of the vault file for validation
// Returns nil if the vault hasn't been loaded yet
func (m *Manager) GetLines() []string {
	if m.writer == nil {
		return nil
	}
	return m.writer.lines
}

// Save is a no-op kept for API compatibility.
// Writer methods already persist changes via flush().
func (m *Manager) Save() error {
	if m.writer == nil {
		return fmt.Errorf("vault file not open")
	}
	if m.readOnly {
		return fmt.Errorf("cannot save to read-only vault")
	}

	// No-op: Writer methods (AddIdentity, AddSecret, AddSecretValue, etc.)
	// already call flush() which persists changes immediately.
	// Full rewrites should only happen via explicit Defragment() calls.
	return nil
}

// AddIdentity adds an identity to the vault
func (m *Manager) AddIdentity(id Identity) error {
	// Check if identity already exists
	for i, existing := range m.vault.Identities {
		if existing.Fingerprint == id.Fingerprint {
			// Update existing identity in memory
			m.vault.Identities[i] = id
			// For the efficient format, we need to handle updates differently
			// For now, we append and the reader will use the latest
			return nil
		}
	}

	// Add to writer (persists immediately)
	if err := m.writer.AddIdentity(id); err != nil {
		return err
	}

	m.vault.Identities = append(m.vault.Identities, id)
	return nil
}

// AddSecret adds a new secret or updates an existing one with a new value.
// Secret keys are compared case-insensitively using CompareSecretKeys.
func (m *Manager) AddSecret(secret Secret) error {
	// Check if secret already exists (case-insensitive comparison)
	for i, s := range m.vault.Secrets {
		if CompareSecretKeys(s.Key, secret.Key) {
			// Add new values to existing secret
			for _, newVal := range secret.Values {
				if err := m.writer.AddSecretValue(s.Key, newVal); err != nil {
					return err
				}
				m.vault.Secrets[i].Values = append(m.vault.Secrets[i].Values, newVal)
			}
			return nil
		}
	}

	// Add new secret with all its values
	if err := m.writer.AddSecretWithValues(secret); err != nil {
		return err
	}

	m.vault.Secrets = append(m.vault.Secrets, secret)
	return nil
}

// Rewrite replaces the vault's contents with v in the given format version,
// under the lock this Manager holds.
func (m *Manager) Rewrite(v Vault, version int) error {
	if m.writer == nil || m.readOnly {
		return fmt.Errorf("vault is not open for writing")
	}
	if err := m.writer.RewriteFromVaultWithVersion(v, version); err != nil {
		return err
	}
	vault, err := m.writer.ReadVault()
	if err != nil {
		return fmt.Errorf("failed to reload vault after rewrite: %w", err)
	}
	m.vault = vault
	return nil
}

// GetIdentityByFingerprint retrieves an identity by fingerprint
func (m *Manager) GetIdentityByFingerprint(fingerprint string) *Identity {
	return m.vault.GetIdentityByFingerprint(fingerprint)
}

// GetSecretByKey retrieves a secret by key
func (m *Manager) GetSecretByKey(key string) *Secret {
	return m.vault.GetSecretByKey(key)
}

// GetAccessibleSecretValue gets the most recent accessible secret value.
// Returns the most recent value the identity has access to (falls back to older values if needed).
func (m *Manager) GetAccessibleSecretValue(fingerprint, secretKey string) *SecretValue {
	return m.vault.GetAccessibleSecretValue(fingerprint, secretKey)
}

// CanIdentityAccessSecret checks if an identity can access a secret
func (m *Manager) CanIdentityAccessSecret(fingerprint, secretKey string) bool {
	return m.vault.CanIdentityAccessSecret(fingerprint, secretKey)
}

// ListIdentityFingerprints returns all identity fingerprints in the vault
func (m *Manager) ListIdentityFingerprints() []string {
	fingerprints := make([]string, 0, len(m.vault.Identities))
	for _, id := range m.vault.Identities {
		fingerprints = append(fingerprints, id.Fingerprint)
	}
	return fingerprints
}

// ListSecretKeys returns all secret keys in the vault
func (m *Manager) ListSecretKeys() []string {
	keys := make([]string, 0, len(m.vault.Secrets))
	for _, s := range m.vault.Secrets {
		keys = append(keys, s.Key)
	}
	sort.Strings(keys)
	return keys
}

// FragmentationStats returns defragmentation statistics for the vault
func (m *Manager) FragmentationStats() (*FragmentationStats, error) {
	reader, err := NewReader(m.path)
	if err != nil {
		return nil, err
	}
	return CalculateFragmentation(reader)
}

// Defragment performs vault defragmentation
func (m *Manager) Defragment() (*FragmentationStats, error) {
	stats, err := Defragment(m.writer)
	if err != nil {
		return nil, err
	}

	// Reload vault after defragmentation
	vault, err := m.writer.ReadVault()
	if err != nil {
		return stats, fmt.Errorf("failed to reload vault after defragmentation: %w", err)
	}
	m.vault = vault

	return stats, nil
}

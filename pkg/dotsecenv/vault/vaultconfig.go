package vault

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ParseVaultConfig parses vault configuration from a list of paths
func ParseVaultConfig(vaultPaths []string) (VaultConfig, error) {
	var config VaultConfig

	if len(vaultPaths) == 0 {
		return config, nil
	}

	for _, path := range vaultPaths {
		path = ExpandPath(path)
		config.Entries = append(config.Entries, VaultEntry{
			Path: path,
		})
	}

	return config, nil
}

// getCurrentUserHomeDir resolves the current user's home directory
func getCurrentUserHomeDir() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	if currentUser.HomeDir == "" {
		return "", fmt.Errorf("home directory is empty for user %s", currentUser.Username)
	}
	return currentUser.HomeDir, nil
}

// ExpandPath expands ~ to home directory using platform-aware resolution
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := getCurrentUserHomeDir()
		if err != nil {
			// Return as-is if we can't get home dir
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// ValidateVaultConfigExists checks that at least one vault file exists
// Returns error if no vaults exist
func ValidateVaultConfigExists(config VaultConfig) error {
	if len(config.Entries) == 0 {
		return nil // Empty config is valid, caller decides if -v is required
	}

	for _, entry := range config.Entries {
		if _, err := os.Stat(entry.Path); err == nil {
			return nil // At least one vault exists
		}
	}

	// No vaults found
	return fmt.Errorf("no vault files could be read from configuration")
}

// GetEntriesInOrder returns all entries in order
func (vc VaultConfig) GetEntriesInOrder() []VaultEntry {
	return vc.Entries
}

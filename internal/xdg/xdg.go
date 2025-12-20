package xdg

import (
	"os"
	"os/user"
	"path/filepath"
)

// Paths holds XDG-compliant directory paths
type Paths struct {
	ConfigHome string
	DataHome   string
}

// NewPaths returns XDG-compliant directory paths
// If XDG environment variables are set, they are used; otherwise, defaults are applied
func NewPaths() (Paths, error) {
	homeDir, err := getHomeDir()
	if err != nil {
		return Paths{}, err
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(homeDir, ".config")
	}

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(homeDir, ".local", "share")
	}

	return Paths{
		ConfigHome: configHome,
		DataHome:   dataHome,
	}, nil
}

// getHomeDir returns the user's home directory
func getHomeDir() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	return currentUser.HomeDir, nil
}

// ConfigPath returns the path to the config file
func (p Paths) ConfigPath() string {
	return filepath.Join(p.ConfigHome, "dotsecenv", "config")
}

// VaultPath returns the path to the vault file
func (p Paths) VaultPath() string {
	return filepath.Join(p.DataHome, "dotsecenv", "vault")
}

// EnsureDirs creates necessary directories with proper permissions (0700)
func (p Paths) EnsureDirs() error {
	dirs := []string{
		filepath.Join(p.ConfigHome, "dotsecenv"),
		filepath.Join(p.DataHome, "dotsecenv"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// GetDefaultVaultPaths generates default vault paths appropriate for the execution context
// When isSUID is false (normal execution): returns [cwd, home, system] vaults
// When isSUID is true (SUID execution): returns [system] vaults (home excluded for security)
//
// The home path uses XDG_DATA_HOME if set, otherwise defaults to ~/.local/share/dotsecenv/vault
func (p Paths) GetDefaultVaultPaths(isSUID bool) []string {
	var paths []string

	// Include home vault unless running with SUID
	// When SUID, we don't want to expose user's personal vault
	if !isSUID {
		paths = append(paths, ".dotsecenv/vault")
		paths = append(paths, p.VaultPath())
	}

	// Always include system vault
	// in SUID mode, we only include the system vault
	paths = append(paths, "/var/lib/dotsecenv/vault")

	return paths
}

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dotsecenv/dotsecenv/internal/xdg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// InitConfig initializes a configuration file with defaults
// If fips is true, generates config with FIPS 140-3 compliant algorithms only
func InitConfig(configPath string, initialVaults []string, fips bool, stdout, stderr io.Writer) *Error {
	xdgPaths, err := xdg.NewPaths()
	if err != nil {
		return NewError(fmt.Sprintf("failed to get XDG paths: %v", err), ExitConfigError)
	}

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil {
		return NewError(fmt.Sprintf("config file already exists: %s", configPath), ExitConfigError)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return NewError(fmt.Sprintf("failed to create config directory: %v", err), ExitConfigError)
	}

	// Select config based on fips flag
	var cfg config.Config
	if fips {
		cfg = config.FIPSConfig()
	} else {
		cfg = config.DefaultConfig()
	}

	// Inject default vault paths (CLI specific behavior)
	var vaultPaths []string

	if len(initialVaults) > 0 {
		vaultPaths = initialVaults
	} else {
		isSUID := os.Getuid() != os.Geteuid()
		defaultVaults := xdgPaths.GetDefaultVaultPaths(isSUID)
		vaultPaths = append(vaultPaths, defaultVaults...)
	}
	cfg.Vault = vaultPaths

	// Save config
	if err := config.Save(configPath, cfg); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	_, _ = fmt.Fprintf(stdout, "Initialized config file: %s\n", configPath)
	return nil
}

// InitVaultFile initializes a specific vault file
func InitVaultFile(vaultPath string, stdout, stderr io.Writer) *Error {
	// Check if file exists
	if _, err := os.Stat(vaultPath); err == nil {
		return NewError(fmt.Sprintf("vault file already exists: %s", vaultPath), ExitVaultError)
	}

	// Create empty vault structure
	vm := vault.NewManager(vaultPath)

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		return NewError(fmt.Sprintf("failed to create vault directory: %v", err), ExitVaultError)
	}

	// Initialize and save
	if err := vm.OpenAndLock(); err != nil {
		return NewError(fmt.Sprintf("failed to open/create vault: %v", err), ExitVaultError)
	}
	if err := vm.Save(); err != nil {
		_ = vm.Unlock()
		return NewError(fmt.Sprintf("failed to initialize vault structure: %v", err), ExitVaultError)
	}
	_ = vm.Unlock()

	_, _ = fmt.Fprintf(stdout, "Initialized empty vault: %s\n", vaultPath)
	return nil
}

// InitVaultInteractiveStandalone allows user to select a vault from config to initialize
// This runs without requiring the vaults to be openable (since they might not exist yet)
func InitVaultInteractiveStandalone(configPath string, stdout, stderr io.Writer) *Error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return NewError(fmt.Sprintf("failed to load config: %v\nRun 'dotsecenv init config' first.", err), ExitConfigError)
	}

	vaultCfg, err := vault.ParseVaultConfig(cfg.Vault)
	if err != nil {
		return NewError(fmt.Sprintf("failed to parse vault config: %v", err), ExitConfigError)
	}

	if len(vaultCfg.Entries) == 0 {
		return NewError("no vaults configured", ExitVaultError)
	}

	var options []string
	var paths []string

	for _, entry := range vaultCfg.Entries {
		options = append(options, entry.Path)
		paths = append(paths, entry.Path)
	}

	var selectedPath string
	if len(options) == 1 {
		selectedPath = paths[0]
		_, _ = fmt.Fprintf(stdout, "Auto-selected single vault: %s\n", options[0])
	} else {
		idx, selectErr := HandleInteractiveSelection(options, "Select vault to initialize (Arrow Up/Down, Enter to select):", stderr)
		if selectErr != nil {
			return selectErr
		}
		selectedPath = paths[idx]
	}

	return InitVaultFile(selectedPath, stdout, stderr)
}

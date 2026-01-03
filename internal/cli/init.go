package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dotsecenv/dotsecenv/internal/xdg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// InitConfig initializes a configuration file with FIPS-compliant defaults.
// gpgProgram: if non-empty, use this value for gpg.program (without validation)
// noGPGProgram: if true, skip GPG detection entirely and leave gpg.program empty
// strict: if true, initialize config with strict mode enabled
// loginFingerprint: if non-empty, set fingerprint to this value
func InitConfig(configPath string, initialVaults []string, gpgProgram string, noGPGProgram bool, strict bool, loginFingerprint string, stdout, stderr io.Writer) *Error {
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

	// Use FIPS-compliant default configuration
	cfg := config.DefaultConfig()

	// Apply strict mode if requested
	if strict {
		cfg.Strict = true
	}

	// Apply fingerprint if provided via --login
	if loginFingerprint != "" {
		cfg.Fingerprint = loginFingerprint
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

	// Handle GPG program configuration
	switch {
	case gpgProgram != "":
		// Explicit path provided via --gpg-program (no validation)
		cfg.GPG.Program = gpgProgram
		_, _ = fmt.Fprintf(stderr, "Using GPG program: %s\n", gpgProgram)

	case noGPGProgram:
		// Skip GPG detection entirely
		cfg.GPG.Program = ""
		_, _ = fmt.Fprintf(stderr, "Skipping GPG program detection (gpg.program will be empty)\n")

	default:
		// Auto-detect GPG paths and let user choose if multiple are found
		gpgPaths := gpg.DetectAllGPGPaths()

		switch len(gpgPaths) {
		case 0:
			// Fail to generate the config
			return NewError("GPG not found. Please install GPG and ensure it's in your PATH, then try again.\n  Use --no-gpg-program to skip GPG detection, or --gpg-program to specify a path.", ExitConfigError)
		case 1:
			// Single GPG found - always set it explicitly
			cfg.GPG.Program = gpgPaths[0]
			_, _ = fmt.Fprintf(stderr, "Using GPG: %s\n", gpgPaths[0])
		default:
			// Multiple GPG installations found, let user choose
			_, _ = fmt.Fprintf(stderr, "Multiple GPG installations found:\n")

			// Try interactive selection
			idx, selectErr := HandleInteractiveSelection(gpgPaths, "Select GPG to use (Arrow Up/Down, Enter to select):", stderr)
			if selectErr != nil {
				// Interactive selection failed (no terminal, Windows, etc.)
				// Fall back to first detected path
				cfg.GPG.Program = gpgPaths[0]
				_, _ = fmt.Fprintf(stderr, "Could not prompt for selection, using first detected: %s\n", gpgPaths[0])
			} else {
				cfg.GPG.Program = gpgPaths[idx]
				_, _ = fmt.Fprintf(stderr, "Selected GPG: %s\n", gpgPaths[idx])
			}
		}
	}

	// Save config
	if err := config.Save(configPath, cfg); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	_, _ = fmt.Fprintf(stderr, "Initialized config file: %s\n", configPath)
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

	_, _ = fmt.Fprintf(stderr, "Initialized empty vault: %s\n", vaultPath)
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
		_, _ = fmt.Fprintf(stderr, "Auto-selected single vault: %s\n", options[0])
	} else {
		idx, selectErr := HandleInteractiveSelection(options, "Select vault to initialize (Arrow Up/Down, Enter to select):", stderr)
		if selectErr != nil {
			return selectErr
		}
		selectedPath = paths[idx]
	}

	return InitVaultFile(selectedPath, stdout, stderr)
}

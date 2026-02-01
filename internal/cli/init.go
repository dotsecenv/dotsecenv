package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dotsecenv/dotsecenv/internal/xdg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// InitConfig initializes a configuration file with FIPS-compliant defaults.
// gpgProgram: if non-empty, use this value for gpg.program (without validation)
// noGPGProgram: if true, skip GPG detection entirely and leave gpg.program empty
// loginFingerprint: if non-empty, creates a signed login proof for this fingerprint
func InitConfig(configPath string, initialVaults []string, gpgProgram string, noGPGProgram bool, loginFingerprint string, out *output.Handler) *Error {
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

	// Handle GPG program configuration FIRST (before login handling needs it)
	var detectedGPGProgram string
	switch {
	case gpgProgram != "":
		// Explicit path provided via --gpg-program (no validation)
		detectedGPGProgram = gpgProgram
		cfg.GPG.Program = gpgProgram
		_, _ = fmt.Fprintf(out.Stderr(), "Using GPG program: %s\n", gpgProgram)

	case noGPGProgram:
		// Skip GPG detection entirely
		detectedGPGProgram = ""
		cfg.GPG.Program = ""
		_, _ = fmt.Fprintf(out.Stderr(), "Skipping GPG program detection (gpg.program will be empty)\n")

	default:
		// Auto-detect GPG paths and let user choose if multiple are found
		gpgPaths := gpg.DetectAllGPGPaths()

		switch len(gpgPaths) {
		case 0:
			// Fail to generate the config
			return NewError("GPG not found. Please install GPG and ensure it's in your PATH, then try again.\n  Use --no-gpg-program to skip GPG detection, or --gpg-program to specify a path.", ExitConfigError)
		case 1:
			// Single GPG found - always set it explicitly
			detectedGPGProgram = gpgPaths[0]
			cfg.GPG.Program = gpgPaths[0]
			_, _ = fmt.Fprintf(out.Stderr(), "Using GPG: %s\n", gpgPaths[0])
		default:
			// Multiple GPG installations found, let user choose
			_, _ = fmt.Fprintf(out.Stderr(), "Multiple GPG installations found:\n")

			// Try interactive selection
			idx, selectErr := HandleInteractiveSelection(gpgPaths, "Select GPG to use (Arrow Up/Down, Enter to select):", out.Stderr())
			if selectErr != nil {
				// Interactive selection failed (no terminal, Windows, etc.)
				// Fall back to first detected path
				detectedGPGProgram = gpgPaths[0]
				cfg.GPG.Program = gpgPaths[0]
				_, _ = fmt.Fprintf(out.Stderr(), "Could not prompt for selection, using first detected: %s\n", gpgPaths[0])
			} else {
				detectedGPGProgram = gpgPaths[idx]
				cfg.GPG.Program = gpgPaths[idx]
				_, _ = fmt.Fprintf(out.Stderr(), "Selected GPG: %s\n", gpgPaths[idx])
			}
		}
	}

	// Apply signed login if fingerprint is provided via --login
	// (now GPG program is already detected/configured)
	if loginFingerprint != "" {
		if detectedGPGProgram == "" {
			return NewError("--login requires GPG but no GPG program is configured.\n  Use --gpg-program to specify a path, or ensure GPG is installed.", ExitGPGError)
		}

		// Validate and set the GPG program path for the GPG client to use
		if err := gpg.ValidateAndSetGPGProgram(detectedGPGProgram); err != nil {
			return NewError(fmt.Sprintf("failed to validate GPG program: %v", err), ExitGPGError)
		}

		// Create a GPG client (uses the validated program path)
		gpgClient := &gpg.GPGClient{}

		// Validate the key exists first
		publicKeyInfo, pubKeyErr := gpgClient.GetPublicKeyInfo(loginFingerprint)
		if pubKeyErr != nil {
			return NewError(fmt.Sprintf("failed to get public key for fingerprint '%s': %v\nMake sure your GPG key is available in gpg-agent", loginFingerprint, pubKeyErr), ExitGPGError)
		}

		_, _ = fmt.Fprintf(out.Stderr(), "Creating signed login for: %s (%s)\n", publicKeyInfo.UID, loginFingerprint)

		// Create signed login proof
		login, loginErr := CreateSignedLogin(gpgClient, loginFingerprint)
		if loginErr != nil {
			return NewError(fmt.Sprintf("failed to create signed login: %v", loginErr), ExitGPGError)
		}
		cfg.Login = login
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

	// Save config with comments for behavior section
	if err := saveConfigWithComments(configPath, cfg); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	_, _ = fmt.Fprintf(out.Stderr(), "Initialized config file: %s\n", configPath)
	return nil
}

// saveConfigWithComments writes a config file with helpful comments for init.
// This produces a more user-friendly config file than yaml.Marshal alone.
func saveConfigWithComments(path string, cfg config.Config) error {
	// Create parent directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	var sb strings.Builder

	// Approved algorithms section
	sb.WriteString("approved_algorithms:\n")
	for _, alg := range cfg.ApprovedAlgorithms {
		sb.WriteString(fmt.Sprintf("  - algo: %s\n", alg.Algo))
		if len(alg.Curves) > 0 {
			sb.WriteString("    curves:\n")
			for _, curve := range alg.Curves {
				sb.WriteString(fmt.Sprintf("      - %s\n", curve))
			}
		}
		sb.WriteString(fmt.Sprintf("    min_bits: %d\n", alg.MinBits))
	}

	// Login section (only if set) - preferred over deprecated fingerprint
	if cfg.Login != nil && cfg.Login.Fingerprint != "" {
		sb.WriteString("login:\n")
		sb.WriteString(fmt.Sprintf("  fingerprint: %s\n", cfg.Login.Fingerprint))
		sb.WriteString(fmt.Sprintf("  added_at: %s\n", cfg.Login.AddedAt.Format("2006-01-02T15:04:05Z07:00")))
		sb.WriteString(fmt.Sprintf("  hash: %s\n", cfg.Login.Hash))
		sb.WriteString(fmt.Sprintf("  signature: %s\n", cfg.Login.Signature))
	} else if cfg.Fingerprint != "" {
		// Deprecated fingerprint field (for backward compatibility)
		sb.WriteString(fmt.Sprintf("fingerprint: %s\n", cfg.Fingerprint))
	}

	// Vault paths
	sb.WriteString("vault:\n")
	for _, v := range cfg.Vault {
		sb.WriteString(fmt.Sprintf("  - %s\n", v))
	}

	// Behavior section with comments
	sb.WriteString("\n# Behavior settings control how dotsecenv handles edge cases.\n")
	sb.WriteString("# All settings default to false (permissive). Set to true for stricter behavior.\n")
	sb.WriteString("# See: https://dotsecenv.com/docs/concepts/behavior-settings\n")
	sb.WriteString("behavior:\n")
	sb.WriteString("  # Prevent automatic vault format upgrades; requires 'dotsecenv vault doctor'\n")
	sb.WriteString("  require_explicit_vault_upgrade: false\n")
	sb.WriteString("  # Ignore CLI -v flags; only use vaults from this config file\n")
	sb.WriteString("  restrict_to_configured_vaults: false\n")
	sb.WriteString("  # Require a TTY for secret decryption (blocks automated/piped access)\n")
	sb.WriteString("  require_tty_for_decryption: false\n")

	// GPG section
	sb.WriteString("\ngpg:\n")
	if cfg.GPG.Program != "" {
		sb.WriteString(fmt.Sprintf("  program: %s\n", cfg.GPG.Program))
	} else {
		sb.WriteString("  program: \"\"\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// ValidateVaultPathsAgainstConfig checks if specified vault paths are allowed per config.
// Returns an error if restrict_to_configured_vaults is true and paths are not in config.
// Prints a warning if paths are not in config but restriction is off.
// If configPath is empty, uses the default resolved config path.
func ValidateVaultPathsAgainstConfig(configPath string, vaultPaths []string, out *output.Handler) *Error {
	if len(vaultPaths) == 0 {
		return nil
	}

	// Resolve config path
	effectiveConfigPath := ResolveConfigPath(configPath, true, out.Stderr()) // silent for resolution

	// Load config (if it doesn't exist, no validation needed - allow creating vault anywhere)
	cfg, err := config.Load(effectiveConfigPath)
	if err != nil {
		// Config doesn't exist or can't be read - allow vault creation
		return nil
	}

	// If no vaults configured, allow creating at any path
	if len(cfg.Vault) == 0 {
		return nil
	}

	// Normalize config paths
	configPaths := make(map[string]bool)
	for _, p := range cfg.Vault {
		expanded := vault.ExpandPath(p)
		if abs, absErr := filepath.Abs(expanded); absErr == nil {
			configPaths[abs] = true
		} else {
			configPaths[expanded] = true
		}
	}

	// Check if any specified path is NOT in config
	var nonConfigPaths []string
	for _, p := range vaultPaths {
		expanded := vault.ExpandPath(p)
		abs, absErr := filepath.Abs(expanded)
		target := expanded
		if absErr == nil {
			target = abs
		}

		if !configPaths[target] {
			nonConfigPaths = append(nonConfigPaths, p)
		}
	}

	if len(nonConfigPaths) == 0 {
		return nil // All paths are in config
	}

	// If restrict_to_configured_vaults is set, this is an error
	if cfg.ShouldRestrictToConfiguredVaults() {
		return NewError("restrict_to_configured_vaults: specified vault path is not in configuration", ExitGeneralError)
	}

	// Otherwise, just warn (consistent with NewCLI behavior)
	if !out.IsSilent() {
		_, _ = fmt.Fprintf(out.Stderr(), "warning: ignoring vaults in configuration and using specified vault arguments\n")
	}

	return nil
}

// InitVaultFile initializes a specific vault file
func InitVaultFile(vaultPath string, out *output.Handler) *Error {
	// Check if file exists
	if _, err := os.Stat(vaultPath); err == nil {
		return NewError(fmt.Sprintf("vault file already exists: %s", vaultPath), ExitVaultError)
	}

	// Create empty vault structure (strictMode=false since we're creating new)
	vm := vault.NewManager(vaultPath, false)

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

	_, _ = fmt.Fprintf(out.Stderr(), "Initialized empty vault: %s\n", vaultPath)
	return nil
}

// InitVaultInteractiveStandalone allows user to select a vault from config to initialize
// This runs without requiring the vaults to be openable (since they might not exist yet)
func InitVaultInteractiveStandalone(configPath string, out *output.Handler) *Error {
	cfg, err := config.Load(configPath)
	if err != nil {
		// Provide helpful suggestion based on execution context
		var suggestion string
		isSUID := os.Getuid() != os.Geteuid()
		if isSUID {
			// SUID mode: config at /etc/dotsecenv/config, init commands are blocked
			suggestion = fmt.Sprintf("failed to load config: %v\nContact your system administrator to create this file.", err)
		} else if os.Getuid() == 0 {
			// Running as actual root (e.g., via sudo)
			suggestion = fmt.Sprintf("failed to load config: %v\nRun 'sudo dotsecenv init config' first.", err)
		} else {
			// Normal user
			suggestion = fmt.Sprintf("failed to load config: %v\nRun 'dotsecenv init config' first.", err)
		}
		return NewError(suggestion, ExitConfigError)
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
		_, _ = fmt.Fprintf(out.Stderr(), "Auto-selected single vault: %s\n", options[0])
	} else {
		idx, selectErr := HandleInteractiveSelection(options, "Select vault to initialize (Arrow Up/Down, Enter to select):", out.Stderr())
		if selectErr != nil {
			return selectErr
		}
		selectedPath = paths[idx]
	}

	return InitVaultFile(selectedPath, out)
}

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
// gpgProgram: if non-empty, set gpg.program to this value (without validation).
// Otherwise gpg.program defaults to "PATH" (resolved at runtime).
// loginFingerprint: if non-empty, creates a signed login proof for this fingerprint.
func InitConfig(configPath string, initialVaults []string, gpgProgram string, loginFingerprint string, out *output.Handler) *Error {
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

	// Use FIPS-compliant default configuration. DefaultConfig() seeds gpg.program
	// to "PATH", which resolves the gpg binary from the system PATH at runtime.
	cfg := config.DefaultConfig()

	// Override gpg.program only if --gpg-program was explicitly provided.
	if gpgProgram != "" {
		cfg.GPG.Program = gpgProgram
		_, _ = fmt.Fprintf(out.Stderr(), "Using GPG program: %s\n", gpgProgram)
	} else {
		_, _ = fmt.Fprintf(out.Stderr(), "Using GPG program: PATH (resolved at runtime)\n")
	}

	// Apply signed login if fingerprint is provided via --login.
	if loginFingerprint != "" {
		// Validate and set the GPG program path for the GPG client to use.
		// This resolves "PATH" via exec.LookPath, or validates an absolute path.
		if err := gpg.ValidateAndSetGPGProgram(cfg.GPG.Program); err != nil {
			return NewError(fmt.Sprintf("--login requires a working GPG program: %v", err), ExitGPGError)
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
		vaultPaths = append(vaultPaths, xdgPaths.GetDefaultVaultPaths()...)
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
		fmt.Fprintf(&sb, "  - algo: %s\n", alg.Algo)
		if len(alg.Curves) > 0 {
			sb.WriteString("    curves:\n")
			for _, curve := range alg.Curves {
				fmt.Fprintf(&sb, "      - %s\n", curve)
			}
		}
		fmt.Fprintf(&sb, "    min_bits: %d\n", alg.MinBits)
	}

	// Login section (only if set)
	if cfg.Login != nil && cfg.Login.Fingerprint != "" {
		sb.WriteString("login:\n")
		fmt.Fprintf(&sb, "  fingerprint: %s\n", cfg.Login.Fingerprint)
		fmt.Fprintf(&sb, "  added_at: %s\n", cfg.Login.AddedAt.Format("2006-01-02T15:04:05Z07:00"))
		fmt.Fprintf(&sb, "  hash: %s\n", cfg.Login.Hash)
		fmt.Fprintf(&sb, "  signature: %s\n", cfg.Login.Signature)
	}

	// Vault paths
	sb.WriteString("vault:\n")
	for _, v := range cfg.Vault {
		fmt.Fprintf(&sb, "  - %s\n", v)
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

	// GPG section
	sb.WriteString("\ngpg:\n")
	sb.WriteString("  # 'PATH' resolves gpg from the system PATH at runtime.\n")
	sb.WriteString("  # Set to an absolute path (e.g. /usr/bin/gpg) to pin a specific binary.\n")
	if cfg.GPG.Program != "" {
		fmt.Fprintf(&sb, "  program: %s\n", cfg.GPG.Program)
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

	// Create empty vault structure (requireExplicitUpgrade=false since we're creating new)
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
		if os.Getuid() == 0 {
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

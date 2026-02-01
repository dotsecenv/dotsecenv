package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dotsecenv/dotsecenv/internal/xdg"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// ResolveConfigPath returns the effective config path considering:
// 1. Explicit configPath argument (highest priority, e.g. -c flag)
// 2. /etc/dotsecenv/config (if SUID mode)
// 3. DOTSECENV_CONFIG env var (if not SUID mode)
// 4. XDG default path
// If configPath is specified and DOTSECENV_CONFIG is set, prints a warning to stderr (unless silent).
func ResolveConfigPath(configPath string, silent bool, stderr io.Writer) string {
	if configPath != "" {
		if !silent && !isSUID() && os.Getenv("DOTSECENV_CONFIG") != "" {
			_, _ = fmt.Fprintf(stderr, "warning: DOTSECENV_CONFIG environment variable ignored because -c flag was specified\n")
		}
		return configPath
	}
	if isSUID() {
		return "/etc/dotsecenv/config"
	}
	if envConfig := os.Getenv("DOTSECENV_CONFIG"); envConfig != "" {
		return envConfig
	}
	xdgPaths, _ := xdg.NewPaths()
	return xdgPaths.ConfigPath()
}

// CLI represents the command-line interface
type CLI struct {
	vaultPaths    []string // For reference only
	configPath    string
	xdgPaths      xdg.Paths
	config        config.Config
	vaultResolver VaultResolver // Multiple vaults
	gpgClient     gpg.Client
	stdin         io.Reader
	Silent        bool
	output        *output.Handler // Unified output handler
}

// NewCLI creates a new CLI instance
func isSUID() bool {
	return os.Getuid() != os.Geteuid()
}

func NewCLI(vaultPaths []string, configPath string, silent bool, stdin io.Reader, stdout, stderr io.Writer) (*CLI, error) {
	return newCLI(vaultPaths, configPath, silent, stdin, stdout, stderr, nil)
}

// newCLI creates a CLI instance. If requireExplicitUpgradeOverride is non-nil, it overrides the config setting.
func newCLI(vaultPaths []string, configPath string, silent bool, stdin io.Reader, stdout, stderr io.Writer, requireExplicitUpgradeOverride *bool) (*CLI, error) {
	xdgPaths, err := xdg.NewPaths()
	if err != nil {
		return nil, NewError(fmt.Sprintf("failed to get XDG paths: %v", err), ExitConfigError)
	}

	configPath = ResolveConfigPath(configPath, silent, stderr)

	// Ensure directories exist
	if err := xdgPaths.EnsureDirs(); err != nil {
		return nil, NewError(fmt.Sprintf("failed to create directories: %v", err), ExitConfigError)
	}

	// Load config (fail if missing or invalid)
	cfg, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Provide helpful suggestion based on execution context
			var suggestion string
			if isSUID() {
				// SUID mode: config at /etc/dotsecenv/config, init commands are blocked
				suggestion = fmt.Sprintf("config file not found: %s\nContact your system administrator to create this file.", configPath)
			} else if os.Getuid() == 0 {
				// Running as actual root (e.g., via sudo)
				suggestion = fmt.Sprintf("config file not found: %s\nRun 'sudo dotsecenv init config' to create one", configPath)
			} else {
				// Normal user
				suggestion = fmt.Sprintf("config file not found: %s\nRun 'dotsecenv init config' to create one", configPath)
			}
			return nil, NewError(suggestion, ExitConfigError)
		}
		return nil, NewError(fmt.Sprintf("failed to load config: %v", err), ExitConfigError)
	}

	// Deprecation warning for fingerprint field (use login section instead)
	if cfg.HasDeprecatedFingerprint() && !silent {
		_, _ = fmt.Fprintf(stderr, "warning: 'fingerprint:' field is deprecated and will be removed in a future version\n")
		_, _ = fmt.Fprintf(stderr, "         Run 'dotsecenv login %s' to migrate to signed login\n", cfg.Fingerprint)
	}

	// Validate and set GPG program path from config
	if err := gpg.ValidateAndSetGPGProgram(cfg.GPG.Program); err != nil {
		return nil, NewError(fmt.Sprintf("failed: %v", err), ExitGPGError)
	}

	// Create vault resolver
	var vaultResolver *vault.VaultResolver

	// Determine output writer for warnings
	warnWriter := stderr
	if silent {
		warnWriter = io.Discard
	}

	// If -v flags were provided, use those paths directly
	if len(vaultPaths) > 0 {
		// Check if overriding config vaults with NEW vaults
		shouldWarnOrError := false
		if len(cfg.Vault) > 0 {
			// Normalize config paths
			configPaths := make(map[string]bool)
			for _, p := range cfg.Vault {
				expanded := vault.ExpandPath(p)
				if abs, err := filepath.Abs(expanded); err == nil {
					configPaths[abs] = true
				} else {
					configPaths[expanded] = true
				}
			}

			// Check if any specified path is NOT in config
			for _, p := range vaultPaths {
				expanded := vault.ExpandPath(p)
				abs, err := filepath.Abs(expanded)
				target := expanded
				if err == nil {
					target = abs
				}

				if !configPaths[target] {
					shouldWarnOrError = true
					break
				}
			}
		}

		// If restrict_to_configured_vaults is set, ignoring config vaults is an error
		if shouldWarnOrError {
			if cfg.ShouldRestrictToConfiguredVaults() {
				return nil, NewError("restrict_to_configured_vaults: ignoring vaults in configuration and using specified vault arguments is not allowed", ExitGeneralError)
			}
			if !silent {
				_, _ = fmt.Fprintf(stderr, "warning: ignoring vaults in configuration and using specified vault arguments\n")
			}
		}

		// Initialize resolver with config that includes upgrade prevention setting
		requireExplicit := cfg.ShouldRequireExplicitVaultUpgrade()
		if requireExplicitUpgradeOverride != nil {
			requireExplicit = *requireExplicitUpgradeOverride
		}
		vaultResolver = vault.NewVaultResolver(vault.VaultConfig{
			RequireExplicitVaultUpgrade: requireExplicit,
		})
		if err := vaultResolver.OpenVaultsFromPaths(vaultPaths, warnWriter); err != nil {
			return nil, NewError(fmt.Sprintf("failed to open vaults from -v paths: %v", err), ExitVaultError)
		}
	} else {
		// Use config file vault settings
		vaultCfg, err := vault.ParseVaultConfig(cfg.Vault)
		if err != nil {
			return nil, NewError(fmt.Sprintf("failed to parse vault config: %v", err), ExitConfigError)
		}

		// Check if we have any vaults configured
		if len(vaultCfg.Entries) == 0 {
			return nil, NewError("no vaults configured - specify vault paths in config or use -v flag", ExitVaultError)
		}

		// Set vault upgrade behavior from config (or override if specified)
		if requireExplicitUpgradeOverride != nil {
			vaultCfg.RequireExplicitVaultUpgrade = *requireExplicitUpgradeOverride
		} else {
			vaultCfg.RequireExplicitVaultUpgrade = cfg.ShouldRequireExplicitVaultUpgrade()
		}

		vaultResolver = vault.NewVaultResolver(vaultCfg)
		// Suppress startup warnings; commands like 'identity add' or 'validate' will report status
		if err := vaultResolver.OpenVaults(io.Discard); err != nil {
			return nil, NewError(fmt.Sprintf("failed to open vaults from config: %v", err), ExitVaultError)
		}
	}

	return &CLI{
			vaultPaths:    vaultPaths,
			configPath:    configPath,
			xdgPaths:      xdgPaths,
			config:        cfg,
			vaultResolver: vaultResolver,
			gpgClient:     &gpg.GPGClient{},
			stdin:         stdin,
			Silent:        silent,
			output: output.NewHandler(stdout, stderr,
				output.WithSilent(silent),
			),
		},
		nil
}

// Warnf prints a warning message to stderr unless silent mode is enabled.
// Deprecated: For new code, use c.Output().Warnf() with a structured code.
func (c *CLI) Warnf(format string, args ...interface{}) {
	if !c.Silent {
		if !strings.HasPrefix(format, "warning:") {
			format = "warning: " + format
		}
		if !strings.HasSuffix(format, "\n") {
			format = format + "\n"
		}
		_, _ = fmt.Fprintf(c.output.Stderr(), format, args...)
	}
}

// Output returns the unified output handler for this CLI instance.
func (c *CLI) Output() *output.Handler {
	return c.output
}

// SetJSONMode enables or disables JSON output mode for the current command.
// This creates a new handler with fresh warning collection.
func (c *CLI) SetJSONMode(enabled bool) {
	c.output = c.output.WithJSONMode(enabled)
}

// Close closes the vault and releases locks
func (c *CLI) Close() error {
	if c.vaultResolver != nil {
		return c.vaultResolver.CloseAll()
	}
	return nil
}

// getFingerprintFromEnv gets the current fingerprint to use.
// In SUID mode, DOTSECENV_FINGERPRINT is ignored for security.
// Prefers Login.Fingerprint over the deprecated Fingerprint field.
func (c *CLI) getFingerprintFromEnv() string {
	if !isSUID() {
		envFP := os.Getenv("DOTSECENV_FINGERPRINT")
		if envFP != "" {
			return envFP
		}
	}
	return c.config.GetFingerprint()
}

// checkFingerprintRequired ensures a fingerprint is configured
func (c *CLI) checkFingerprintRequired(operation string) (string, *Error) {
	fp := c.getFingerprintFromEnv()
	if fp == "" {
		msg := fmt.Sprintf("select a user identity before running '%s'\n  run: `dotsecenv login FINGERPRINT`", operation)
		return "", NewError(msg, ExitFingerprintRequired)
	}
	return fp, nil
}

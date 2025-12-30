package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	Strict        bool            // Strict mode: certain warnings become errors
	output        *output.Handler // Unified output handler
}

// NewCLI creates a new CLI instance
func isSUID() bool {
	return os.Getuid() != os.Geteuid()
}

func NewCLI(vaultPaths []string, configPath string, silent bool, strict bool, stdin io.Reader, stdout, stderr io.Writer) (*CLI, error) {
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
		return nil, NewError(fmt.Sprintf("failed to load config: %v", err), ExitConfigError)
	}

	// Set GPG program path from config (if specified)
	gpg.SetGPGProgram(cfg.GPGProgram)

	// Compute effective strict mode early (CLI flag or config setting)
	effectiveStrict := strict || cfg.Strict

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

		// In strict mode, ignoring config vaults is an error
		if shouldWarnOrError {
			if effectiveStrict {
				return nil, NewError("strict mode: ignoring vaults in configuration and using specified vault arguments is not allowed", ExitGeneralError)
			}
			if !silent {
				_, _ = fmt.Fprintf(stderr, "warning: ignoring vaults in configuration and using specified vault arguments\n")
			}
		}

		// Initialize resolver with empty config and load paths
		vaultResolver = vault.NewVaultResolver(vault.VaultConfig{})
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
			Strict:        effectiveStrict,
			output: output.NewHandler(stdout, stderr,
				output.WithSilent(silent),
				output.WithStrict(effectiveStrict),
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
func (c *CLI) getFingerprintFromEnv() string {
	if !isSUID() {
		envFP := os.Getenv("DOTSECENV_FINGERPRINT")
		if envFP != "" {
			return envFP
		}
	}
	return c.config.Fingerprint
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

// createSignedIdentity creates a new signed identity structure
func (c *CLI) createSignedIdentity(info *gpg.KeyInfo, targetFP, signingFP string) (*vault.Identity, *Error) {
	// Validate algorithm policy
	if !c.config.IsAlgorithmAllowed(info.Algorithm, info.AlgorithmBits) {
		return nil, NewError(fmt.Sprintf("algorithm not allowed: %s (%d bits)\n%s", info.Algorithm, info.AlgorithmBits, c.config.GetAllowedAlgorithmsString()), ExitAlgorithmNotAllowed)
	}

	// Validate encryption capability
	if !info.CanEncrypt {
		return nil, NewError(fmt.Sprintf("key %s is not capable of encryption (signing-only key).\nPlease ensure your key has an encryption subkey.", targetFP), ExitGPGError)
	}

	now := time.Now().UTC()
	algo, curve := c.gpgClient.ExtractAlgorithmAndCurve(info.Algorithm)

	newIdentity := &vault.Identity{
		AddedAt:       now,
		Fingerprint:   targetFP,
		UID:           info.UID,
		Algorithm:     algo,
		AlgorithmBits: info.AlgorithmBits,
		Curve:         curve,
		CreatedAt:     c.gpgClient.GetKeyCreationTime(targetFP),
		ExpiresAt:     info.ExpiresAt,
		PublicKey:     info.PublicKeyBase64,
		SignedBy:      signingFP,
	}

	newIdentity.Hash = ComputeIdentityHash(newIdentity)

	signature, signErr := c.gpgClient.SignDataWithAgent(signingFP, []byte(newIdentity.Hash))
	if signErr != nil {
		return nil, NewError(fmt.Sprintf("failed to sign identity: %v", signErr), ExitGPGError)
	}
	newIdentity.Signature = signature

	return newIdentity, nil
}

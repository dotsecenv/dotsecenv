package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/crypto"
	"gopkg.in/yaml.v3"
)

// ApprovedAlgorithm specifies an approved algorithm with its requirements
type ApprovedAlgorithm struct {
	Algo    string   `yaml:"algo"`             // Algorithm family name (RSA, ECC, EdDSA, etc.)
	Curves  []string `yaml:"curves,omitempty"` // For ECC/EdDSA: allowed curves (P-256, P-521, Ed25519, etc.)
	MinBits int      `yaml:"min_bits"`         // Minimum bit length
}

// GPGConfig holds GPG-related configuration
type GPGConfig struct {
	Program string `yaml:"program,omitempty"` // Path to GPG executable: "PATH" or absolute path
}

// BehaviorConfig holds granular behavior settings.
// All fields are *bool to distinguish between "not set" (nil) and "explicitly false".
// When nil, the legacy Strict field is used as fallback.
type BehaviorConfig struct {
	// RequireExplicitVaultUpgrade when true prevents automatic vault format upgrades.
	// Users must run `dotsecenv vault upgrade` explicitly.
	RequireExplicitVaultUpgrade *bool `yaml:"require_explicit_vault_upgrade,omitempty"`

	// RestrictToConfiguredVaults when true ignores CLI -v flags and uses only config vaults.
	RestrictToConfiguredVaults *bool `yaml:"restrict_to_configured_vaults,omitempty"`
}

// Login represents authenticated login state with cryptographic proof.
// The signature proves the user controls the secret key at login time.
type Login struct {
	Fingerprint string    `yaml:"fingerprint"` // GPG key fingerprint
	AddedAt     time.Time `yaml:"added_at"`    // When the login was performed
	Hash        string    `yaml:"hash"`        // SHA-256 of canonical string (login:{added_at}:{fingerprint})
	Signature   string    `yaml:"signature"`   // Hex-encoded detached GPG signature of the hash
}

// Config represents the dotsecenv configuration
type Config struct {
	ApprovedAlgorithms []ApprovedAlgorithm `yaml:"approved_algorithms"`
	Login              *Login              `yaml:"login,omitempty"`       // Authenticated login with cryptographic proof
	Fingerprint        string              `yaml:"fingerprint,omitempty"` // DEPRECATED: use login section instead
	Vault              []string            `yaml:"vault"`                 // List of vault paths
	Strict             bool                `yaml:"strict"`                // DEPRECATED: use behavior section
	Behavior           BehaviorConfig      `yaml:"behavior,omitempty"`    // Granular behavior settings
	GPG                GPGConfig           `yaml:"gpg,omitempty"`         // GPG configuration
}

// UnmarshalYAML provides custom YAML unmarshaling with better error messages for vault configuration
func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	// Create a temporary struct with the same fields for unmarshaling
	type configAlias Config
	var temp configAlias

	if err := node.Decode(&temp); err != nil {
		// Check if this is a vault configuration error
		if strings.Contains(err.Error(), "cannot unmarshal") && strings.Contains(err.Error(), "into []string") {
			// Extract line number from error message for better context
			lineInfo := ""
			if strings.Contains(err.Error(), "line ") {
				// Try to extract line number for better context
				parts := strings.Split(err.Error(), "line ")
				if len(parts) > 1 {
					lineInfo = " on line " + strings.Split(parts[1], ":")[0]
				}
			}
			return fmt.Errorf(
				"invalid vault configuration%s:\n"+
					"  Expected format: vault: [/path/to/vault, /path/to/other]\n"+
					"  Got: vault structure error (check for object syntax or missing brackets)\n"+
					"  Original error: %w",
				lineInfo, err,
			)
		}
		return err
	}

	*c = Config(temp)
	return nil
}

// ShouldRequireExplicitVaultUpgrade returns true if automatic vault upgrades should be prevented.
// Checks behavior setting first, falls back to legacy Strict field.
func (c *Config) ShouldRequireExplicitVaultUpgrade() bool {
	if c.Behavior.RequireExplicitVaultUpgrade != nil {
		return *c.Behavior.RequireExplicitVaultUpgrade
	}
	return c.Strict
}

// ShouldRestrictToConfiguredVaults returns true if CLI -v flags should be ignored.
// Checks behavior setting first, falls back to legacy Strict field.
func (c *Config) ShouldRestrictToConfiguredVaults() bool {
	if c.Behavior.RestrictToConfiguredVaults != nil {
		return *c.Behavior.RestrictToConfiguredVaults
	}
	return c.Strict
}

// GetFingerprint returns the active fingerprint, preferring login.fingerprint over the deprecated field.
// This method provides backward compatibility during the migration from the old fingerprint field.
func (c *Config) GetFingerprint() string {
	if c.Login != nil && c.Login.Fingerprint != "" {
		return c.Login.Fingerprint
	}
	return c.Fingerprint // fallback to deprecated field
}

// HasDeprecatedFingerprint returns true if the config uses the deprecated fingerprint field
// without a login section. Used to emit deprecation warnings.
func (c *Config) HasDeprecatedFingerprint() bool {
	return c.Fingerprint != "" && (c.Login == nil || c.Login.Fingerprint == "")
}

// DefaultConfig returns a new Config with FIPS 186-5 compliant algorithm defaults.
// Algorithm minimums are set per the Digital Signature Standard:
//   - RSA: 2048 bits minimum (FIPS 186-5)
//   - ECC: P-384 and P-521 curves (FIPS 186-5, P-256 excluded)
//   - EdDSA: Ed25519 and Ed448 (FIPS 186-5)
func DefaultConfig() Config {
	return Config{
		ApprovedAlgorithms: []ApprovedAlgorithm{
			{
				Algo: "ECC",
				Curves: []string{
					"P-384",
					"P-521",
				},
				MinBits: 384,
			},
			{
				Algo: "EdDSA",
				Curves: []string{
					"Ed25519",
					"Ed448",
				},
				MinBits: 255,
			},
			{
				Algo:    "RSA",
				MinBits: 2048,
			},
		},
		Fingerprint: "",
		Strict:      false,
		Vault:       []string{},                 // No default vaults from library; caller must populate
		GPG:         GPGConfig{Program: "PATH"}, // Default to PATH inference
	}
}

// Load reads the config from the specified path
// If the file doesn't exist or is empty, it returns an error
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read config: %w", err)
	}

	if len(data) == 0 {
		return Config{}, fmt.Errorf("config file is empty")
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to the specified path with proper formatting
func Save(path string, cfg Config) error {
	// Create parent directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// IsAlgorithmAllowed checks if an algorithm is in the allow-list
func (c Config) IsAlgorithmAllowed(algo string, bits int) bool {
	// All algorithms are validated through asymmetric requirements (FIPS 186-5 compliant by default)
	if len(c.ApprovedAlgorithms) <= 0 {
		return false
	}

	// Extract the base algorithm name (e.g., "ECC" from "ECC P-384", "RSA" from "RSA-4096")
	algoName := crypto.ExtractAlgorithmName(algo)

	// validateAsymmetricAgainstRequirements validates an asymmetric algorithm against requirements
	for _, req := range c.ApprovedAlgorithms {
		if strings.EqualFold(algoName, req.Algo) {
			// Check minimum bit length
			if bits > 0 && bits < req.MinBits {
				return false
			}

			// For ECC and EdDSA, check allowed curves
			if req.Algo == "ECC" || req.Algo == "EdDSA" {
				if len(req.Curves) == 0 {
					// No allowed curves specified, reject all
					return false
				}

				// Extract curve from algo
				// "ECC P-521" -> "P-521", "EdDSA Ed25519" -> "Ed25519"
				var curve string
				switch req.Algo {
				case "ECC":
					curve = strings.TrimPrefix(algo, "ECC ")
				case "EdDSA":
					curve = strings.TrimPrefix(algo, "EdDSA ")
				}
				curve = strings.TrimSpace(curve)
				return isCurveAllowed(curve, req.Curves)
			}

			return true
		}
	}

	return false
}

// isCurveAllowed checks if a curve is in the allowed list
func isCurveAllowed(curve string, allowedCurves []string) bool {
	curve = strings.TrimSpace(curve)
	for _, allowed := range allowedCurves {
		if strings.EqualFold(curve, allowed) {
			return true
		}
	}
	return false
}

// GetFingerprintFromEnv gets fingerprint from environment variable or config
func GetFingerprintFromEnv(envFingerprint, cfgFingerprint string) string {
	if envFingerprint != "" {
		return envFingerprint
	}
	return cfgFingerprint
}

// GetAllowedAlgorithmsString returns a human-readable string of approved algorithms
func (c Config) GetAllowedAlgorithmsString() string {
	var parts []string
	for _, alg := range c.ApprovedAlgorithms {
		part := fmt.Sprintf("%s (minimum %d bits", alg.Algo, alg.MinBits)
		if len(alg.Curves) > 0 {
			part += fmt.Sprintf(", curves: %s", strings.Join(alg.Curves, ", "))
		}
		part += ")"
		parts = append(parts, part)
	}
	return "Allowed algorithms: " + strings.Join(parts, ", ")
}

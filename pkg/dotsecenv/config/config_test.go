package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.ApprovedAlgorithms) == 0 {
		t.Error("DefaultConfig should have approved algorithms")
	}

	// Verify FIPS-compliant minimums
	for _, algo := range cfg.ApprovedAlgorithms {
		switch algo.Algo {
		case "RSA":
			if algo.MinBits < 2048 {
				t.Errorf("RSA min bits should be >= 2048 (FIPS 186-5), got %d", algo.MinBits)
			}
		case "ECC":
			if algo.MinBits < 384 {
				t.Errorf("ECC min bits should be >= 384 (FIPS 186-5), got %d", algo.MinBits)
			}
		case "EdDSA":
			if algo.MinBits < 255 {
				t.Errorf("EdDSA min bits should be >= 255 (Ed25519), got %d", algo.MinBits)
			}
		}
	}

	// Verify required algorithms are present
	algoMap := make(map[string]bool)
	for _, algo := range cfg.ApprovedAlgorithms {
		algoMap[algo.Algo] = true
	}

	for _, required := range []string{"RSA", "ECC", "EdDSA"} {
		if !algoMap[required] {
			t.Errorf("DefaultConfig missing required algorithm: %s", required)
		}
	}
}

func TestIsAlgorithmAllowed(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name    string
		algo    string
		bits    int
		allowed bool
	}{
		// RSA: minimum 2048 bits (FIPS 186-5)
		{"RSA-4096", "RSA", 4096, true},
		{"RSA-3072", "RSA", 3072, true},
		{"RSA-2048", "RSA", 2048, true},
		{"RSA-1024", "RSA", 1024, false}, // Below FIPS minimum
		// ECC: P-384 and P-521 only (FIPS 186-5)
		{"ECC P-521", "ECC P-521", 521, true},
		{"ECC P-384", "ECC P-384", 384, true},
		{"ECC P-256", "ECC P-256", 256, false}, // Excluded for FIPS compliance
		{"ECC Unknown", "ECC Unknown", 256, false},
		// EdDSA: Ed25519 and Ed448
		{"EdDSA Ed25519", "EdDSA Ed25519", 255, true},
		{"EdDSA Ed448", "EdDSA Ed448", 448, true},
		{"Unknown", "Unknown", 1024, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.IsAlgorithmAllowed(tt.algo, tt.bits); got != tt.allowed {
				t.Errorf("IsAlgorithmAllowed(%q, %d) = %v, want %v", tt.algo, tt.bits, got, tt.allowed)
			}
		})
	}
}

func TestConfigLoadSave(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfgPath := filepath.Join(tempDir, "config.yaml")
	cfg := DefaultConfig()
	cfg.Fingerprint = "test-fingerprint"
	cfg.Vault = []string{"/path/to/vault"}

	if err := Save(cfgPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loadedCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loadedCfg.Fingerprint != cfg.Fingerprint {
		t.Errorf("expected fingerprint %s, got %s", cfg.Fingerprint, loadedCfg.Fingerprint)
	}
	if len(loadedCfg.Vault) != len(cfg.Vault) || loadedCfg.Vault[0] != cfg.Vault[0] {
		t.Errorf("vault paths mismatch")
	}
}

func TestUnmarshalYAML_Error(t *testing.T) {
	badYAML := `
vault:
  nested: value
`
	var cfg Config
	err := yaml.Unmarshal([]byte(badYAML), &cfg)
	if err == nil {
		t.Fatal("expected error unmarshaling bad YAML")
	}

	if !strings.Contains(err.Error(), "invalid vault configuration") {
		t.Errorf("expected custom error message, got: %v", err)
	}
}

// boolPtr returns a pointer to a bool value
func boolPtr(b bool) *bool {
	return &b
}

func TestShouldRequireTTYForDecryption(t *testing.T) {
	tests := []struct {
		name     string
		behavior *bool
		strict   bool
		expected bool
	}{
		{"nil behavior, strict false", nil, false, false},
		{"nil behavior, strict true", nil, true, true},
		{"explicit false, strict true", boolPtr(false), true, false},
		{"explicit true, strict false", boolPtr(true), false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Strict: tt.strict,
				Behavior: BehaviorConfig{
					RequireTTYForDecryption: tt.behavior,
				},
			}
			if got := cfg.ShouldRequireTTYForDecryption(); got != tt.expected {
				t.Errorf("ShouldRequireTTYForDecryption() = %v, want %v", got, tt.expected)
			}
		})
	}
}

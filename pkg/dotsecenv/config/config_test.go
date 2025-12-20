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

	// Check for RSA
	hasRSA := false
	for _, algo := range cfg.ApprovedAlgorithms {
		if algo.Algo == "RSA" {
			hasRSA = true
			if algo.MinBits != 1024 {
				t.Errorf("expected RSA min bits 1024, got %d", algo.MinBits)
			}
		}
	}
	if !hasRSA {
		t.Error("DefaultConfig missing RSA")
	}
}

func TestFIPSConfig(t *testing.T) {
	cfg := FIPSConfig()

	for _, algo := range cfg.ApprovedAlgorithms {
		if algo.Algo == "RSA" {
			if algo.MinBits < 3072 {
				t.Errorf("FIPS RSA min bits should be >= 3072, got %d", algo.MinBits)
			}
		}
		if algo.Algo == "ECC" {
			if algo.MinBits < 384 {
				t.Errorf("FIPS ECC min bits should be >= 384, got %d", algo.MinBits)
			}
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
		{"RSA-2048", "RSA", 2048, true},
		{"RSA-1024", "RSA", 1024, true},
		{"RSA-512", "RSA", 512, false},
		{"ECC P-256", "ECC P-256", 256, true},
		{"ECC P-384", "ECC P-384", 384, true},
		{"ECC Unknown", "ECC Unknown", 256, false},
		{"EdDSA Ed25519", "EdDSA Ed25519", 255, true},
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

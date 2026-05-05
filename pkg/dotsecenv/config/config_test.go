package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// Hand-construct a Login literal: this test exercises YAML round-trip,
	// not signature crypto, so importing gpg here would invert package layering.
	// Truncate AddedAt to seconds — YAML round-trip drops monotonic/nanos.
	cfg.Login = &Login{
		Fingerprint: "test-fingerprint",
		AddedAt:     time.Now().UTC().Truncate(time.Second),
		Hash:        "abc",
		Signature:   "sig",
	}
	cfg.Vault = []string{"/path/to/vault"}

	if err := Save(cfgPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loadedCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loadedCfg.Login == nil {
		t.Fatal("expected Login to be present after round-trip")
	}
	if loadedCfg.Login.Fingerprint != cfg.Login.Fingerprint {
		t.Errorf("expected fingerprint %s, got %s", cfg.Login.Fingerprint, loadedCfg.Login.Fingerprint)
	}
	if !loadedCfg.Login.AddedAt.Equal(cfg.Login.AddedAt) {
		t.Errorf("expected AddedAt %s, got %s", cfg.Login.AddedAt, loadedCfg.Login.AddedAt)
	}
	if loadedCfg.Login.Hash != cfg.Login.Hash {
		t.Errorf("expected hash %s, got %s", cfg.Login.Hash, loadedCfg.Login.Hash)
	}
	if loadedCfg.Login.Signature != cfg.Login.Signature {
		t.Errorf("expected signature %s, got %s", cfg.Login.Signature, loadedCfg.Login.Signature)
	}
	if len(loadedCfg.Vault) != len(cfg.Vault) || loadedCfg.Vault[0] != cfg.Vault[0] {
		t.Errorf("vault paths mismatch")
	}
}

// TestLoad_StrayFingerprintFieldIsIgnored guards the post-cleanup contract:
// an old config that still carries a top-level `fingerprint:` key must load
// without error. yaml.v3 silently drops unknown keys, so the deprecated value
// is discarded and the config loads as if the field were absent. Identity is
// resolved exclusively from the signed `login:` section.
func TestLoad_StrayFingerprintFieldIsIgnored(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_stray_fingerprint_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfgPath := filepath.Join(tempDir, "stray.yaml")
	body := []byte(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
fingerprint: ABC123DEF456
vault:
  - /tmp/v
`)
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Login != nil {
		t.Errorf("stray fingerprint must not populate Login: got %+v", cfg.Login)
	}
	if len(cfg.Vault) != 1 || cfg.Vault[0] != "/tmp/v" {
		t.Errorf("vault entries lost during load: %v", cfg.Vault)
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

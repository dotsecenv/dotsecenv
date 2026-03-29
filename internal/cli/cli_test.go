package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
)

func TestNewCLIConfigOnly_LoadsConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Create a valid config file
	cfg := config.DefaultConfig()
	cfg.Vault = []string{"/tmp/nonexistent-vault.dsv"}
	cfg.GPG.Program = "PATH"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cli, err := NewCLIConfigOnly(cfgPath, true, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("NewCLIConfigOnly failed: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Config should be loaded
	if cli.configPath != cfgPath {
		t.Errorf("expected configPath=%s, got %s", cfgPath, cli.configPath)
	}

	// Vault resolver should be nil (no vault init)
	if cli.vaultResolver != nil {
		t.Error("expected vaultResolver to be nil for config-only CLI")
	}
}

func TestNewCLIConfigOnly_MissingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nonexistent.yaml")

	var stdout, stderr bytes.Buffer
	_, err := NewCLIConfigOnly(cfgPath, true, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing config, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "config file not found") {
		t.Errorf("expected 'config file not found' in error, got: %s", errMsg)
	}
}

func TestNewCLIConfigOnly_DoesNotOpenVaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Create config pointing to a vault that does NOT exist
	cfg := config.DefaultConfig()
	cfg.Vault = []string{filepath.Join(tmpDir, "nonexistent.dsv")}
	cfg.GPG.Program = "PATH"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cli, err := NewCLIConfigOnly(cfgPath, true, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("NewCLIConfigOnly should succeed even with nonexistent vault, got: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Verify it didn't try to create the vault file
	if _, statErr := os.Stat(filepath.Join(tmpDir, "nonexistent.dsv")); !os.IsNotExist(statErr) {
		t.Error("config-only CLI should not create or touch vault files")
	}
}

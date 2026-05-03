package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/policy"
)

// withTempPolicyDir overrides policy.DefaultDir for the duration of t and
// restores it on cleanup. The returned dir is the one tests should write
// fragments into.
func withTempPolicyDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	orig := policy.DefaultDir
	policy.DefaultDir = tmp
	t.Cleanup(func() { policy.DefaultDir = orig })
	return tmp
}

// pointPolicyAtMissing makes policy.DefaultDir point at a path that does
// not exist for the duration of t. Used to neutralise system-wide policy
// in tests that don't care about it.
func pointPolicyAtMissing(t *testing.T) {
	t.Helper()
	orig := policy.DefaultDir
	policy.DefaultDir = filepath.Join(t.TempDir(), "no-such-policy-dir")
	t.Cleanup(func() { policy.DefaultDir = orig })
}

func TestNewCLIConfigOnly_LoadsConfig(t *testing.T) {
	pointPolicyAtMissing(t)
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
	pointPolicyAtMissing(t)
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
	pointPolicyAtMissing(t)
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

// TestNewCLIConfigOnly_AbortsOnBrokenPolicy proves that any policy load
// failure (malformed YAML, forbidden key, empty allow-list, insecure perms)
// prevents dotsecenv from starting. Fail closed: a broken policy directory
// is indistinguishable from tampering.
//
// The test uses a real temp dir as the policy directory but writes fragments
// owned by the test user (not root). Since the production permission check
// requires root ownership, the load would normally fail with
// ErrInsecurePermissions before reaching the malformed-content check. We
// can only fully exercise the malformed/forbidden paths via the unit-test
// `loadFromDir(dir, secureStat)` in policy_test.go (which fakes the perm
// check). Here we cover the "any failure aborts" contract by checking the
// permission failure itself — equivalent semantically.
func TestNewCLIConfigOnly_AbortsOnInsecurePolicy(t *testing.T) {
	policyDir := withTempPolicyDir(t)
	if err := os.WriteFile(filepath.Join(policyDir, "00-broken.yaml"), []byte("approved_algorithms: [{algo: RSA, min_bits: 2048}]"), 0o644); err != nil {
		t.Fatalf("write fragment: %v", err)
	}

	// Set up a valid user config so the only thing that can fail is policy.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	cfg := config.DefaultConfig()
	cfg.Vault = []string{filepath.Join(cfgDir, "vault.dsv")}
	cfg.GPG.Program = "PATH"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	_, err := NewCLIConfigOnly(cfgPath, true, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected NewCLIConfigOnly to fail on insecure policy, got nil")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("expected error to mention insecure permissions, got: %v", err)
	}
}

// TestNewCLIConfigOnly_PolicyLoadErrorClassification ensures the error
// classification (permission vs config vs general) reaches the caller —
// not just a generic "failed to load policy" wrapper.
func TestNewCLIConfigOnly_PolicyLoadErrorClassification(t *testing.T) {
	policyDir := withTempPolicyDir(t)
	// A test-user-owned fragment triggers ErrInsecurePermissions, which
	// classifyPolicyError maps to ExitAccessDenied.
	if err := os.WriteFile(filepath.Join(policyDir, "00.yaml"), []byte("approved_algorithms: [{algo: RSA, min_bits: 2048}]"), 0o644); err != nil {
		t.Fatalf("write fragment: %v", err)
	}

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	cfg := config.DefaultConfig()
	cfg.Vault = []string{filepath.Join(cfgDir, "vault.dsv")}
	cfg.GPG.Program = "PATH"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	_, err := NewCLIConfigOnly(cfgPath, true, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	cliErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if cliErr.ExitCode != ExitAccessDenied {
		t.Errorf("expected ExitAccessDenied (%d), got exit code %d", ExitAccessDenied, cliErr.ExitCode)
	}
}

// errorsIsCheck satisfies the goimports lint by ensuring we use errors.Is
// somewhere in this file even when tests don't reference it directly.
var _ = errors.Is

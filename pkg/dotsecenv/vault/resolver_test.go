package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVaults_MissingConfiguredVault(t *testing.T) {
	// Create a vault config with a non-existent vault path
	config := VaultConfig{
		Entries: []VaultEntry{
			{
				Path: "/nonexistent/path/to/vault",
			},
		},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	// Try to open the missing vault
	err := resolver.OpenVaults(stderr)

	// Should return an error because the required vault couldn't be opened
	if err == nil {
		t.Fatal("expected error when configured vault file doesn't exist, but got nil")
	}

	// Error should mention the required vault couldn't be opened
	errMsg := err.Error()
	if !strings.Contains(errMsg, "no vault files could be opened") {
		t.Errorf("expected error to mention 'no vault files could be opened', got: %v", errMsg)
	}

	// Stderr should be empty (missing files are silently skipped)
	stderrOutput := stderr.String()
	if stderrOutput != "" {
		t.Errorf("expected no stderr output for missing vault file, got: %s", stderrOutput)
	}
}

func TestOpenVaults_ValidVault(t *testing.T) {
	// Create a temporary vault file
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")

	// Create the vault file
	vm := NewManager(vaultPath, false)
	if err := vm.OpenAndLock(); err != nil {
		t.Fatalf("failed to create test vault: %v", err)
	}
	if err := vm.Save(); err != nil {
		t.Fatalf("failed to save test vault: %v", err)
	}
	if err := vm.Unlock(); err != nil {
		t.Fatalf("failed to close test vault: %v", err)
	}

	// Create a vault config pointing to the valid vault
	config := VaultConfig{
		Entries: []VaultEntry{
			{
				Path: vaultPath,
			},
		},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	// Try to open the vault
	err := resolver.OpenVaults(stderr)

	// Should not return an error
	if err != nil {
		t.Fatalf("expected no error for valid vault, got: %v", err)
	}

	// Resolver should have loaded the vault (can verify via GetVaultPaths or checking GetVaultManager(0))
	paths := resolver.GetVaultPaths()
	if len(paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(paths))
	}

	manager := resolver.GetVaultManager(0)
	if manager == nil {
		t.Errorf("expected vault 0 to be loaded")
	}
}

func TestOpenVaults_MultipleVaults_OneMissing(t *testing.T) {
	// Create one temporary vault file
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "existing.vault")

	vm := NewManager(vaultPath, false)
	if err := vm.OpenAndLock(); err != nil {
		t.Fatalf("failed to create test vault: %v", err)
	}
	if err := vm.Save(); err != nil {
		t.Fatalf("failed to save test vault: %v", err)
	}
	if err := vm.Unlock(); err != nil {
		t.Fatalf("failed to close test vault: %v", err)
	}

	// Create a config with one valid and one missing optional vault
	// The missing optional vault should be skipped with a warning, but the valid one should be loaded
	config := VaultConfig{
		Entries: []VaultEntry{
			{
				Path: vaultPath,
			},
			{
				Path:     "/nonexistent/vault",
				Optional: true, // Mark as optional so missing vault doesn't cause failure
			},
		},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	// Try to open vaults
	err := resolver.OpenVaults(stderr)

	// Should succeed because at least one vault is valid
	if err != nil {
		t.Fatalf("expected no error when at least one vault is valid, got: %v", err)
	}

	// Check vaults loaded
	// Vault 0 should be loaded
	if resolver.GetVaultManager(0) == nil {
		t.Errorf("expected vault 0 (existing) to be loaded")
	}
	// Vault 1 should be nil (failed)
	if resolver.GetVaultManager(1) != nil {
		t.Errorf("expected vault 1 (missing) to be nil")
	}

	// Stderr should be empty (missing files are silently skipped)
	stderrOutput := stderr.String()
	if stderrOutput != "" {
		t.Errorf("expected no stderr output for missing vault file, got: %s", stderrOutput)
	}
}

func TestOpenVaults_AllMissing(t *testing.T) {
	// Create a config with all missing required vaults
	config := VaultConfig{
		Entries: []VaultEntry{
			{
				Path: "/nonexistent/vault1",
			},
			{
				Path: "/nonexistent/vault2",
			},
		},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	// Try to open vaults
	err := resolver.OpenVaults(stderr)

	// Should return an error because required vaults couldn't be opened
	if err == nil {
		t.Fatal("expected error when required vaults can't be opened, but got nil")
	}

	// The error should mention that required vault files could not be opened
	errMsg := err.Error()
	if !strings.Contains(errMsg, "no vault files could be opened") {
		t.Errorf("expected error about required vault files, got: %v", errMsg)
	}

	// Stderr should be empty (missing files are silently skipped)
	stderrOutput := stderr.String()
	if stderrOutput != "" {
		t.Errorf("expected no stderr output for missing vault files, got: %s", stderrOutput)
	}
}

func TestOpenVaults_MultipleVaults_AllValid(t *testing.T) {
	// Create two temporary vault files
	tmpDir := t.TempDir()
	vaultPath1 := filepath.Join(tmpDir, "vault1.vault")
	vaultPath2 := filepath.Join(tmpDir, "vault2.vault")

	// Create first vault
	vm1 := NewManager(vaultPath1, false)
	if err := vm1.OpenAndLock(); err != nil {
		t.Fatalf("failed to create first test vault: %v", err)
	}
	if err := vm1.Save(); err != nil {
		t.Fatalf("failed to save first test vault: %v", err)
	}
	if err := vm1.Unlock(); err != nil {
		t.Fatalf("failed to close first test vault: %v", err)
	}

	// Create second vault
	vm2 := NewManager(vaultPath2, false)
	if err := vm2.OpenAndLock(); err != nil {
		t.Fatalf("failed to create second test vault: %v", err)
	}
	if err := vm2.Save(); err != nil {
		t.Fatalf("failed to save second test vault: %v", err)
	}
	if err := vm2.Unlock(); err != nil {
		t.Fatalf("failed to close second test vault: %v", err)
	}

	// Create a config with both vaults
	config := VaultConfig{
		Entries: []VaultEntry{
			{
				Path: vaultPath1,
			},
			{
				Path: vaultPath2,
			},
		},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	// Try to open vaults
	err := resolver.OpenVaults(stderr)

	// Should succeed
	if err != nil {
		t.Fatalf("expected no error for valid vaults, got: %v", err)
	}

	// Resolver should have loaded both vaults
	if resolver.GetVaultManager(0) == nil {
		t.Errorf("expected vault 0 to be loaded")
	}
	if resolver.GetVaultManager(1) == nil {
		t.Errorf("expected vault 1 to be loaded")
	}
}

func TestOpenVaults_EmptyConfig(t *testing.T) {
	config := VaultConfig{
		Entries: []VaultEntry{},
	}

	resolver := NewVaultResolver(config)
	stderr := &bytes.Buffer{}

	err := resolver.OpenVaults(stderr)

	if err == nil {
		t.Fatal("expected error for empty vault config, but got nil")
	}

	if !strings.Contains(err.Error(), "no vaults configured") {
		t.Errorf("expected error to mention 'no vaults configured', got: %v", err)
	}
}

func TestOpenVaultsFromPaths_NotFound(t *testing.T) {
	resolver := NewVaultResolver(VaultConfig{})
	stderr := &bytes.Buffer{}

	err := resolver.OpenVaultsFromPaths([]string{"/nonexistent/vault/path"}, stderr)

	if err == nil {
		t.Fatal("expected error for non-existent vault file")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "not found") {
		t.Errorf("expected error to contain 'not found', got: %v", errMsg)
	}
}

func TestOpenVaultsFromPaths_PermissionDenied(t *testing.T) {
	// Skip if running as root (root can read any file)
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	// Create a vault file with no read permissions
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "noperm.vault")

	// Create the file first
	if err := os.WriteFile(vaultPath, []byte("test"), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Remove all permissions
	if err := os.Chmod(vaultPath, 0o000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	// Ensure cleanup restores permissions so temp dir can be removed
	t.Cleanup(func() {
		_ = os.Chmod(vaultPath, 0o600)
	})

	resolver := NewVaultResolver(VaultConfig{})
	stderr := &bytes.Buffer{}

	err := resolver.OpenVaultsFromPaths([]string{vaultPath}, stderr)

	if err == nil {
		t.Fatal("expected error for permission denied")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "permission denied") {
		t.Errorf("expected error to contain 'permission denied', got: %v", errMsg)
	}
	if !strings.Contains(errMsg, "Check file permissions") {
		t.Errorf("expected error to contain helpful suggestion, got: %v", errMsg)
	}
}

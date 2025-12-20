package vault

import (
	"bytes"
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
	if !strings.Contains(errMsg, "nonexistent") || !strings.Contains(errMsg, "vault") {
		t.Errorf("expected error to mention the vault path, got: %v", errMsg)
	}

	// Stderr should contain an error about the missing vault (not a warning, since it's required)
	stderrOutput := stderr.String()
	if !strings.Contains(stderrOutput, "warning") || !strings.Contains(stderrOutput, "vault") {
		t.Errorf("expected warning in stderr about missing vault, got: %s", stderrOutput)
	}
}

func TestOpenVaults_ValidVault(t *testing.T) {
	// Create a temporary vault file
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")

	// Create the vault file
	vm := NewManager(vaultPath)
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

	vm := NewManager(vaultPath)
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

	// Stderr should contain a warning about the missing optional vault
	stderrOutput := stderr.String()
	if !strings.Contains(stderrOutput, "warning") || !strings.Contains(stderrOutput, "/nonexistent/vault") {
		t.Errorf("expected warning about missing optional vault, got: %s", stderrOutput)
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

	// Stderr should contain error messages about the missing required vaults
	stderrOutput := stderr.String()
	if !strings.Contains(stderrOutput, "warning") || !strings.Contains(stderrOutput, "vault") {
		t.Errorf("expected warning messages in stderr about missing vaults, got: %s", stderrOutput)
	}
}

func TestOpenVaults_MultipleVaults_AllValid(t *testing.T) {
	// Create two temporary vault files
	tmpDir := t.TempDir()
	vaultPath1 := filepath.Join(tmpDir, "vault1.vault")
	vaultPath2 := filepath.Join(tmpDir, "vault2.vault")

	// Create first vault
	vm1 := NewManager(vaultPath1)
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
	vm2 := NewManager(vaultPath2)
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

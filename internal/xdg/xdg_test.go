package xdg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPaths(t *testing.T) {
	// Save current env vars
	origConfigHome := os.Getenv("XDG_CONFIG_HOME")
	origDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		_ = os.Setenv("XDG_CONFIG_HOME", origConfigHome)
		_ = os.Setenv("XDG_DATA_HOME", origDataHome)
	}()

	t.Run("defaults", func(t *testing.T) {
		_ = os.Unsetenv("XDG_CONFIG_HOME")
		_ = os.Unsetenv("XDG_DATA_HOME")

		paths, err := NewPaths()
		if err != nil {
			t.Fatalf("NewPaths failed: %v", err)
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("failed to get home dir: %v", err)
		}

		expectedConfig := filepath.Join(homeDir, ".config")
		expectedData := filepath.Join(homeDir, ".local", "share")

		if paths.ConfigHome != expectedConfig {
			t.Errorf("expected ConfigHome %s, got %s", expectedConfig, paths.ConfigHome)
		}
		if paths.DataHome != expectedData {
			t.Errorf("expected DataHome %s, got %s", expectedData, paths.DataHome)
		}
	})

	t.Run("with env vars", func(t *testing.T) {
		customConfig := "/tmp/custom/config"
		customData := "/tmp/custom/data"
		_ = os.Setenv("XDG_CONFIG_HOME", customConfig)
		_ = os.Setenv("XDG_DATA_HOME", customData)

		paths, err := NewPaths()
		if err != nil {
			t.Fatalf("NewPaths failed: %v", err)
		}

		if paths.ConfigHome != customConfig {
			t.Errorf("expected ConfigHome %s, got %s", customConfig, paths.ConfigHome)
		}
		if paths.DataHome != customData {
			t.Errorf("expected DataHome %s, got %s", customData, paths.DataHome)
		}
	})
}

func TestPaths_Helpers(t *testing.T) {
	p := Paths{
		ConfigHome: "/config",
		DataHome:   "/data",
	}

	expectedConfigPath := filepath.Join("/config", "dotsecenv", "config")
	if got := p.ConfigPath(); got != expectedConfigPath {
		t.Errorf("ConfigPath: expected %s, got %s", expectedConfigPath, got)
	}

	expectedVaultPath := filepath.Join("/data", "dotsecenv", "vault")
	if got := p.VaultPath(); got != expectedVaultPath {
		t.Errorf("VaultPath: expected %s, got %s", expectedVaultPath, got)
	}
}

func TestEnsureDirs(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "xdg_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	p := Paths{
		ConfigHome: filepath.Join(tempDir, "config"),
		DataHome:   filepath.Join(tempDir, "data"),
	}

	if err := p.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs failed: %v", err)
	}

	dirs := []string{
		filepath.Join(p.ConfigHome, "dotsecenv"),
		filepath.Join(p.DataHome, "dotsecenv"),
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %s not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
		// Check permissions (approximate, masking might apply)
		mode := info.Mode().Perm()
		if mode&0700 != 0700 {
			t.Errorf("directory %s has wrong permissions: %v", dir, mode)
		}
	}
}

func TestGetDefaultVaultPaths(t *testing.T) {
	p := Paths{
		DataHome: "/data",
	}

	t.Run("normal execution", func(t *testing.T) {
		paths := p.GetDefaultVaultPaths(false)
		expected := []string{
			".dotsecenv/vault",
			filepath.Join("/data", "dotsecenv", "vault"),
			"/var/lib/dotsecenv/vault",
		}

		if len(paths) != len(expected) {
			t.Errorf("expected %d paths, got %d", len(expected), len(paths))
		}
		for i := range expected {
			if paths[i] != expected[i] {
				t.Errorf("path[%d]: expected %s, got %s", i, expected[i], paths[i])
			}
		}
	})

	t.Run("suid execution", func(t *testing.T) {
		paths := p.GetDefaultVaultPaths(true)
		expected := []string{
			"/var/lib/dotsecenv/vault",
		}

		if len(paths) != len(expected) {
			t.Errorf("expected %d paths, got %d", len(expected), len(paths))
		}
		// Check that the user vault is NOT present
		userVault := filepath.Join("/data", "dotsecenv", "vault")
		for _, path := range paths {
			if path == userVault {
				t.Error("user vault found in SUID execution paths")
			}
		}
	})
}

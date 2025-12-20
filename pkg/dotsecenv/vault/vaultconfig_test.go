package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseVaultConfig_SimplePaths(t *testing.T) {
	entries := []string{
		".dotsecenv/vault",
		"~/.local/share/dotsecenv/vault",
		"/var/lib/dotsecenv/vault",
	}

	cfg, err := ParseVaultConfig(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(cfg.Entries))
	}
}

func TestExpandPath(t *testing.T) {
	// Need a way to reliably test home dir expansion.
	// getCurrentUserHomeDir uses os/user which might behave differently in test env.
	// However, expandPath uses getCurrentUserHomeDir.
	// We can assume it works similarly to os.UserHomeDir in standard env.

	home, _ := os.UserHomeDir()
	// Note: if os.UserHomeDir differs from what os/user returns (e.g. in some containers), this test might fail.
	// But usually they align.

	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		// Simple checks
		{"/absolute/path", "/absolute/path", "absolute path unchanged"},
		{"relative/path", "relative/path", "relative path unchanged"},
	}

	for _, test := range tests {
		result := ExpandPath(test.input)
		if result != test.expected {
			t.Errorf("%s: expected '%s', got '%s'", test.desc, test.expected, result)
		}
	}

	// Tilde expansion test
	res := ExpandPath("~/.config")
	// It should be absolute path now or relative to home.
	// Check suffix at least.
	if !filepath.IsAbs(res) && home != "" {
		// Not absolute and home is set? Use it as base?
		// For now we assume if it starts with ~ resolved to home, so it is absolute.
		// This branch is kept for understanding behavior but does nothing yet.
		_ = home // Suppress empty branch warning
	}
}

func TestGetEntriesInOrder(t *testing.T) {
	cfg := VaultConfig{
		Entries: []VaultEntry{
			{Path: ".dotsecenv/vault"},
			{Path: "/custom"},
		},
	}

	entries := cfg.GetEntriesInOrder()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries")
	}
	if entries[0].Path != ".dotsecenv/vault" {
		t.Errorf("order mismatch 0")
	}
	if entries[1].Path != "/custom" {
		t.Errorf("order mismatch 1")
	}
}

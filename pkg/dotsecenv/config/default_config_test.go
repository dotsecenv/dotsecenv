package config

import (
	"testing"
)

func TestDefaultConfig_VaultEntries(t *testing.T) {
	cfg := DefaultConfig()

	// Default config should not populate vault entries anymore (delegated to CLI)
	if len(cfg.Vault) != 0 {
		t.Errorf("expected default config to have 0 vault entries, got %d", len(cfg.Vault))
	}
}

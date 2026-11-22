package main_test

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// validate only reports. --fix used to be accepted and silently ignored, so
// it must fail and point at doctor, which does repair.
func TestValidate_FixFlagPointsToDoctor(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")
	writeTestConfig(t, configPath, []string{vaultPath})
	if _, stderr, err := runCmd("init", "vault", "-v", vaultPath); err != nil {
		t.Fatalf("init vault: %v\n%s", err, stderr)
	}

	_, stderr, err := runCmd("-c", configPath, "validate", "--fix")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("validate --fix: want exit 1, got %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "dotsecenv doctor --fix") {
		t.Errorf("validate --fix should point to doctor --fix, got: %s", stderr)
	}

	if _, stderr, err := runCmd("-c", configPath, "validate"); err != nil {
		t.Errorf("plain validate should still succeed: %v\n%s", err, stderr)
	}
}

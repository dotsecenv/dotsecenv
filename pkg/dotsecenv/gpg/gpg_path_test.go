package gpg

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndSetGPGProgram_AbsolutePath(t *testing.T) {
	// Find a real GPG executable to test with
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH, skipping test")
	}

	err = ValidateAndSetGPGProgram(gpgPath)
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) returned error: %v", gpgPath, err)
	}

	// Verify the path was set
	if GetGPGProgram() != gpgPath {
		t.Errorf("GetGPGProgram() = %q, want %q", GetGPGProgram(), gpgPath)
	}
}

func TestValidateAndSetGPGProgram_PATH(t *testing.T) {
	// This test requires gpg to be in PATH
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH, skipping test")
	}

	err = ValidateAndSetGPGProgram("PATH")
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(\"PATH\") returned error: %v", err)
	}

	// Verify the path was set to the resolved path from PATH
	if GetGPGProgram() != gpgPath {
		t.Errorf("GetGPGProgram() = %q, want %q", GetGPGProgram(), gpgPath)
	}
}

func TestValidateAndSetGPGProgram_RelativePath(t *testing.T) {
	err := ValidateAndSetGPGProgram("gpg")
	if err == nil {
		t.Error("ValidateAndSetGPGProgram(\"gpg\") should return error for relative path")
	}

	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error message should mention 'absolute path': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_NonExistent(t *testing.T) {
	nonExistent := "/nonexistent/path/to/gpg"
	err := ValidateAndSetGPGProgram(nonExistent)
	if err == nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) should return error for non-existent file", nonExistent)
	}

	if !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("error message should mention 'not an executable': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_EmptyPath_ReturnsError(t *testing.T) {
	err := ValidateAndSetGPGProgram("")
	if err == nil {
		t.Error("ValidateAndSetGPGProgram(\"\") should return error")
	}

	if !strings.Contains(err.Error(), "must be configured") {
		t.Errorf("error message should mention 'must be configured': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_NotExecutable(t *testing.T) {
	// Create a temporary file that is not executable
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "fake-gpg")
	if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho hello"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	err := ValidateAndSetGPGProgram(tmpFile)
	if err == nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) should return error for non-executable file", tmpFile)
	}

	if !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("error message should mention 'not an executable': %s", err.Error())
	}
}

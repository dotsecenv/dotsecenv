package gpg

import (
	"bytes"
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

	var stderr bytes.Buffer
	err = ValidateAndSetGPGProgram(gpgPath, false, &stderr)
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) returned error: %v", gpgPath, err)
	}

	// Should not print warning when path is explicitly specified
	if stderr.Len() > 0 {
		t.Errorf("unexpected warning: %s", stderr.String())
	}

	// Verify the path was set
	if GetGPGProgram() != gpgPath {
		t.Errorf("GetGPGProgram() = %q, want %q", GetGPGProgram(), gpgPath)
	}
}

func TestValidateAndSetGPGProgram_RelativePath(t *testing.T) {
	var stderr bytes.Buffer
	err := ValidateAndSetGPGProgram("gpg", false, &stderr)
	if err == nil {
		t.Error("ValidateAndSetGPGProgram(\"gpg\") should return error for relative path")
	}

	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error message should mention 'absolute path': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_NonExistent(t *testing.T) {
	var stderr bytes.Buffer
	nonExistent := "/nonexistent/path/to/gpg"
	err := ValidateAndSetGPGProgram(nonExistent, false, &stderr)
	if err == nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) should return error for non-existent file", nonExistent)
	}

	if !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("error message should mention 'not an executable': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_EmptyPath_InfersFromPATH(t *testing.T) {
	// This test requires gpg to be in PATH
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH, skipping test")
	}

	var stderr bytes.Buffer
	err = ValidateAndSetGPGProgram("", false, &stderr)
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(\"\") returned error: %v", err)
	}

	// Should print warning about inferring from PATH
	if !strings.Contains(stderr.String(), "warning:") {
		t.Errorf("expected warning about inferring from PATH, got: %s", stderr.String())
	}

	if !strings.Contains(stderr.String(), "gpg.program not configured") {
		t.Errorf("expected warning about gpg.program not configured, got: %s", stderr.String())
	}

	// Verify the path was set to the resolved path
	if GetGPGProgram() != gpgPath {
		t.Errorf("GetGPGProgram() = %q, want %q", GetGPGProgram(), gpgPath)
	}
}

func TestValidateAndSetGPGProgram_EmptyPath_SilentMode(t *testing.T) {
	// This test requires gpg to be in PATH
	_, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH, skipping test")
	}

	// Pass nil for stderr to simulate silent mode
	err = ValidateAndSetGPGProgram("", false, nil)
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(\"\") returned error: %v", err)
	}
}

func TestValidateAndSetGPGProgram_StrictMode_EmptyPath(t *testing.T) {
	var stderr bytes.Buffer
	err := ValidateAndSetGPGProgram("", true, &stderr)
	if err == nil {
		t.Error("ValidateAndSetGPGProgram(\"\", strict=true) should return error")
	}

	if !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("error message should mention 'strict mode': %s", err.Error())
	}
}

func TestValidateAndSetGPGProgram_StrictMode_ValidPath(t *testing.T) {
	// Find a real GPG executable to test with
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH, skipping test")
	}

	var stderr bytes.Buffer
	err = ValidateAndSetGPGProgram(gpgPath, true, &stderr)
	if err != nil {
		t.Errorf("ValidateAndSetGPGProgram(%q, strict=true) returned error: %v", gpgPath, err)
	}
}

func TestValidateAndSetGPGProgram_NotExecutable(t *testing.T) {
	// Create a temporary file that is not executable
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "fake-gpg")
	if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho hello"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	var stderr bytes.Buffer
	err := ValidateAndSetGPGProgram(tmpFile, false, &stderr)
	if err == nil {
		t.Errorf("ValidateAndSetGPGProgram(%q) should return error for non-executable file", tmpFile)
	}

	if !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("error message should mention 'not an executable': %s", err.Error())
	}
}

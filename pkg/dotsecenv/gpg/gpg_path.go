package gpg

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
)

var (
	// resolvedGPGPath caches the resolved GPG path
	resolvedGPGPath string
	resolvedOnce    sync.Once
	configuredPath  string
)

// ValidateAndSetGPGProgram validates and sets the GPG program path.
// It returns an error if validation fails.
//
// Validation rules:
//   - "PATH": explicitly infer gpg from system PATH (silent, no warning)
//   - Absolute path: must point to an existing, executable program
//   - Empty/missing: returns an error (must be explicitly configured)
func ValidateAndSetGPGProgram(program string) error {
	// Empty/missing program is an error - must be explicitly configured
	if program == "" {
		return errors.New("gpg.program must be configured (set to 'PATH' or an absolute path)")
	}

	// "PATH" means explicitly infer from system PATH (silent, no warning)
	if program == "PATH" {
		gpgPath, err := exec.LookPath("gpg")
		if err != nil {
			return errors.New("gpg.program set to PATH but gpg not found in system PATH")
		}
		setGPGProgramInternal(gpgPath)
		return nil
	}

	// Must be an absolute path
	if !filepath.IsAbs(program) {
		return fmt.Errorf("gpg.program must be 'PATH' or an absolute path, got: %s", program)
	}

	// Validate that the file exists and is executable
	if !isExecutableFile(program) {
		return fmt.Errorf("gpg.program is not an executable file: %s", program)
	}

	// Path is valid, set it
	setGPGProgramInternal(program)
	return nil
}

// setGPGProgramInternal sets the configured GPG program path.
// This is an internal function - use ValidateAndSetGPGProgram for external callers.
func setGPGProgramInternal(path string) {
	configuredPath = path
	// Reset cache when config changes
	resolvedOnce = sync.Once{}
	resolvedGPGPath = ""
}

// GetGPGProgram returns the path to the GPG executable.
// This returns the path set by ValidateAndSetGPGProgram().
// If validation was not performed, returns empty string.
func GetGPGProgram() string {
	resolvedOnce.Do(func() {
		resolvedGPGPath = configuredPath
	})
	return resolvedGPGPath
}

// DetectAllGPGPaths finds all GPG executables on the system.
// Returns a slice of paths, with PATH entries first, then common locations.
// Duplicates are removed.
func DetectAllGPGPaths() []string {
	seen := make(map[string]bool)
	var paths []string

	// First, check if gpg is in PATH
	if path, err := exec.LookPath("gpg"); err == nil {
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}

	// Try platform-specific common locations
	for _, path := range commonGPGPaths() {
		if isExecutable(path) && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}

	return paths
}

// isExecutable checks if a file exists and is executable.
func isExecutable(path string) bool {
	_, err := exec.LookPath(path)
	if err == nil {
		return true
	}

	// LookPath may fail for absolute paths, try direct stat
	return isExecutableFile(path)
}

package gpg

import (
	"errors"
	"fmt"
	"io"
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
// It returns an error if validation fails, and writes warnings to stderr.
//
// Validation rules:
//   - If path is specified: must be an absolute path to an existing, executable program
//   - If path is empty: infers "gpg" from PATH and prints a warning to stderr
//   - In strict mode: fails if path is not explicitly specified
func ValidateAndSetGPGProgram(path string, strict bool, stderr io.Writer) error {
	// In strict mode, gpg.program must be explicitly specified
	if strict && path == "" {
		return errors.New("strict mode: gpg.program must be explicitly configured in config file")
	}

	if path != "" {
		// Validate that the path is absolute
		if !filepath.IsAbs(path) {
			return fmt.Errorf("gpg.program must be an absolute path, got: %s", path)
		}

		// Validate that the file exists and is executable
		if !isExecutableFile(path) {
			return fmt.Errorf("gpg.program is not an executable file: %s", path)
		}

		// Path is valid, set it
		setGPGProgramInternal(path)
		return nil
	}

	// Path not specified, infer from PATH
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		return errors.New("gpg.program not configured and gpg not found in PATH")
	}

	// Warn about inferring from PATH
	if stderr != nil {
		_, _ = fmt.Fprintf(stderr, "warning: gpg.program not configured, using gpg from PATH: %s\n", gpgPath)
	}

	// Set the resolved path
	setGPGProgramInternal(gpgPath)
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

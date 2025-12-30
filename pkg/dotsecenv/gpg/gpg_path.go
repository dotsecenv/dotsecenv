package gpg

import (
	"os/exec"
	"sync"
)

var (
	// resolvedGPGPath caches the resolved GPG path
	resolvedGPGPath string
	resolvedOnce    sync.Once
	configuredPath  string
)

// SetGPGProgram sets the configured GPG program path from config.
// Call this at startup with the config value.
// If path is empty, GPG will be looked up in PATH.
func SetGPGProgram(path string) {
	configuredPath = path
	// Reset cache when config changes
	resolvedOnce = sync.Once{}
	resolvedGPGPath = ""
}

// GetGPGProgram returns the path to the GPG executable.
// Priority:
// 1. Configured path (from config gpg_program)
// 2. "gpg" in PATH
func GetGPGProgram() string {
	resolvedOnce.Do(func() {
		resolvedGPGPath = resolveGPGPath()
	})
	return resolvedGPGPath
}

// resolveGPGPath determines the GPG executable path.
func resolveGPGPath() string {
	// If explicitly configured, use that
	if configuredPath != "" {
		return configuredPath
	}

	// Otherwise, just return "gpg" and let exec.Command find it in PATH
	// On Windows, exec.Command will automatically try gpg.exe
	return "gpg"
}

// DetectGPGPath attempts to find GPG in common locations.
// Returns the path if found, empty string if not found.
// This is used by "init config" to suggest a path.
func DetectGPGPath() string {
	// First, check if gpg is already in PATH
	if path, err := exec.LookPath("gpg"); err == nil {
		return path
	}

	// Try platform-specific common locations
	for _, path := range commonGPGPaths() {
		if isExecutable(path) {
			return path
		}
	}

	return ""
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

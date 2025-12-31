//go:build unix

package gpg

import (
	"os"
)

// commonGPGPaths returns common GPG installation paths on Unix systems.
func commonGPGPaths() []string {
	return []string{
		"/usr/bin/gpg",
		"/usr/local/bin/gpg",
		"/opt/homebrew/bin/gpg", // macOS Homebrew on Apple Silicon
		"/opt/local/bin/gpg",    // MacPorts
		"/snap/bin/gpg",         // Ubuntu Snap
	}
}

// isExecutableFile checks if a file exists and is executable on Unix.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Check if it's a regular file and has executable bit
	return info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

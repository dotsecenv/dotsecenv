//go:build unix

package gpg

import (
	"os"
)

// isExecutableFile checks if a file exists and is executable on Unix.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Check if it's a regular file and has executable bit
	return info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

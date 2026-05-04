//go:build windows

package gpg

import (
	"os"
)

// isExecutableFile checks if a file exists and is executable on Windows.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// On Windows, just check if it's a regular file
	// The .exe extension is what makes it executable
	return info.Mode().IsRegular()
}

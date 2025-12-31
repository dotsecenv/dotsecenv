//go:build windows

package gpg

import (
	"os"
	"path/filepath"
)

// commonGPGPaths returns common GPG installation paths on Windows.
func commonGPGPaths() []string {
	paths := []string{
		// Gpg4win default installations
		`C:\Program Files (x86)\GnuPG\bin\gpg.exe`,
		`C:\Program Files\GnuPG\bin\gpg.exe`,
		// Git for Windows includes GPG
		`C:\Program Files\Git\usr\bin\gpg.exe`,
		`C:\Program Files (x86)\Git\usr\bin\gpg.exe`,
	}

	// Also check user-specific locations
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		paths = append(paths,
			filepath.Join(userProfile, "scoop", "apps", "gpg", "current", "bin", "gpg.exe"), // Scoop
			filepath.Join(userProfile, "AppData", "Local", "Programs", "GnuPG", "bin", "gpg.exe"),
		)
	}

	// Check LOCALAPPDATA for portable installs
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		paths = append(paths,
			filepath.Join(localAppData, "Programs", "GnuPG", "bin", "gpg.exe"),
		)
	}

	return paths
}

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

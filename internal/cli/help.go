package cli

import (
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// PrintVersion prints the version information
func PrintVersion(w io.Writer, version, commit, date string) {
	if version == "" {
		version = "unknown"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}
	_, _ = fmt.Fprintf(w, "version: %s\n", version)
	_, _ = fmt.Fprintf(w, "commit: %s\n", commit)
	_, _ = fmt.Fprintf(w, "build at: %s\n", date)
	_, _ = fmt.Fprintf(w, "go version: %s\n", runtime.Version())
	_, _ = fmt.Fprintf(w, "crypto: %s\n", cryptoStatus())
}

// cryptoStatus returns a string describing the crypto module status.
func cryptoStatus() string {
	fipsSetting := fipsBuildSetting()
	if fipsSetting == "" {
		return "Go standard library (not FIPS validated)"
	}
	status := "FIPS 140-3 mode disabled"
	if fips140.Enabled() {
		status = "FIPS 140-3 mode enabled"
	}
	return fmt.Sprintf("GOFIPS140=%s (%s)", fipsSetting, status)
}

// fipsBuildSetting returns the GOFIPS140 setting used at build time, if any.
func fipsBuildSetting() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOFIPS140" {
			return setting.Value
		}
	}
	return ""
}

// VersionInfo represents version information as a structured object.
type VersionInfo struct {
	Version        string     `json:"version"`
	Commit         string     `json:"commit"`
	BuiltAt        string     `json:"builtAt"`
	GoBuildVersion string     `json:"goBuildVersion"`
	Crypto         CryptoInfo `json:"crypto"`
}

// CryptoInfo represents cryptographic module information.
type CryptoInfo struct {
	GOFIPS140      string `json:"GOFIPS140,omitempty"`
	FIPS140Enabled bool   `json:"fips140Enabled"`
}

// PrintVersionJSON prints version information as JSON.
func PrintVersionJSON(w io.Writer, version, commit, date string) {
	if version == "" {
		version = "unknown"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}

	info := VersionInfo{
		Version:        version,
		Commit:         commit,
		BuiltAt:        date,
		GoBuildVersion: runtime.Version(),
		Crypto: CryptoInfo{
			GOFIPS140:      fipsBuildSetting(),
			FIPS140Enabled: fips140.Enabled(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

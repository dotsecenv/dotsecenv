package cli

import (
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// PrintHelp prints the help message
func PrintHelp(w io.Writer) {
	help := `dotsecenv: safe environment secrets

USAGE:
  dotsecenv [-v VAULT_PATH] [-c CONFIG_PATH] COMMAND [ARGS]

OPTIONS:
  -v PATH    Path to vault file (global, for all commands)
  -c PATH    Path to config file (global, for all commands)

COMMANDS:
  login FINGERPRINT             Initialize user identity
  init config [-c PATH]         Initialize configuration file
  init vault [-c PATH]          Initialize vault (interactive from config)
  init vault -v PATH            Initialize specific vault file
  secret put SECRET             Store encrypted secret
  secret get SECRET [--all] [--json] Retrieve secret value(s)
  secret share SECRET FINGERPRINT [--all] Share secret with another identity
  secret revoke SECRET FINGERPRINT [--all] Revoke access from identity
  vault identity add FINGERPRINT Add identity to vault
  vault identity list [--json]   List identities in configured vaults
  vault list [--json]           List configured vaults and their secrets
  validate                      Validate vault and config
  version                       Show version information

ENVIRONMENT:
  DOTSECENV_FINGERPRINT         Override fingerprint from config
  XDG_CONFIG_HOME              Override config directory
  XDG_DATA_HOME                Override data directory
`
	_, _ = fmt.Fprint(w, help)
}

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
	_, _ = fmt.Fprintf(w, "built at: %s\n", date)
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
	return fmt.Sprintf("%s GOFIPS140=%s (%s)", runtime.Version(), fipsSetting, status)
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
	GOFIPS140 string `json:"GOFIPS140,omitempty"`
	Enabled   bool   `json:"enabled"`
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
			GOFIPS140: fipsBuildSetting(),
			Enabled:   fips140.Enabled(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

package cli

import (
	"fmt"
	"io"
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
	_, _ = fmt.Fprintf(w, "dotsecenv version %s\n", version)
	_, _ = fmt.Fprintf(w, "commit: %s\n", commit)
	_, _ = fmt.Fprintf(w, "built at: %s\n", date)
}

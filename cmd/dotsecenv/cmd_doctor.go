package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

// doctor flags (top-level alias for `vault doctor`)
var doctorJSON bool
var doctorFix bool

// doctorCmd is a top-level alias for `dotsecenv vault doctor`, following the
// `brew doctor` / `flutter doctor` convention.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run health checks on vaults and environment (alias for 'vault doctor')",
	Long: `Run health checks on vaults and the GPG environment.

This is a top-level alias for 'dotsecenv vault doctor'.

Checks performed:
  - GPG agent availability
  - Vault format version (upgrades outdated vaults)
  - Vault fragmentation (defragments if needed)

In CI environments (CI=true, GITHUB_ACTIONS, GITLAB_CI, etc.),
interactive prompts are automatically skipped to avoid blocking
pipelines.

Use -v to target a specific vault for checks.

Options:
  --json  Output as JSON
  --fix   Auto-fix issues without prompting`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		vaultPath, fromIndex, parseErr := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if parseErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, clilib.NewError(parseErr.Error(), clilib.ExitGeneralError))))
		}

		exitErr := cli.VaultDoctor(doctorJSON, doctorFix, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Output as JSON")
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Auto-fix issues without prompting")
}

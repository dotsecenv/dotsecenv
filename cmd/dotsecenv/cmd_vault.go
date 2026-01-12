package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults",
	Long:  `Commands for managing vaults: describe, doctor.`,
}

// vault describe flags
var vaultDescribeJSON bool

var vaultDescribeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Describe configured vaults with identities and secrets",
	Long: `Describe all configured vaults showing their identities and secrets.

Options:
  --json  Output as JSON`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.VaultDescribe(vaultDescribeJSON)
		exitWithError(exitErr)
	},
}

// vault doctor flags
var vaultDoctorJSON bool

var vaultDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run health checks on vaults and environment",
	Long: `Run health checks on vaults and the GPG environment.

Checks performed:
  - GPG agent availability
  - Vault format version (upgrades outdated vaults)
  - Vault fragmentation (defragments if needed)

In CI environments (CI=true, GITHUB_ACTIONS, GITLAB_CI, etc.),
interactive prompts are automatically skipped to avoid blocking
pipelines.

Use -v to target a specific vault for checks.

Options:
  --json  Output as JSON`,
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

		exitErr := cli.VaultDoctor(vaultDoctorJSON, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

func init() {
	// vault describe flags
	vaultDescribeCmd.Flags().BoolVar(&vaultDescribeJSON, "json", false, "Output as JSON")

	// vault doctor flags
	vaultDoctorCmd.Flags().BoolVar(&vaultDoctorJSON, "json", false, "Output as JSON")

	// Build command tree
	vaultCmd.AddCommand(vaultDescribeCmd)
	vaultCmd.AddCommand(vaultDoctorCmd)
}

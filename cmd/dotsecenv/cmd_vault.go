package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults",
	Long:  `Commands for managing vaults: list, identity.`,
}

// vault list flags
var vaultListJSON bool

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured vaults and their secrets",
	Long: `List all configured vaults and the secrets they contain.

Options:
  --json  Output as JSON`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.VaultList(vaultListJSON)
		exitWithError(exitErr)
	},
}

// vault identity command
var vaultIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage vault identities",
	Long:  `Commands for managing vault identities: add, list.`,
}

// vault identity add flags
var vaultIdentityAddAll bool

var vaultIdentityAddCmd = &cobra.Command{
	Use:   "add FINGERPRINT",
	Short: "Add an identity to vault(s)",
	Long: `Add an identity to one or more vaults.

Options:
  --all  Add identity to all configured vaults
  -v     Target vault (path or 1-based index)`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fingerprint := args[0]

		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		vaultPath, fromIndex, parseErr := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if parseErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, clilib.NewError(parseErr.Error(), clilib.ExitGeneralError))))
		}

		exitErr := cli.IdentityAdd(fingerprint, vaultIdentityAddAll, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

// vault identity list flags
var vaultIdentityListJSON bool

// vault defrag flags
var vaultDefragDryRun bool
var vaultDefragJSON bool
var vaultDefragYes bool

var vaultDefragCmd = &cobra.Command{
	Use:   "defrag",
	Short: "Defragment vault files",
	Long: `Analyze vault fragmentation and optionally defragment.

Prompts to select a vault if multiple are configured.
Use --dry-run to only show stats without making changes.

Options:
  --dry-run  Show fragmentation stats without defragmenting
  --json     Output as JSON
  --yes      Skip confirmation prompt`,
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

		exitErr := cli.VaultDefrag(vaultDefragDryRun, vaultDefragJSON, vaultDefragYes, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

var vaultIdentityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List identities in configured vaults",
	Long: `List all identities in the configured vaults.

Options:
  --json  Output as JSON`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.IdentityList(vaultIdentityListJSON)
		exitWithError(exitErr)
	},
}

func init() {
	// vault list flags
	vaultListCmd.Flags().BoolVar(&vaultListJSON, "json", false, "Output as JSON")

	// vault identity add flags
	vaultIdentityAddCmd.Flags().BoolVar(&vaultIdentityAddAll, "all", false, "Add identity to all configured vaults")

	// vault identity list flags
	vaultIdentityListCmd.Flags().BoolVar(&vaultIdentityListJSON, "json", false, "Output as JSON")

	// vault defrag flags
	vaultDefragCmd.Flags().BoolVar(&vaultDefragDryRun, "dry-run", false, "Show fragmentation stats without defragmenting")
	vaultDefragCmd.Flags().BoolVar(&vaultDefragJSON, "json", false, "Output as JSON")
	vaultDefragCmd.Flags().BoolVarP(&vaultDefragYes, "yes", "y", false, "Skip confirmation prompt")

	// Build command tree
	vaultIdentityCmd.AddCommand(vaultIdentityAddCmd)
	vaultIdentityCmd.AddCommand(vaultIdentityListCmd)

	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultIdentityCmd)
	vaultCmd.AddCommand(vaultDefragCmd)
}

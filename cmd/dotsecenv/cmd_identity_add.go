package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var identityAddAll bool

var identityAddCmd = &cobra.Command{
	Use:   "add FINGERPRINT",
	Short: "Add an identity to vault(s)",
	Long: `Add a GPG identity to one or more vaults by fingerprint.

The identity's public key is fetched from GPG, validated against the
configured approved_algorithms, signed, and appended to the vault.

If the identity already exists in a vault, it is skipped.

Options:
  --all  Add identity to all configured vaults
  -v     Target vault (path or 1-based index)

When neither --all nor -v is specified and only one vault is configured,
that vault is selected automatically.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		checkSUIDMode(cmd)

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

		exitErr := cli.IdentityAdd(fingerprint, identityAddAll, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

func init() {
	identityAddCmd.Flags().BoolVar(&identityAddAll, "all", false, "Add identity to all configured vaults")

	identityCmd.AddCommand(identityAddCmd)
}

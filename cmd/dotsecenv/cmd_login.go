package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login [FINGERPRINT]",
	Short: "Initialize user identity",
	Long: `Initialize user identity with a GPG fingerprint.

If no fingerprint is provided, you will be prompted to select from
available secret keys in your GPG keyring.

The fingerprint should be the full 40-character GPG key fingerprint
of the user who will be accessing secrets.

This command creates a cryptographically signed login proof that is
stored in your configuration file, ensuring only users with access
to the secret key can configure dotsecenv to use it.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Warn if -v or -c are specified (they have no effect on login)
		if len(globalOpts.VaultPaths) > 0 || globalOpts.ConfigPath != "" {
			_, _ = fmt.Fprintf(os.Stderr, "warning: -v and -c flags have no effect on 'login' command\n")
			globalOpts.VaultPaths = nil
			globalOpts.ConfigPath = ""
		}

		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		// If no fingerprint provided, pass empty string to trigger interactive selection
		fingerprint := ""
		if len(args) > 0 {
			fingerprint = args[0]
		}

		exitErr := cli.Login(fingerprint)
		exitWithError(exitErr)
	},
}

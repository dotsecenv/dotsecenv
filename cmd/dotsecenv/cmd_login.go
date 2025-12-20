package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login FINGERPRINT",
	Short: "Initialize user identity",
	Long: `Initialize user identity with the given GPG fingerprint.

The fingerprint should be the full 40-character GPG key fingerprint
of the user who will be accessing secrets.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// If no fingerprint provided, show help
		if len(args) == 0 {
			_ = cmd.Help()
			return
		}

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

		exitErr := cli.Login(args[0])
		exitWithError(exitErr)
	},
}

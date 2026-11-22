package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var validateFix bool

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate vault and config",
	Long: `Validate the vault and configuration files.

Validation only reports problems. To repair a vault, run 'dotsecenv doctor --fix'.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if validateFix {
			exitWithError(clilib.NewError("validate only reports problems; to repair a vault, run 'dotsecenv doctor --fix'", clilib.ExitGeneralError))
		}

		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.Validate()
		exitWithError(exitErr)
	},
}

func init() {
	// Kept hidden so old scripts get a pointer to doctor instead of "unknown flag".
	validateCmd.Flags().BoolVar(&validateFix, "fix", false, "Removed; use 'dotsecenv doctor --fix'")
	_ = validateCmd.Flags().MarkHidden("fix")
}

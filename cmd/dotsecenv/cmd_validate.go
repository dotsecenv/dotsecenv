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

Options:
  --fix  Attempt to fix any issues found`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := createCLI()
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.Validate(validateFix)
		exitWithError(exitErr)
	},
}

func init() {
	validateCmd.Flags().BoolVar(&validateFix, "fix", false, "Attempt to fix issues")
}

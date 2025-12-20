package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display the version, commit hash, and build date of dotsecenv.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		clilib.PrintVersion(os.Stdout, version, commit, date)
	},
}

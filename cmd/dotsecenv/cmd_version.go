package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var versionJSON bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display the version, commit hash, and build date of dotsecenv.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if versionJSON {
			clilib.PrintVersionJSON(os.Stdout, version, commit, date)
		} else {
			clilib.PrintVersion(os.Stdout, version, commit, date)
		}
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionJSON, "json", false, "Output version information as JSON")
}

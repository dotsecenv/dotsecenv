package main

import (
	"github.com/spf13/cobra"
)

var (
	version = "unknown"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "dotsecenv",
	Short: "Safe environment secrets",
	Long: `dotsecenv: safe environment secrets — encrypted at rest, ready to commit, easy to share.

A secure tool for managing environment secrets using GPG encryption.
Secrets are stored in vault files and can be shared between team members.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		checkSUIDMode(cmd)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// If no subcommand, show help
		_ = cmd.Help()
	},
}

func init() {
	// Persistent flags available to all commands
	rootCmd.PersistentFlags().StringVarP(&globalOpts.ConfigPath, "config", "c", "", "Path to config file")
	rootCmd.PersistentFlags().StringArrayVarP(&globalOpts.VaultPaths, "vault", "v", nil, "Path to vault file or vault index (1-based)")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Silent, "silent", "s", false, "Silent mode (suppress warnings)")

	// Add subcommands
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(secretCmd)
	rootCmd.AddCommand(vaultCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(completionCmd)
}

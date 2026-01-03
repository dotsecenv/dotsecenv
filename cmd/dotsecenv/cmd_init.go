package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

// pathValue is a custom pflag.Value that rejects flag-like values
type pathValue struct {
	value *string
}

func (p *pathValue) String() string {
	if p.value == nil {
		return ""
	}
	return *p.value
}

func (p *pathValue) Set(s string) error {
	if len(s) > 0 && s[0] == '-' {
		return fmt.Errorf("--gpg-program requires a path argument")
	}
	*p.value = s
	return nil
}

func (p *pathValue) Type() string {
	return "string"
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration or vault files",
	Long:  `Initialize dotsecenv configuration file or vault files.`,
}

// initConfigOpts holds flags specific to init config command
var initConfigOpts struct {
	GPGProgram       string
	NoGPGProgram     bool
	Strict           bool
	LoginFingerprint string
}

var initConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Initialize configuration file",
	Long: `Initialize a new dotsecenv configuration file.

By default, creates a configuration file at the XDG config location.
Use -c to specify a custom path.`,
	Args: cobra.NoArgs,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate mutually exclusive flags
		if initConfigOpts.NoGPGProgram && initConfigOpts.GPGProgram != "" {
			return fmt.Errorf("--no-gpg-program and --gpg-program cannot be used together")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		targetConfig := clilib.ResolveConfigPath(globalOpts.ConfigPath, globalOpts.Silent, os.Stderr)
		err := clilib.InitConfig(targetConfig, globalOpts.VaultPaths, initConfigOpts.GPGProgram, initConfigOpts.NoGPGProgram, initConfigOpts.Strict, initConfigOpts.LoginFingerprint, os.Stdout, os.Stderr)
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		os.Exit(int(clilib.ExitSuccess))
	},
}

var initVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Initialize vault file(s)",
	Long: `Initialize vault file(s).

Two modes of operation:
  1. With -v PATH: Initialize a specific vault file at the given path
  2. Without -v: Interactive mode using vaults from configuration

Note: Both -v and -c cannot be specified at the same time.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		hasVaults := len(globalOpts.VaultPaths) > 0
		hasConfig := globalOpts.ConfigPath != ""

		if hasVaults && hasConfig {
			fmt.Fprintf(os.Stderr, "error: Both -v and -c cannot be specified at the same time for 'init vault'\n")
			os.Exit(int(clilib.ExitGeneralError))
		}

		if hasVaults {
			// Init specific vaults
			for _, vPath := range globalOpts.VaultPaths {
				if err := clilib.InitVaultFile(vPath, os.Stdout, os.Stderr); err != nil {
					os.Exit(int(clilib.PrintError(os.Stderr, err)))
				}
			}
			os.Exit(int(clilib.ExitSuccess))
		}

		// Interactive mode
		effectiveConfig := clilib.ResolveConfigPath(globalOpts.ConfigPath, globalOpts.Silent, os.Stderr)
		exitErr := clilib.InitVaultInteractiveStandalone(effectiveConfig, os.Stdout, os.Stderr)
		if exitErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, exitErr)))
		}
		os.Exit(int(clilib.ExitSuccess))
	},
}

func init() {
	// Flags for init config
	// Use custom pathValue to reject flag-like values during parsing (before Cobra's subcommand resolution)
	initConfigCmd.Flags().Var(&pathValue{value: &initConfigOpts.GPGProgram}, "gpg-program", "Set gpg.program to this path (without validation)")
	initConfigCmd.Flags().BoolVar(&initConfigOpts.NoGPGProgram, "no-gpg-program", false, "Skip GPG detection (leave gpg.program empty)")
	initConfigCmd.Flags().BoolVar(&initConfigOpts.Strict, "strict", false, "Initialize config with strict mode enabled")
	initConfigCmd.Flags().StringVar(&initConfigOpts.LoginFingerprint, "login", "", "Initialize config with specified fingerprint")

	initCmd.AddCommand(initConfigCmd)
	initCmd.AddCommand(initVaultCmd)
}

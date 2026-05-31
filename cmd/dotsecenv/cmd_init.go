package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
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

// defaultOutput creates a default output handler with silent mode from global options
func defaultOutput() *output.Handler {
	return output.NewHandler(os.Stdout, os.Stderr,
		output.WithSilent(globalOpts.Silent),
		output.WithStdin(os.Stdin),
	)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration or vault files",
	Long:  `Initialize dotsecenv configuration file or vault files.`,
}

// initConfigOpts holds flags specific to init config command
var initConfigOpts struct {
	GPGProgram       string
	LoginFingerprint string
}

var initConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Initialize configuration file",
	Long: `Initialize a new dotsecenv configuration file.

By default, creates a configuration file at the XDG config location.
Use -c to specify a custom path.

The config defaults to gpg.program: PATH, which resolves the gpg binary
from the system PATH at runtime. Use --gpg-program to pin an absolute path.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		out := defaultOutput()
		targetConfig := clilib.ResolveConfigPath(globalOpts.ConfigPath, globalOpts.Silent, out.Stderr())
		err := clilib.InitConfig(targetConfig, globalOpts.VaultPaths, initConfigOpts.GPGProgram, initConfigOpts.LoginFingerprint, out)
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
  1. With -v PATH or -v INDEX: Initialize a specific vault file (path or 1-based config index)
  2. Without -v: Interactive mode using vaults from configuration`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		out := defaultOutput()
		hasVaults := len(globalOpts.VaultPaths) > 0

		if hasVaults {
			// Resolve numeric vault indices to actual paths from config
			resolvedPaths, resolveErr := resolveVaultPaths(globalOpts.ConfigPath, globalOpts.VaultPaths)
			if resolveErr != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", resolveErr)
				os.Exit(int(clilib.ExitGeneralError))
			}

			// Validate resolved vault paths against config (respects restrict_to_configured_vaults)
			if err := clilib.ValidateVaultPathsAgainstConfig(globalOpts.ConfigPath, resolvedPaths, out); err != nil {
				os.Exit(int(clilib.PrintError(os.Stderr, err)))
			}

			// Init specific vaults
			for _, vPath := range resolvedPaths {
				if err := clilib.InitVaultFile(vPath, out); err != nil {
					os.Exit(int(clilib.PrintError(os.Stderr, err)))
				}
			}
			os.Exit(int(clilib.ExitSuccess))
		}

		// Interactive mode
		effectiveConfig := clilib.ResolveConfigPath(globalOpts.ConfigPath, globalOpts.Silent, out.Stderr())
		exitErr := clilib.InitVaultInteractiveStandalone(effectiveConfig, out)
		if exitErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, exitErr)))
		}
		os.Exit(int(clilib.ExitSuccess))
	},
}

// initSecenvAll forces non-interactive batch mode without suppressing warnings.
var initSecenvAll bool

var initSecenvCmd = &cobra.Command{
	Use:   "secenv",
	Short: "Add vault secret references to .secenv",
	Long: `Add vault secret references to the .secenv file in the current directory.

In a terminal this opens an interactive picker: one tab per vault, arrow keys
to move, space to select, and a final Apply tab to confirm. Without a terminal,
or with --all or --silent, it adds every reference not already present.

References point at vault secrets (KEY={dotsecenv/...}); it never writes
plaintext values. Keys already defined in .secenv stay untouched.

Modes:
  -v PATH or -v INDEX   restrict to specific vaults (path or 1-based index)
  --all                 add all references without prompting (warnings shown)
  --silent              add all references and suppress duplicate warnings`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cwd, wdErr := os.Getwd()
		if wdErr != nil {
			exitWithError(clilib.NewError(fmt.Sprintf("failed to determine working directory: %v", wdErr), clilib.ExitGeneralError))
		}

		forceBatch := globalOpts.Silent || initSecenvAll || !clilib.HasTTY()

		cli, cliErr := createCLI()
		if cliErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, cliErr)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.InitSecenv(cwd, forceBatch)
		exitWithError(exitErr)
	},
}

func init() {
	// Flags for init config
	// Use custom pathValue to reject flag-like values during parsing (before Cobra's subcommand resolution)
	initConfigCmd.Flags().Var(&pathValue{value: &initConfigOpts.GPGProgram}, "gpg-program", "Set gpg.program to this absolute path (default: PATH, resolved at runtime)")
	initConfigCmd.Flags().StringVar(&initConfigOpts.LoginFingerprint, "login", "", "Initialize config with specified fingerprint")

	initSecenvCmd.Flags().BoolVar(&initSecenvAll, "all", false, "Add all not-present references without prompting")

	initCmd.AddCommand(initConfigCmd)
	initCmd.AddCommand(initVaultCmd)
	initCmd.AddCommand(initSecenvCmd)
}

package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  `Commands for managing secrets: put, get, share, revoke.`,
}

// secret put
var secretPutCmd = &cobra.Command{
	Use:   "put SECRET",
	Short: "Store an encrypted secret",
	Long: `Store an encrypted secret value.

The secret value is read from stdin. Use -v to specify which vault
to store the secret in (either a path or 1-based index).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		secretKey := args[0]

		vaultPath, fromIndex, err := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(int(clilib.ExitGeneralError))
		}

		// Clear VaultPaths for createCLI if we're using an index
		if fromIndex > 0 {
			globalOpts.VaultPaths = []string{}
		}

		cli, cliErr := createCLI()
		if cliErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, cliErr)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.SecretPut(secretKey, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

// secret get flags
var (
	secretGetAll  bool
	secretGetLast bool
	secretGetJSON bool
)

var secretGetCmd = &cobra.Command{
	Use:   "get SECRET",
	Short: "Retrieve a secret value",
	Long: `Retrieve a secret value from the vault.

Options:
  --all   Retrieve all values for the secret across all vaults
  --last  Retrieve the most recent value across all vaults
  --json  Output as JSON`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		secretKey := args[0]

		vaultPath, fromIndex, err := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(int(clilib.ExitGeneralError))
		}

		// Clear VaultPaths so createCLI loads from config
		globalOpts.VaultPaths = []string{}

		cli, cliErr := createCLI()
		if cliErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, cliErr)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.SecretGet(secretKey, secretGetAll, secretGetLast, secretGetJSON, vaultPath, fromIndex)
		exitWithError(exitErr)
	},
}

// secret share flags
var secretShareAll bool

var secretShareCmd = &cobra.Command{
	Use:   "share SECRET FINGERPRINT",
	Short: "Share a secret with another identity",
	Long: `Share a secret with another identity by their GPG fingerprint.

The secret will be re-encrypted so the target identity can decrypt it.

Options:
  --all  Share the secret in all vaults where it exists`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		secretKey := args[0]
		targetFingerprint := args[1]

		vaultPath, targetIndex, err := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(int(clilib.ExitGeneralError))
		}

		// Handle vault path vs index
		if vaultPath != "" {
			targetIndex = 0 // Path-based lookup uses index 0
		} else if targetIndex > 0 {
			targetIndex-- // Convert to 0-based
		} else {
			targetIndex = -1 // No specific vault
		}

		// Clear VaultPaths so createCLI loads from config
		globalOpts.VaultPaths = []string{}

		cli, cliErr := createCLI()
		if cliErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, cliErr)))
		}
		defer func() { _ = cli.Close() }()

		if secretShareAll {
			// Check for conflicting flags
			if targetIndex >= 0 || vaultPath != "" {
				fmt.Fprintf(os.Stderr, "warning: --all flag overrides -v; processing all vaults\n")
			}
			exitErr := cli.SecretShareAll(secretKey, targetFingerprint)
			exitWithError(exitErr)
		} else {
			exitErr := cli.SecretShare(secretKey, targetFingerprint, targetIndex)
			exitWithError(exitErr)
		}
	},
}

// secret revoke flags
var secretRevokeAll bool

var secretRevokeCmd = &cobra.Command{
	Use:   "revoke SECRET FINGERPRINT",
	Short: "Revoke access to a secret from an identity",
	Long: `Revoke access to a secret from an identity.

This removes the ability for the specified identity to decrypt the secret.

Options:
  --all  Revoke access from all vaults where the secret is shared`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		secretKey := args[0]
		targetFingerprint := args[1]

		vaultPath, targetIndex, err := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(int(clilib.ExitGeneralError))
		}

		// Handle vault path vs index
		if vaultPath != "" {
			targetIndex = 0 // Path-based lookup uses index 0
		} else if targetIndex > 0 {
			targetIndex-- // Convert to 0-based
		} else {
			targetIndex = -1 // No specific vault
		}

		// Clear VaultPaths so createCLI loads from config
		globalOpts.VaultPaths = []string{}

		cli, cliErr := createCLI()
		if cliErr != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, cliErr)))
		}
		defer func() { _ = cli.Close() }()

		if secretRevokeAll {
			// Check for conflicting flags
			if targetIndex >= 0 || vaultPath != "" {
				fmt.Fprintf(os.Stderr, "warning: --all flag overrides -v; processing all vaults\n")
			}
			exitErr := cli.SecretRevokeAll(secretKey, targetFingerprint)
			exitWithError(exitErr)
		} else {
			exitErr := cli.SecretRevoke(secretKey, targetFingerprint, targetIndex)
			exitWithError(exitErr)
		}
	},
}

func init() {
	// secret get flags
	secretGetCmd.Flags().BoolVar(&secretGetAll, "all", false, "Retrieve all values")
	secretGetCmd.Flags().BoolVar(&secretGetLast, "last", false, "Retrieve most recent value across all vaults")
	secretGetCmd.Flags().BoolVar(&secretGetJSON, "json", false, "Output as JSON")

	// secret share flags
	secretShareCmd.Flags().BoolVar(&secretShareAll, "all", false, "Share secret in all vaults where it exists")

	// secret revoke flags
	secretRevokeCmd.Flags().BoolVar(&secretRevokeAll, "all", false, "Revoke from all vaults")

	secretCmd.AddCommand(secretPutCmd)
	secretCmd.AddCommand(secretGetCmd)
	secretCmd.AddCommand(secretShareCmd)
	secretCmd.AddCommand(secretRevokeCmd)
}

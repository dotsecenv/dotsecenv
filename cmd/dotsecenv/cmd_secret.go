package main

import (
	"bufio"
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  `Commands for managing secrets: store, get, share, revoke, forget.`,
}

// secret store (alias: put)
var secretPutCmd = &cobra.Command{
	Use:     "store SECRET",
	Aliases: []string{"put"},
	Short:   "Store an encrypted secret",
	Long: `Store an encrypted secret value.

Secret key formats:
  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)
  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)

Keys are case-insensitive and normalized when stored:
  - Namespace part: lowercase
  - Key name part: UPPERCASE

The secret value is read from stdin. Use -v to specify which vault
to store the secret in (either a path or 1-based index).`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		// Validate secret key format
		if _, err := vault.NormalizeSecretKey(args[0]); err != nil {
			return fmt.Errorf("%s", vault.FormatSecretKeyError(err))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		secretKey := args[0]

		vaultPath, fromIndex, err := parseVaultSpec(globalOpts.ConfigPath, globalOpts.VaultPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(int(clilib.ExitGeneralError))
		}

		// Read stdin BEFORE creating CLI (which acquires vault locks) to prevent
		// deadlock when piping: `dotsecenv secret get KEY | dotsecenv secret store KEY`
		// If stdin is piped (not TTY), read it now before vault lock acquisition.
		var preReadValue string
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				preReadValue = scanner.Text()
			} else if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to read secret from stdin: %v\n", err)
				os.Exit(int(clilib.ExitGeneralError))
			} else {
				fmt.Fprintf(os.Stderr, "error: no input provided on stdin\n")
				os.Exit(int(clilib.ExitGeneralError))
			}
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

		exitErr := cli.SecretPut(secretKey, vaultPath, fromIndex, preReadValue)
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
	Use:   "get [SECRET]",
	Short: "Retrieve a secret value or list all secrets",
	Long: `Retrieve a secret value from the vault, or list all secret keys if no secret is specified.

Secret key formats:
  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)
  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)

When called without arguments:
  Lists all secret keys from all configured vaults.
  Use -v to list secrets from a specific vault only.

When called with a SECRET argument:
  Retrieves the secret value from the vault.

Options:
  --all   Retrieve all values for the secret across all vaults
  --last  Retrieve the most recent value across all vaults
  --json  Output as JSON`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			// List mode - no arguments needed
			return nil
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
		}
		// Validate secret key format
		if _, err := vault.NormalizeSecretKey(args[0]); err != nil {
			return fmt.Errorf("%s", vault.FormatSecretKeyError(err))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
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

		// If no arguments provided, list secrets
		if len(args) == 0 {
			// --all and --last are not valid for list mode
			if secretGetAll {
				fmt.Fprintf(os.Stderr, "error: --all flag requires a secret key argument\n")
				os.Exit(int(clilib.ExitGeneralError))
			}
			if secretGetLast {
				fmt.Fprintf(os.Stderr, "error: --last flag requires a secret key argument\n")
				os.Exit(int(clilib.ExitGeneralError))
			}

			exitErr := cli.SecretList(secretGetJSON, vaultPath, fromIndex)
			exitWithError(exitErr)
			return
		}

		// Get secret value
		secretKey := args[0]
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

Secret key formats:
  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)
  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)

The secret will be re-encrypted so the target identity can decrypt it.

Options:
  --all  Share the secret in all vaults where it exists`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(2)(cmd, args); err != nil {
			return err
		}
		// Validate secret key format
		if _, err := vault.NormalizeSecretKey(args[0]); err != nil {
			return fmt.Errorf("%s", vault.FormatSecretKeyError(err))
		}
		return nil
	},
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

Secret key formats:
  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)
  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)

This removes the ability for the specified identity to decrypt the secret.

Options:
  --all  Revoke access from all vaults where the secret is shared`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(2)(cmd, args); err != nil {
			return err
		}
		// Validate secret key format
		if _, err := vault.NormalizeSecretKey(args[0]); err != nil {
			return fmt.Errorf("%s", vault.FormatSecretKeyError(err))
		}
		return nil
	},
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

// secret forget
var secretForgetCmd = &cobra.Command{
	Use:   "forget SECRET",
	Short: "Mark a secret as deleted",
	Long: `Mark a secret as deleted in the vault.

Secret key formats:
  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)
  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)

This adds a deletion marker to the secret. The secret will no longer be
returned by 'secret get' and will be shown as deleted in 'vault describe'.

Use -v to specify which vault to delete the secret from (either a path
or 1-based index).`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		// Validate secret key format
		if _, err := vault.NormalizeSecretKey(args[0]); err != nil {
			return fmt.Errorf("%s", vault.FormatSecretKeyError(err))
		}
		return nil
	},
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

		exitErr := cli.SecretForget(secretKey, vaultPath, fromIndex)
		exitWithError(exitErr)
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
	secretCmd.AddCommand(secretForgetCmd)
}

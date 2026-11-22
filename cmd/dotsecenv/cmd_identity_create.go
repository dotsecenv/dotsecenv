package main

import (
	"errors"
	"io"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/spf13/cobra"
)

var identityCreateOpts struct {
	Algorithm    string
	Name         string
	Email        string
	TemplateOnly bool
	NoPassphrase bool
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage GPG identities",
	Long:  `Commands for managing GPG identities used with dotsecenv.`,
}

var identityCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Generate a new GPG key",
	Long: `Generate a new GPG key for use with dotsecenv.

This command simplifies GPG key creation by providing sensible defaults
while allowing customization for power users.

While dotsecenv's philosophy aligns with Unix/POSIX tool composition, we felt
that providing a simplified wrapper for GPG key generation is a net positive
for users unfamiliar with GPG.

Supported algorithms:
  - P384    (default) - NIST P-384: ECDSA signing, ECDH encryption
  - P521              - NIST P-521: ECDSA signing, ECDH encryption
  - ED25519           - EdDSA signing; X25519 encryption is not NIST-approved
  - RSA4096 (legacy)  - RSA 4096-bit key

The requested algorithm must be allowed by your configuration's approved_algorithms
setting. See https://dotsecenv.com/concepts/compliance/ for details.

P384 is the default because NIST approves both of its algorithms. ED25519
signatures are FIPS 186-5 approved, but its X25519 encryption subkey is not
approved for key agreement under FIPS 140-3. RSA is not in the default
approved_algorithms: OpenPGP encrypts to RSA keys with PKCS #1 v1.5 padding,
which Go deprecated in 1.26.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		opts := clilib.IdentityCreateOptions{
			Algorithm:    identityCreateOpts.Algorithm,
			Name:         identityCreateOpts.Name,
			Email:        identityCreateOpts.Email,
			TemplateOnly: identityCreateOpts.TemplateOnly,
			NoPassphrase: identityCreateOpts.NoPassphrase,
			NoPinentry:   globalOpts.NoPinentry,
		}

		// Only a missing config falls back to the defaults (plus system policy).
		// Any other startup error is the user's to fix, not a reason to drop
		// their approved_algorithms.
		configPath := clilib.ResolveConfigPath(globalOpts.ConfigPath, true, io.Discard)
		if _, statErr := os.Stat(configPath); errors.Is(statErr, os.ErrNotExist) {
			out := output.NewHandler(os.Stdout, os.Stderr,
				output.WithSilent(globalOpts.Silent),
				output.WithStdin(os.Stdin),
			)
			exitErr := clilib.IdentityCreateStandalone(opts, out)
			exitWithError(exitErr)
			return
		}

		// Key generation needs config, policy and GPG, never the vaults.
		cli, err := clilib.NewCLIConfigOnly(globalOpts.ConfigPath, globalOpts.Silent, globalOpts.NoPinentry, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			os.Exit(int(clilib.PrintError(os.Stderr, err)))
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.IdentityCreate(opts)
		exitWithError(exitErr)
	},
}

func init() {
	identityCreateCmd.Flags().StringVar(&identityCreateOpts.Algorithm, "algo", string(gpg.DefaultAlgorithm),
		"Key algorithm: P384, P521, ED25519, RSA4096 (legacy)")
	identityCreateCmd.Flags().StringVar(&identityCreateOpts.Name, "name", "",
		"Your full name (prompts if not provided)")
	identityCreateCmd.Flags().StringVar(&identityCreateOpts.Email, "email", "",
		"Your email address (prompts if not provided)")
	identityCreateCmd.Flags().BoolVar(&identityCreateOpts.TemplateOnly, "template", false,
		`Output GPG batch template instead of generating key.
This allows you to:
- Review and customize the template before generation
- Execute key generation directly with GPG for maximum security
- Generate the key on an air-gapped machine
- Reduce attack surface by avoiding secret material handling in dotsecenv`)
	identityCreateCmd.Flags().BoolVar(&identityCreateOpts.NoPassphrase, "no-passphrase", false,
		"Create key without passphrase protection (for CI/automation only)")

	identityCmd.AddCommand(identityCreateCmd)
}

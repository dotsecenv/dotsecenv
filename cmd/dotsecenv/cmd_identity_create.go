package main

import (
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
  - P384    (default) - NIST P-384 ECDSA curve
  - P521              - NIST P-521 ECDSA curve
  - ED25519           - EdDSA with Ed25519 curve
  - RSA4096           - RSA 4096-bit key

The requested algorithm must be allowed by your configuration's approved_algorithms
setting. See https://dotsecenv.com/concepts/compliance/ for details.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		opts := clilib.IdentityCreateOptions{
			Algorithm:    identityCreateOpts.Algorithm,
			Name:         identityCreateOpts.Name,
			Email:        identityCreateOpts.Email,
			TemplateOnly: identityCreateOpts.TemplateOnly,
			NoPassphrase: identityCreateOpts.NoPassphrase,
		}

		// Try to create CLI (may fail if no config exists)
		cli, err := createCLI()
		if err != nil {
			// If config doesn't exist, use standalone mode with default config
			out := output.NewHandler(os.Stdout, os.Stderr,
				output.WithSilent(globalOpts.Silent),
				output.WithStdin(os.Stdin),
			)
			exitErr := clilib.IdentityCreateStandalone(opts, out)
			exitWithError(exitErr)
			return
		}
		defer func() { _ = cli.Close() }()

		exitErr := cli.IdentityCreate(opts)
		exitWithError(exitErr)
	},
}

func init() {
	identityCreateCmd.Flags().StringVar(&identityCreateOpts.Algorithm, "algo", string(gpg.DefaultAlgorithm),
		"Key algorithm: ED25519, RSA4096, P384, P521")
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

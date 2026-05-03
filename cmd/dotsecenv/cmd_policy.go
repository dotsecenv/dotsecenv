package main

import (
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect and validate the system policy directory",
	Long: `Inspect and validate the trusted policy directory at /etc/dotsecenv/policy.d/.

System administrators drop YAML policy fragments into the directory to
constrain every user of the binary. These commands let admins (and users)
introspect what policy is in effect.`,
}

var policyListJSON bool

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "Print the effective policy with per-field origin attribution",
	Long: `Print the effective system policy assembled from /etc/dotsecenv/policy.d/.
Each field shows which fragment(s) contributed to the merged value.

Options:
  --json  Output as JSON`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		exitWithError(clilib.PolicyList(policyListJSON, globalOpts.Silent, os.Stdout, os.Stderr))
	},
}

var policyValidateJSON bool

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate policy fragment structure",
	Long: `Parse all fragments in /etc/dotsecenv/policy.d/ and report structural errors.

Exit codes:
  0  No policy enforced, or all fragments structurally valid
  2  Malformed YAML or forbidden key (use 'login:', 'vault:', 'behavior:', or 'gpg:')
  8  Insecure permissions or unreadable fragment
  1  Empty allow-list field (omit the field instead of setting an empty list)

Options:
  --json  Output as JSON (errors are embedded in the JSON object as well as
          surfaced via the exit code)`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		exitWithError(clilib.PolicyValidate(policyValidateJSON, globalOpts.Silent, os.Stdout, os.Stderr))
	},
}

func init() {
	policyListCmd.Flags().BoolVar(&policyListJSON, "json", false, "Output as JSON")
	policyValidateCmd.Flags().BoolVar(&policyValidateJSON, "json", false, "Output as JSON")

	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyValidateCmd)
}

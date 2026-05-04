package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/policy"
)

// PolicyList prints the effective system policy with per-field origin
// attribution. Operates standalone (does not require a loaded user config),
// so admins can introspect policy without being dotsecenv users themselves.
func PolicyList(jsonMode, silent bool, stdout, stderr io.Writer) *Error {
	out := output.NewHandler(stdout, stderr, output.WithSilent(silent))

	pol, _, err := policy.Load()
	if err != nil {
		return classifyPolicyError(err)
	}

	if jsonMode {
		return writePolicyListJSON(stdout, pol)
	}
	return writePolicyListText(out, pol)
}

// PolicyValidate parses all fragments and reports structural errors.
// In text mode (default), prints a short status line. In JSON mode, emits a
// structured object compatible with the convention from `vault doctor --json`
// (raw json.NewEncoder output to stdout, no envelope; errors surface via the
// returned *Error which the caller reports to stderr with the appropriate
// non-zero exit code).
//
// Returns nil on success (no policy enforced OR all fragments structurally
// valid). Otherwise returns *Error with a distinct ExitCode per category.
func PolicyValidate(jsonMode, silent bool, stdout, stderr io.Writer) *Error {
	out := output.NewHandler(stdout, stderr, output.WithSilent(silent))

	pol, _, err := policy.Load()
	if err != nil {
		if jsonMode {
			cliErr := classifyPolicyError(err)
			_ = writePolicyValidateJSON(stdout, policy.DefaultDir, false, 0, cliErr)
			return cliErr
		}
		return classifyPolicyError(err)
	}

	if jsonMode {
		dir := pol.Dir
		if dir == "" {
			dir = policy.DefaultDir
		}
		if writeErr := writePolicyValidateJSON(stdout, dir, true, len(pol.Fragments), nil); writeErr != nil {
			return NewError(fmt.Sprintf("failed to encode json: %v", writeErr), ExitGeneralError)
		}
		return nil
	}

	if pol.Empty() {
		out.Successf("no policy in effect (%s does not exist)", policy.DefaultDir)
		return nil
	}
	out.Successf("policy valid (%d fragment(s) in %s)", len(pol.Fragments), pol.Dir)
	return nil
}

// classifyPolicyError maps a policy.Load error to a CLI Error with a distinct
// exit code per category, matching the convention of other dotsecenv commands.
func classifyPolicyError(err error) *Error {
	switch {
	case errors.Is(err, policy.ErrInsecurePermissions),
		errors.Is(err, policy.ErrUnreadableFragment):
		return NewError(err.Error(), ExitAccessDenied)
	case errors.Is(err, policy.ErrEmptyAllowList):
		return NewError(err.Error(), ExitGeneralError)
	case errors.Is(err, policy.ErrForbiddenKey),
		errors.Is(err, policy.ErrMalformedFragment):
		return NewError(err.Error(), ExitConfigError)
	default:
		return NewError(err.Error(), ExitConfigError)
	}
}

// writePolicyListText prints the effective policy in human-readable form.
func writePolicyListText(out *output.Handler, p policy.Policy) *Error {
	if p.Empty() {
		out.Successf("no policy in effect (%s does not exist)", policy.DefaultDir)
		return nil
	}

	out.WriteLine(fmt.Sprintf("Policy directory: %s (%d fragment(s))", p.Dir, len(p.Fragments)))

	algos, algoOrigins := p.MergedApprovedAlgorithms()
	if len(algos) > 0 {
		out.WriteLine("  approved_algorithms:")
		for i, a := range algos {
			out.WriteLine(fmt.Sprintf("    - %s  %s",
				formatAlgo(a),
				formatOrigins(algoOrigins[i]),
			))
		}
	}

	vaultPatterns, vaultOrigins := p.MergedApprovedVaultPaths()
	if len(vaultPatterns) > 0 {
		out.WriteLine("  approved_vault_paths:")
		for _, pat := range vaultPatterns {
			out.WriteLine(fmt.Sprintf("    - %s  %s",
				pat,
				formatOrigins(vaultOrigins[pat]),
			))
		}
	}

	behavior, behaviorOrigins, _ := p.MergedBehavior()
	if hasBehaviorSet(behavior) {
		out.WriteLine("  behavior:")
		if behavior.RequireExplicitVaultUpgrade != nil {
			out.WriteLine(fmt.Sprintf("    require_explicit_vault_upgrade: %v  [%s]",
				*behavior.RequireExplicitVaultUpgrade,
				filepath.Base(behaviorOrigins["behavior.require_explicit_vault_upgrade"]),
			))
		}
		if behavior.RestrictToConfiguredVaults != nil {
			out.WriteLine(fmt.Sprintf("    restrict_to_configured_vaults: %v  [%s]",
				*behavior.RestrictToConfiguredVaults,
				filepath.Base(behaviorOrigins["behavior.restrict_to_configured_vaults"]),
			))
		}
	}

	gpgProgram, gpgOrigin, _ := p.MergedGPGProgram()
	if gpgProgram != "" {
		out.WriteLine(fmt.Sprintf("  gpg.program: %s  [%s]",
			gpgProgram, filepath.Base(gpgOrigin),
		))
	}

	return nil
}

// hasBehaviorSet reports whether at least one BehaviorConfig sub-field is set.
func hasBehaviorSet(b config.BehaviorConfig) bool {
	return b.RequireExplicitVaultUpgrade != nil || b.RestrictToConfiguredVaults != nil
}

// writePolicyListJSON emits the effective policy as raw JSON to stdout,
// matching the convention from `vault describe --json` and `vault doctor --json`
// (json.NewEncoder direct emission, no envelope wrapper).
func writePolicyListJSON(stdout io.Writer, p policy.Policy) *Error {
	type algoEntry struct {
		Entry   config.ApprovedAlgorithm `json:"entry"`
		Origins []string                 `json:"origins"`
	}
	type vaultEntry struct {
		Pattern string   `json:"pattern"`
		Origins []string `json:"origins"`
	}
	type behaviorEntry struct {
		Field  string `json:"field"`
		Value  bool   `json:"value"`
		Origin string `json:"origin"`
	}
	type gpgEntry struct {
		Program string `json:"program"`
		Origin  string `json:"origin"`
	}
	type listOutput struct {
		Dir                string          `json:"dir,omitempty"`
		Fragments          []string        `json:"fragments,omitempty"`
		ApprovedAlgorithms []algoEntry     `json:"approved_algorithms,omitempty"`
		ApprovedVaultPaths []vaultEntry    `json:"approved_vault_paths,omitempty"`
		Behavior           []behaviorEntry `json:"behavior,omitempty"`
		GPG                *gpgEntry       `json:"gpg,omitempty"`
	}

	data := listOutput{}
	if p.Empty() {
		data.Dir = policy.DefaultDir
	} else {
		data.Dir = p.Dir
		for _, f := range p.Fragments {
			data.Fragments = append(data.Fragments, filepath.Base(f.Path))
		}
		algos, algoOrigins := p.MergedApprovedAlgorithms()
		for i, a := range algos {
			data.ApprovedAlgorithms = append(data.ApprovedAlgorithms, algoEntry{
				Entry:   a,
				Origins: basenames(algoOrigins[i]),
			})
		}
		vaultPatterns, vaultOrigins := p.MergedApprovedVaultPaths()
		for _, pat := range vaultPatterns {
			data.ApprovedVaultPaths = append(data.ApprovedVaultPaths, vaultEntry{
				Pattern: pat,
				Origins: basenames(vaultOrigins[pat]),
			})
		}
		behavior, behaviorOrigins, _ := p.MergedBehavior()
		if behavior.RequireExplicitVaultUpgrade != nil {
			data.Behavior = append(data.Behavior, behaviorEntry{
				Field:  "require_explicit_vault_upgrade",
				Value:  *behavior.RequireExplicitVaultUpgrade,
				Origin: filepath.Base(behaviorOrigins["behavior.require_explicit_vault_upgrade"]),
			})
		}
		if behavior.RestrictToConfiguredVaults != nil {
			data.Behavior = append(data.Behavior, behaviorEntry{
				Field:  "restrict_to_configured_vaults",
				Value:  *behavior.RestrictToConfiguredVaults,
				Origin: filepath.Base(behaviorOrigins["behavior.restrict_to_configured_vaults"]),
			})
		}
		gpgProgram, gpgOrigin, _ := p.MergedGPGProgram()
		if gpgProgram != "" {
			data.GPG = &gpgEntry{
				Program: gpgProgram,
				Origin:  filepath.Base(gpgOrigin),
			}
		}
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
	}
	return nil
}

// validateOutput is the JSON shape for `dotsecenv policy validate --json`.
// Mirrors the vault-doctor pattern: a flat object on stdout, no envelope.
// On failure, error.{code,message} is populated and `valid` is false.
type validateOutput struct {
	Dir           string         `json:"dir"`
	Valid         bool           `json:"valid"`
	FragmentCount int            `json:"fragment_count"`
	Error         *validateError `json:"error,omitempty"`
}

type validateError struct {
	ExitCode int    `json:"exit_code"`
	Message  string `json:"message"`
}

// writePolicyValidateJSON emits the validate result as raw JSON to stdout.
// When cliErr is non-nil, the error block is populated; valid is forced false.
func writePolicyValidateJSON(stdout io.Writer, dir string, valid bool, fragmentCount int, cliErr *Error) error {
	out := validateOutput{
		Dir:           dir,
		Valid:         valid,
		FragmentCount: fragmentCount,
	}
	if cliErr != nil {
		out.Valid = false
		out.Error = &validateError{
			ExitCode: int(cliErr.ExitCode),
			Message:  cliErr.Message,
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func formatAlgo(a config.ApprovedAlgorithm) string {
	parts := []string{fmt.Sprintf("algo: %s", a.Algo)}
	if len(a.Curves) > 0 {
		parts = append(parts, fmt.Sprintf("curves: [%s]", strings.Join(a.Curves, ", ")))
	}
	parts = append(parts, fmt.Sprintf("min_bits: %d", a.MinBits))
	return strings.Join(parts, ", ")
}

func formatOrigins(paths []string) string {
	return "[" + strings.Join(basenames(paths), ", ") + "]"
}

func basenames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

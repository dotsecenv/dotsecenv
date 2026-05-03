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
	out := output.NewHandler(stdout, stderr,
		output.WithSilent(silent),
		output.WithJSON(jsonMode),
	)

	pol, _, err := policy.Load()
	if err != nil {
		return classifyPolicyError(err)
	}

	if jsonMode {
		return writePolicyListJSON(out, pol)
	}
	return writePolicyListText(out, pol)
}

// PolicyValidate parses all fragments and reports structural errors.
// Returns nil on success (no policy enforced OR all fragments structurally
// valid). Otherwise returns *Error with a distinct ExitCode per category.
func PolicyValidate(silent bool, stdout, stderr io.Writer) *Error {
	out := output.NewHandler(stdout, stderr, output.WithSilent(silent))

	pol, _, err := policy.Load()
	if err != nil {
		return classifyPolicyError(err)
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
	case errors.Is(err, policy.ErrInsecurePermissions):
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

	algos, origins := p.MergedApprovedAlgorithms()
	if len(algos) > 0 {
		out.WriteLine("  approved_algorithms:")
		for i, a := range algos {
			out.WriteLine(fmt.Sprintf("    - %s  %s",
				formatAlgo(a),
				formatOrigins(origins[i]),
			))
		}
	}

	return nil
}

// writePolicyListJSON emits the effective policy as a JSON envelope.
func writePolicyListJSON(out *output.Handler, p policy.Policy) *Error {
	type algoEntry struct {
		Entry   config.ApprovedAlgorithm `json:"entry"`
		Origins []string                 `json:"origins"`
	}
	type listOutput struct {
		Dir                string      `json:"dir,omitempty"`
		Fragments          []string    `json:"fragments,omitempty"`
		ApprovedAlgorithms []algoEntry `json:"approved_algorithms,omitempty"`
	}

	data := listOutput{}
	if p.Empty() {
		data.Dir = policy.DefaultDir
	} else {
		data.Dir = p.Dir
		for _, f := range p.Fragments {
			data.Fragments = append(data.Fragments, filepath.Base(f.Path))
		}
		algos, origins := p.MergedApprovedAlgorithms()
		for i, a := range algos {
			data.ApprovedAlgorithms = append(data.ApprovedAlgorithms, algoEntry{
				Entry:   a,
				Origins: basenames(origins[i]),
			})
		}
	}

	if err := out.WriteJSON(data, nil); err != nil {
		return NewError(fmt.Sprintf("failed to write json: %v", err), ExitGeneralError)
	}
	return nil
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

// Compile-time check: encoding/json must remain imported (used by WriteJSON envelope).
var _ = json.Marshal

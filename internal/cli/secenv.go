package cli

import (
	"fmt"
	"path/filepath"

	"github.com/dotsecenv/dotsecenv/internal/cli/secenvpicker"
	"github.com/dotsecenv/dotsecenv/internal/secenv"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// HasTTY reports whether a controlling terminal is available. It wraps the
// unexported detector so the cmd layer has a single source of truth.
func HasTTY() bool { return defaultHasTTY() }

// InitSecenv adds vault-secret references to dir/.secenv. In a terminal it opens
// the interactive picker; with forceBatch (no TTY, --silent, or --all) it adds
// every not-yet-present reference from the resolver's vaults. The resolver is
// already scoped to any -v vaults, so both paths inherit that restriction.
// References never overwrite existing keys, and values are never written.
func (c *CLI) InitSecenv(dir string, forceBatch bool) *Error {
	secenvPath := filepath.Join(dir, ".secenv")

	existing, err := secenv.ReadEnvNames(secenvPath)
	if err != nil {
		return NewError(fmt.Sprintf("failed to read %s: %v", secenvPath, err), ExitGeneralError)
	}

	if forceBatch {
		return c.initSecenvBatch(secenvPath, existing)
	}
	return c.initSecenvInteractive(secenvPath, existing)
}

// initSecenvBatch adds every non-deleted, not-present reference without prompting.
func (c *CLI) initSecenvBatch(secenvPath string, existing map[string]bool) *Error {
	refs := buildRefsFromInfos(c.vaultResolver.ListAllSecretKeys(), c.Output())
	if len(refs) == 0 {
		c.Output().WriteLine("No secrets available to add.")
		return nil
	}
	return c.writeRefs(secenvPath, refs, existing)
}

// initSecenvInteractive runs the picker and writes the chosen references.
func (c *CLI) initSecenvInteractive(secenvPath string, existing map[string]bool) *Error {
	tabs := c.buildPickerTabs(existing)
	if len(tabs) == 0 {
		return NewError("no vaults available to pick from", ExitVaultError)
	}

	result, err := secenvpicker.Run(tabs, secenvPath)
	if err != nil {
		// The terminal disappeared between the TTY check and launch; do the
		// safe non-interactive thing rather than failing outright.
		return c.initSecenvBatch(secenvPath, existing)
	}
	if !result.Confirmed {
		_, _ = fmt.Fprintln(c.Output().Stderr(), "Cancelled.")
		return NewError("", ExitGeneralError)
	}

	refs := make([]secenv.Ref, 0, len(result.Refs))
	for _, cand := range result.Refs {
		refs = append(refs, secenv.Ref{EnvName: cand.EnvName, SecretKey: cand.SecretKey})
	}
	if len(refs) == 0 {
		c.Output().WriteLine("Nothing selected.")
		return nil
	}
	return c.writeRefs(secenvPath, refs, existing)
}

// writeRefs appends refs, warns on each skipped duplicate (muted by --silent),
// and reports the count.
func (c *CLI) writeRefs(secenvPath string, refs []secenv.Ref, existing map[string]bool) *Error {
	out := c.Output()
	written, skipped, err := secenv.Append(secenvPath, refs, existing)
	if err != nil {
		return NewError(fmt.Sprintf("failed to write %s: %v", secenvPath, err), ExitGeneralError)
	}
	for _, s := range skipped {
		out.Warnf(output.CodeWarnGeneric, "%s already present, skipping", s.EnvName)
	}
	if len(written) == 0 {
		out.WriteLine(fmt.Sprintf("No new references added to %s.", secenvPath))
	} else {
		out.Successf("Added %d reference(s) to %s", len(written), secenvPath)
	}
	return nil
}

// buildRefsFromInfos turns vault key listings into references, dropping deleted
// keys and warning on any key that cannot be parsed into an env-var name.
func buildRefsFromInfos(infos []vault.SecretKeyInfo, out *output.Handler) []secenv.Ref {
	var refs []secenv.Ref
	for _, info := range infos {
		if info.Deleted {
			continue
		}
		ref, err := secenv.DeriveRef(info.Key)
		if err != nil {
			out.Warnf(output.CodeWarnGeneric, "skipping secret %q: %v", info.Key, err)
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

// buildPickerTabs builds one picker tab per loaded vault. Unparseable legacy
// keys are dropped silently here (the picker is visual; warnings would be lost
// behind the alternate screen). Keys already in .secenv are shown but marked
// pre-existing so they cannot be selected.
func (c *CLI) buildPickerTabs(existing map[string]bool) []secenvpicker.VaultTab {
	available := c.vaultResolver.GetAvailableVaultPathsWithIndices()
	tabs := make([]secenvpicker.VaultTab, 0, len(available))
	for _, v := range available {
		var cands []secenvpicker.Candidate
		for _, info := range c.vaultResolver.ListSecretKeysFromVault(v.Index) {
			if info.Deleted {
				continue
			}
			ref, err := secenv.DeriveRef(info.Key)
			if err != nil {
				continue
			}
			cands = append(cands, secenvpicker.Candidate{
				SecretKey:   ref.SecretKey,
				EnvName:     ref.EnvName,
				Line:        ref.Line(),
				PreExisting: existing[ref.EnvName],
			})
		}
		tabs = append(tabs, secenvpicker.VaultTab{
			Name: fmt.Sprintf("%d:%s", v.Index+1, filepath.Base(v.Path)),
			Keys: cands,
		})
	}
	return tabs
}

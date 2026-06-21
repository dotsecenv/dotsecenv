package cli

import (
	"encoding/json"
	"fmt"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// CompactSecretJSON is a per-secret entry in the compact JSON output.
type CompactSecretJSON struct {
	Key     string `json:"key"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
	Removed bool   `json:"removed,omitempty"`
}

// CompactResultJSON is the JSON output structure for vault compact.
type CompactResultJSON struct {
	Vault          string              `json:"vault"`
	Applied        bool                `json:"applied"`
	Secrets        []CompactSecretJSON `json:"secrets"`
	ValuesBefore   int                 `json:"values_before"`
	ValuesAfter    int                 `json:"values_after"`
	ValuesDropped  int                 `json:"values_dropped"`
	SecretsRemoved int                 `json:"secrets_removed"`
}

// VaultCompact drops superseded secret-value versions from a vault, keeping the
// newest value each current identity can decrypt and removing deleted secrets
// entirely. It never decrypts: it reads only access lists and value order, then
// rewrites the file preserving every kept value verbatim (signatures intact).
//
// Without --yes it prints the plan and asks for confirmation (skipped in CI).
// In JSON mode it reports the plan and only writes when --yes is set.
func (c *CLI) VaultCompact(jsonOutput bool, yes bool, vaultPath string, fromIndex int) *Error {
	targetIndex, resolveErr := c.resolveWritableVaultIndex(vaultPath, fromIndex, "Select vault to compact:")
	if resolveErr != nil {
		return resolveErr
	}

	entry := c.vaultResolver.GetConfig().Entries[targetIndex]
	expandedPath := vault.ExpandPath(entry.Path)

	if writeErr := checkVaultWritable(entry.Path); writeErr != nil {
		return writeErr
	}

	writer, err := vault.NewWriter(expandedPath)
	if err != nil {
		return NewError(fmt.Sprintf("failed to open vault: %v", err), ExitVaultError)
	}

	v, err := writer.ReadVault()
	if err != nil {
		return NewError(fmt.Sprintf("failed to read vault: %v", err), ExitVaultError)
	}

	compacted, stats := vault.PlanCompaction(v)

	if jsonOutput {
		applied := false
		if stats.Changed() && yes {
			if rewriteErr := writer.RewriteFromVault(compacted); rewriteErr != nil {
				return NewError(fmt.Sprintf("failed to rewrite vault: %v", rewriteErr), ExitVaultError)
			}
			applied = true
		}
		return c.printCompactJSON(entry.Path, stats, applied)
	}

	c.printCompactPlan(entry.Path, stats)

	if !stats.Changed() {
		_, _ = fmt.Fprintf(c.output.Stdout(), "\nVault is already compact; nothing to do.\n")
		return nil
	}

	if !yes && !isCI() {
		confirmed, confirmErr := PromptConfirm(
			fmt.Sprintf("Compact vault %s? This rewrites the vault file.", expandedPath),
			c.output.Stderr())
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Aborted; vault unchanged.\n")
			return nil
		}
	}

	if rewriteErr := writer.RewriteFromVault(compacted); rewriteErr != nil {
		return NewError(fmt.Sprintf("failed to rewrite vault: %v", rewriteErr), ExitVaultError)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "\nCompacted %s: dropped %d value(s)", expandedPath, stats.ValuesDropped)
	if stats.SecretsRemoved > 0 {
		_, _ = fmt.Fprintf(c.output.Stdout(), ", removed %d deleted secret(s)", stats.SecretsRemoved)
	}
	_, _ = fmt.Fprintf(c.output.Stdout(), ".\nRun `dotsecenv validate` to verify.\n")
	return nil
}

// printCompactPlan prints the per-secret before/after counts.
func (c *CLI) printCompactPlan(path string, stats *vault.CompactStats) {
	out := c.output.Stdout()
	_, _ = fmt.Fprintf(out, "Vault: %s\n", path)
	_, _ = fmt.Fprintf(out, "Compaction plan (metadata only, no decryption):\n")
	if len(stats.Secrets) == 0 {
		_, _ = fmt.Fprintf(out, "  (no secrets)\n")
		return
	}
	for _, s := range stats.Secrets {
		switch {
		case s.Removed:
			_, _ = fmt.Fprintf(out, "  %s: %d value(s) -> removed (deleted)\n", s.Key, s.Before)
		case s.Before != s.After:
			_, _ = fmt.Fprintf(out, "  %s: %d -> %d value(s)\n", s.Key, s.Before, s.After)
		default:
			_, _ = fmt.Fprintf(out, "  %s: %d value(s) (unchanged)\n", s.Key, s.Before)
		}
	}
	_, _ = fmt.Fprintf(out, "Total: %d -> %d value(s)", stats.ValuesBefore, stats.ValuesAfter)
	if stats.SecretsRemoved > 0 {
		_, _ = fmt.Fprintf(out, "; %d deleted secret(s) removed", stats.SecretsRemoved)
	}
	_, _ = fmt.Fprintf(out, "\n")
}

// printCompactJSON emits the compaction result as JSON.
func (c *CLI) printCompactJSON(path string, stats *vault.CompactStats, applied bool) *Error {
	result := CompactResultJSON{
		Vault:          path,
		Applied:        applied,
		ValuesBefore:   stats.ValuesBefore,
		ValuesAfter:    stats.ValuesAfter,
		ValuesDropped:  stats.ValuesDropped,
		SecretsRemoved: stats.SecretsRemoved,
	}
	for _, s := range stats.Secrets {
		result.Secrets = append(result.Secrets, CompactSecretJSON{
			Key:     s.Key,
			Before:  s.Before,
			After:   s.After,
			Removed: s.Removed,
		})
	}

	encoder := json.NewEncoder(c.output.Stdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
	}
	return nil
}

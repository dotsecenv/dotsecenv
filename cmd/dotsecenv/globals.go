package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
	"github.com/dotsecenv/dotsecenv/internal/xdg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// GlobalOptions holds the global configuration flags
type GlobalOptions struct {
	ConfigPath string
	VaultPaths []string
	Silent     bool
}

// globalOpts is the shared global options instance
var globalOpts = &GlobalOptions{}

// resolveVaultPaths resolves numeric vault indices to actual paths using config
func resolveVaultPaths(configPath string, vaultPaths []string) ([]string, error) {
	resolvedPaths := make([]string, len(vaultPaths))
	copy(resolvedPaths, vaultPaths)

	for i, vPath := range resolvedPaths {
		if idx, err := strconv.Atoi(vPath); err == nil {
			// It's a number, resolve from config
			cfgPath := configPath
			if cfgPath == "" {
				xdgPaths, _ := xdg.NewPaths()
				cfgPath = xdgPaths.ConfigPath()
			}

			cfg, _, configErr := config.Load(cfgPath)
			if configErr != nil {
				return nil, fmt.Errorf("failed to load config for vault index %d: %v", idx, configErr)
			}

			vaultCfg, parseErr := vault.ParseVaultConfig(cfg.Vault)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse vault config: %v", parseErr)
			}

			if idx <= 0 || idx > len(vaultCfg.Entries) {
				var sb strings.Builder
				fmt.Fprintf(&sb, "-v index %d exceeds number of configured vaults (%d)", idx, len(vaultCfg.Entries))
				if len(vaultCfg.Entries) > 0 {
					sb.WriteString("\nConfigured vaults:\n")
					for k, entry := range vaultCfg.Entries {
						fmt.Fprintf(&sb, "  %d: %s\n", k+1, entry.Path)
					}
				}
				return nil, fmt.Errorf("%s", sb.String())
			}

			resolvedPaths[i] = vaultCfg.Entries[idx-1].Path
		}
	}

	return resolvedPaths, nil
}

// createCLI creates a CLI instance with resolved vault paths
func createCLI() (*clilib.CLI, error) {
	resolvedPaths, err := resolveVaultPaths(globalOpts.ConfigPath, globalOpts.VaultPaths)
	if err != nil {
		return nil, err
	}

	return clilib.NewCLI(resolvedPaths, globalOpts.ConfigPath, globalOpts.Silent, os.Stdin, os.Stdout, os.Stderr)
}

// parseVaultSpec parses a vault specification (-v value) and returns the vault path and index
// Returns: vaultPath (if path), fromIndex (if 1-based index), error
func parseVaultSpec(configPath string, vaultPaths []string) (vaultPath string, fromIndex int, err error) {
	if len(vaultPaths) == 0 {
		return "", 0, nil
	}

	vaultSpec := vaultPaths[0]

	// Check if it's a numeric index
	if idx, parseErr := strconv.Atoi(vaultSpec); parseErr == nil {
		// It's a number - validate it's a positive 1-based index
		if idx <= 0 {
			printVaultList(configPath, os.Stderr)
			return "", 0, fmt.Errorf("-v index must be a positive integer (N >= 1), got: %d", idx)
		}

		// Validate against config
		cfgPath := configPath
		if cfgPath == "" {
			xdgPaths, _ := xdg.NewPaths()
			cfgPath = xdgPaths.ConfigPath()
		}

		cfg, _, configErr := config.Load(cfgPath)
		if configErr != nil {
			return "", 0, fmt.Errorf("failed to load config: %v", configErr)
		}

		vaultCfg, parseErr := vault.ParseVaultConfig(cfg.Vault)
		if parseErr != nil {
			return "", 0, fmt.Errorf("failed to parse vault config: %v", parseErr)
		}

		if idx > len(vaultCfg.Entries) {
			printVaultList(configPath, os.Stderr)
			return "", 0, fmt.Errorf("-v index %d exceeds number of configured vaults (%d)", idx, len(vaultCfg.Entries))
		}

		return "", idx, nil
	}

	// It's a path
	return vaultSpec, 0, nil
}

// printVaultList prints the list of configured vaults to the given writer
func printVaultList(configPath string, w io.Writer) {
	cfgPath := configPath
	if cfgPath == "" {
		xdgPaths, _ := xdg.NewPaths()
		cfgPath = xdgPaths.ConfigPath()
	}

	cfg, _, configErr := config.Load(cfgPath)
	if configErr != nil {
		return
	}

	vaultCfg, parseErr := vault.ParseVaultConfig(cfg.Vault)
	if parseErr != nil || len(vaultCfg.Entries) == 0 {
		return
	}

	_, _ = fmt.Fprintf(w, "Configured vaults:\n")
	for i, entry := range vaultCfg.Entries {
		_, _ = fmt.Fprintf(w, "  %d: %s\n", i+1, entry.Path)
	}
}

// exitWithError prints an error and exits with the appropriate code
func exitWithError(err *clilib.Error) {
	if err != nil {
		os.Exit(int(clilib.PrintError(os.Stderr, err)))
	}
}

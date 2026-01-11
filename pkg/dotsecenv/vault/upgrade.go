package vault

import (
	"bufio"
	"fmt"
	"os"
)

// DetectVaultVersion reads just the first line of a vault file and extracts the version
// from the header marker without parsing the full header JSON.
func DetectVaultVersion(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Non-existent vault is treated as "no version" - will create with latest
			return 0, nil
		}
		return 0, fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Check if file is empty
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to stat vault: %w", err)
	}
	if info.Size() == 0 {
		// Empty file is treated as "no version" - will create with latest
		return 0, nil
	}

	scanner := bufio.NewScanner(f)

	// Line 1: Header marker
	if !scanner.Scan() {
		return 0, fmt.Errorf("empty vault file")
	}
	markerLine := scanner.Text()

	// Validate header marker
	if err := ValidateHeaderMarker(markerLine); err != nil {
		return 0, err
	}

	// Line 2: JSON header (contains version)
	if !scanner.Scan() {
		return 0, fmt.Errorf("missing header JSON line")
	}
	headerLine := scanner.Text()

	return detectVersionFromJSON([]byte(headerLine))
}

// upgradeVault performs in-place upgrade from currentVersion to targetVersion.
// It reads the vault using the current version's parser and rewrites it using
// the target version's format.
func upgradeVault(w *Writer, currentVersion, targetVersion int) error {
	if currentVersion >= targetVersion {
		return nil // Already at or above target version
	}

	// Read entire vault
	vault, err := w.ReadVault()
	if err != nil {
		return fmt.Errorf("failed to read vault for upgrade: %w", err)
	}

	// Rewrite vault using target version's format
	return w.RewriteFromVaultWithVersion(vault, targetVersion)
}

// printUpgradeWarning outputs warning to stderr when an outdated vault is detected.
func printUpgradeWarning(path string, currentVersion, latestVersion int) {
	fmt.Fprintf(os.Stderr, "dotsecenv: warning: vault %q uses format v%d, upgrade to v%d recommended\n",
		path, currentVersion, latestVersion)
}

// printUpgradeNotice outputs notice to stderr after successful upgrade.
func printUpgradeNotice(path string, fromVersion, toVersion int) {
	fmt.Fprintf(os.Stderr, "dotsecenv: vault %q upgraded from v%d to v%d\n",
		path, fromVersion, toVersion)
}

// printExplicitUpgradeHint outputs hint about running vault upgrade command.
func printExplicitUpgradeHint() {
	fmt.Fprintf(os.Stderr, "dotsecenv: run 'dotsecenv vault upgrade' to upgrade the vault format\n")
}

// CheckAndUpgradeVault checks if a vault needs upgrading and handles it based on requireExplicitUpgrade.
// Returns true if the vault was upgraded (caller may need to reload).
// If requireExplicitUpgrade is true: warns but doesn't modify the vault.
// If requireExplicitUpgrade is false: upgrades the vault in-place.
func CheckAndUpgradeVault(w *Writer, path string, requireExplicitUpgrade bool) (bool, error) {
	currentVersion := w.Version()

	if currentVersion >= LatestFormatVersion {
		return false, nil // Already at latest version
	}

	if currentVersion == 0 {
		// New vault or empty file - no upgrade needed, will be created with latest
		return false, nil
	}

	if currentVersion < MinSupportedVersion {
		return false, fmt.Errorf("vault format v%d is no longer supported (minimum: v%d)",
			currentVersion, MinSupportedVersion)
	}

	// Always warn to stderr
	printUpgradeWarning(path, currentVersion, LatestFormatVersion)

	if requireExplicitUpgrade {
		// Explicit upgrade required: warn only, don't modify
		printExplicitUpgradeHint()
		return false, nil
	}

	// Auto-upgrade: perform upgrade
	if err := upgradeVault(w, currentVersion, LatestFormatVersion); err != nil {
		return false, fmt.Errorf("failed to upgrade vault: %w", err)
	}

	printUpgradeNotice(path, currentVersion, LatestFormatVersion)
	return true, nil
}

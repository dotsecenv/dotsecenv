//go:build !windows

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// checkSecure verifies the directory or file is owned by root and not
// writable by group/other. Uses statFn (injectable) so tests can fake
// FileInfo without needing real root-owned files.
func checkSecure(path string, statFn func(string) (os.FileInfo, error)) error {
	st, err := statFn(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"%w: %s is writable by group or other (mode %#o); policy files must be mode 0644 or stricter",
			ErrInsecurePermissions, path, st.Mode().Perm(),
		)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot inspect ownership of %s", ErrInsecurePermissions, path)
	}
	if sys.Uid != 0 {
		return fmt.Errorf(
			"%w: %s is owned by uid=%d, expected root (uid 0)",
			ErrInsecurePermissions, path, sys.Uid,
		)
	}
	return nil
}

//go:build windows

package policy

import (
	"fmt"
	"os"
)

// checkSecure on Windows returns "not supported". Windows uses ACLs instead of
// POSIX permissions; supporting policy on Windows is out of scope for this
// phase (Windows port is itself WIP).
func checkSecure(path string, statFn func(string) (os.FileInfo, error)) error {
	return fmt.Errorf("policy directory not supported on Windows yet (path: %s)", path)
}

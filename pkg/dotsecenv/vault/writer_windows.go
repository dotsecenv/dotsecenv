//go:build windows

package vault

import "os"

// getFileOwner returns the uid and gid of a file from its FileInfo.
// On Windows, Unix-style ownership doesn't apply, so we return -1, -1.
func getFileOwner(info os.FileInfo) (uid, gid int) {
	return -1, -1
}

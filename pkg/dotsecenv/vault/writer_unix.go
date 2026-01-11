//go:build !windows

package vault

import (
	"os"
	"syscall"
)

// getFileOwner returns the uid and gid of a file from its FileInfo.
// Returns -1, -1 if the information cannot be retrieved.
func getFileOwner(info os.FileInfo) (uid, gid int) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}

//go:build unix

package vault

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile locks the file for exclusive or shared access
func lockFile(file *os.File, exclusive bool) error {
	lockType := unix.LOCK_SH
	if exclusive {
		lockType = unix.LOCK_EX
	}
	return unix.Flock(int(file.Fd()), lockType)
}

// unlockFile releases the lock on the file
func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

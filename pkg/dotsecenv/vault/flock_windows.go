//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

const (
	// Windows LockFileEx flags
	lockfileExclusiveLock = 0x00000002
)

// lockFile locks the file for exclusive or shared access
func lockFile(file *os.File, exclusive bool) error {
	var flags uint32
	if exclusive {
		flags = lockfileExclusiveLock
	}

	// Lock the entire file (use max values for length)
	ol := new(windows.Overlapped)
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		flags,
		0,
		1,
		0,
		ol,
	)
}

// unlockFile releases the lock on the file
func unlockFile(file *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		1,
		0,
		ol,
	)
}

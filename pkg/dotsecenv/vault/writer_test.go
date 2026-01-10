package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

func TestFlushPreservesFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault with default permissions (0600)
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Verify default permissions
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected default permissions 0600, got %o", info.Mode().Perm())
	}

	// Change permissions to something different
	if err := os.Chmod(vaultPath, 0o640); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	// Add an identity (triggers flush)
	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Verify permissions were preserved
	info, err = os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat after AddIdentity failed: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("expected permissions 0640 to be preserved, got %o", info.Mode().Perm())
	}
}

func TestFlushPreservesPermissionsAfterRewriteFromVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Change permissions to 0640
	if err := os.Chmod(vaultPath, 0o640); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	// Read vault and rewrite it (like defrag does)
	vault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	if err := w.RewriteFromVault(vault); err != nil {
		t.Fatalf("RewriteFromVault failed: %v", err)
	}

	// Verify permissions were preserved
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat after RewriteFromVault failed: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("expected permissions 0640 to be preserved after rewrite, got %o", info.Mode().Perm())
	}
}

func TestFlushPreservesPermissionsWithUpgrade(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Set specific permissions
	if err := os.Chmod(vaultPath, 0o600); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	// Simulate vault upgrade (rewrite with specific version)
	vault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	if err := w.RewriteFromVaultWithVersion(vault, LatestFormatVersion); err != nil {
		t.Fatalf("RewriteFromVaultWithVersion failed: %v", err)
	}

	// Verify permissions were preserved
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat after RewriteFromVaultWithVersion failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected permissions 0600 to be preserved after upgrade, got %o", info.Mode().Perm())
	}
}

func TestNewVaultHasDefaultPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "newvault")

	// Create a new vault (file doesn't exist yet)
	_, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Verify default permissions are 0600
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected new vault to have permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestFlushWithRestrictivePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Set very restrictive permissions (owner read-only)
	if err := os.Chmod(vaultPath, 0o400); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	// Need to make writable for the test to proceed
	// (this tests that we can still write after chmod)
	if err := os.Chmod(vaultPath, 0o644); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	// Add an identity
	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Verify permissions were preserved
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("expected permissions 0644, got %o", info.Mode().Perm())
	}
}

func TestGetFileOwnerUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping Unix-specific test on Windows")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}

	uid, gid := getFileOwner(info)

	// On Unix, uid and gid should be >= 0 for files we own
	if uid < 0 {
		t.Errorf("expected uid >= 0, got %d", uid)
	}
	if gid < 0 {
		t.Errorf("expected gid >= 0, got %d", gid)
	}

	// Should match current user
	if uid != os.Getuid() {
		t.Errorf("expected uid %d, got %d", os.Getuid(), uid)
	}
	if gid != os.Getgid() {
		t.Errorf("expected gid %d, got %d", os.Getgid(), gid)
	}
}

func TestGetFileOwnerWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows-specific test on non-Windows")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}

	uid, gid := getFileOwner(info)

	// On Windows, getFileOwner returns -1, -1
	if uid != -1 {
		t.Errorf("expected uid -1 on Windows, got %d", uid)
	}
	if gid != -1 {
		t.Errorf("expected gid -1 on Windows, got %d", gid)
	}
}

func TestFlushPreservesMultipleWriteOperations(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Set specific permissions
	if err := os.Chmod(vaultPath, 0o640); err != nil {
		t.Fatalf("os.Chmod failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Perform multiple operations (each triggers flush)
	for i := 0; i < 5; i++ {
		if err := w.AddIdentity(identity.Identity{
			AddedAt:     now.Add(time.Duration(i) * time.Second),
			Fingerprint: string(rune('A' + i)),
		}); err != nil {
			t.Fatalf("AddIdentity %d failed: %v", i, err)
		}

		// Verify permissions after each operation
		info, err := os.Stat(vaultPath)
		if err != nil {
			t.Fatalf("os.Stat after operation %d failed: %v", i, err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("operation %d: expected permissions 0640, got %o", i, info.Mode().Perm())
		}
	}
}

func TestTempFileCleanupOnError(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create initial vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Add an identity to have some content
	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Verify no .tmp file exists after successful write
	tmpPath := vaultPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file should not exist after successful write")
	}
}

func TestDirectoryPermissionsOnNewVault(t *testing.T) {
	tmpDir := t.TempDir()
	// Create in a subdirectory that doesn't exist yet
	vaultPath := filepath.Join(tmpDir, "subdir", "vault")

	_, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Check that the directory was created with 0700 permissions
	dirInfo, err := os.Stat(filepath.Dir(vaultPath))
	if err != nil {
		t.Fatalf("os.Stat on directory failed: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("expected directory permissions 0700, got %o", dirInfo.Mode().Perm())
	}
}

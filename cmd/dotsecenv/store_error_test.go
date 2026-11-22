package main_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestSecretStore_RefusedWriteFails checks that a write the append-time clock
// check refuses makes 'secret store' fail and leaves the vault unchanged.
func TestSecretStore_RefusedWriteFails(t *testing.T) {
	vaultPath, users := setupSharedVault(t, "UserA")
	user := users[0]
	if _, stderr, err := user.run("v1", "secret", "store", "K1"); err != nil {
		t.Fatalf("store K1: %v\n%s", err, stderr)
	}

	// Date the last entry 3 minutes ahead, as a teammate with a fast clock would.
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	future := time.Now().UTC().Add(3 * time.Minute).Format(time.RFC3339Nano)
	last := len(lines) - 1
	lines[last] = regexp.MustCompile(`"added_at":"[^"]+"`).ReplaceAllString(lines[last], `"added_at":"`+future+`"`)
	before := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(vaultPath, before, 0600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := user.run("v2", "secret", "store", "K2")
	if err == nil {
		t.Fatalf("store K2 succeeded; stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "refusing to append entry") {
		t.Errorf("stderr does not name the refused write: %s", stderr)
	}
	if strings.Contains(stdout, "stored successfully") {
		t.Errorf("reported success: %s", stdout)
	}
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("vault changed after a refused write")
	}
}

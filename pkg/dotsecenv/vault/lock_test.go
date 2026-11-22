package vault

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Concurrent writers, each with its own Manager, must not lose entries: the
// lock has to follow the file that each flush renames into place.
func TestConcurrentManagersKeepEveryEntry(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault")
	if _, err := NewWriter(vaultPath); err != nil {
		t.Fatal(err)
	}

	const writers = 25
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			time.Sleep(time.Duration(i) * 2 * time.Millisecond)
			m := NewManager(vaultPath, false)
			if err := m.OpenAndLock(); err != nil {
				t.Errorf("writer %d: OpenAndLock: %v", i, err)
				return
			}
			defer func() { _ = m.Unlock() }()
			// Two writes: the lock must also survive this Manager's own first rename.
			for _, suffix := range []string{"A", "B"} {
				now := time.Now().UTC()
				s := Secret{AddedAt: now, Key: fmt.Sprintf("K%02d_%s", i, suffix), Values: []SecretValue{{AddedAt: now, Value: "v"}}}
				if err := m.AddSecret(s); err != nil {
					t.Errorf("writer %d: AddSecret: %v", i, err)
				}
			}
		})
	}
	wg.Wait()

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.ListSecretKeys()); got != 2*writers {
		t.Fatalf("vault holds %d secrets, want %d", got, 2*writers)
	}
}

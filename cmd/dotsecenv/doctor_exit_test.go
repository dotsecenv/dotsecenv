package main_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("command did not run: %v", err)
	}
	return exitErr.ExitCode()
}

// writeDoctorConfig writes a config whose vaults are not upgraded on load,
// so doctor sees outdated formats.
func writeDoctorConfig(t *testing.T, dir string, vaults ...string) string {
	t.Helper()
	configPath := filepath.Join(dir, "config.yaml")
	var list string
	for _, v := range vaults {
		list += fmt.Sprintf("  - %s\n", v)
	}
	content := fmt.Sprintf(`approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
%sbehavior:
  require_explicit_vault_upgrade: true
gpg:
  program: PATH
`, list)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

// doctorEnv runs doctor non-interactively with a live gpg-agent, so the
// gpg-agent check passes and the vault checks decide the exit code.
func doctorEnv(t *testing.T) []string {
	t.Helper()
	// A short path: gpg-agent's socket path must fit in sun_path.
	gpgHome, err := os.MkdirTemp("", "dse-gpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(gpgHome) })
	t.Cleanup(startGPGAgent(t, gpgHome))
	return []string{"CI=true", "GNUPGHOME=" + gpgHome}
}

// doctor used to exit 0 whatever it found. A failed check exits with that
// check's error category; changes found but not applied exit 10.
func TestDoctor_ExitCodes(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "dotsecenv", "vault", "testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unloadable vault exits 3", func(t *testing.T) {
		dir := t.TempDir()
		bad := filepath.Join(dir, "bad.vault")
		if err := os.WriteFile(bad, []byte("line1\nline2\nline3\n"), 0600); err != nil {
			t.Fatal(err)
		}
		// A healthy second vault, so startup succeeds and doctor itself runs.
		good := filepath.Join(dir, "good.vault")
		if _, stderr, err := runCmd("init", "vault", "-v", good); err != nil {
			t.Fatalf("init vault: %v\n%s", err, stderr)
		}
		configPath := writeDoctorConfig(t, dir, bad, good)
		env := doctorEnv(t)
		for _, args := range [][]string{{"doctor"}, {"doctor", "--json"}, {"vault", "doctor", "--fix"}} {
			_, stderr, err := runCmdWithEnv(env, append([]string{"-c", configPath}, args...)...)
			if got := exitCode(t, err); got != 3 {
				t.Errorf("%v: exit %d, want 3\nstderr: %s", args, got, stderr)
			}
		}
	})

	t.Run("outdated vault exits 10 and prints the fix", func(t *testing.T) {
		dir := t.TempDir()
		v1 := filepath.Join(dir, "it's a vault")
		if err := os.WriteFile(v1, fixture, 0600); err != nil {
			t.Fatal(err)
		}
		configPath := writeDoctorConfig(t, dir, v1)
		env := doctorEnv(t)

		stdout, stderr, err := runCmdWithEnv(env, "-c", configPath, "doctor", "-v", v1)
		if got := exitCode(t, err); got != 10 {
			t.Fatalf("doctor: exit %d, want 10\nstdout: %s\nstderr: %s", got, stdout, stderr)
		}
		want := fmt.Sprintf(`Run: dotsecenv doctor --fix -c '%s' -v '%s'`, configPath, strings.ReplaceAll(v1, "'", `'\''`))
		if !strings.Contains(stdout, want) {
			t.Errorf("doctor output should contain %q, got:\n%s", want, stdout)
		}

		if _, _, err := runCmdWithEnv(env, "-c", configPath, "doctor", "--json"); exitCode(t, err) != 10 {
			t.Errorf("doctor --json: want exit 10")
		}

		if stdout, stderr, err := runCmdWithEnv(env, "-c", configPath, "doctor", "--fix"); exitCode(t, err) != 0 {
			t.Errorf("doctor --fix: want exit 0, got %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		if _, stderr, err := runCmdWithEnv(env, "-c", configPath, "doctor"); exitCode(t, err) != 0 {
			t.Errorf("doctor after --fix: want exit 0, got %v\nstderr: %s", err, stderr)
		}
	})
}

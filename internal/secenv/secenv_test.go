package secenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefLine(t *testing.T) {
	tests := []struct {
		name string
		ref  Ref
		want string
	}{
		{"same name", Ref{EnvName: "FOO", SecretKey: "FOO"}, "FOO={dotsecenv/}"},
		{"empty secret key", Ref{EnvName: "FOO", SecretKey: ""}, "FOO={dotsecenv/}"},
		{"namespaced", Ref{EnvName: "PROD_DB_PASSWORD", SecretKey: "prod::DB_PASSWORD"}, "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}"},
		{"dotted key", Ref{EnvName: "APP_DOMAIN_ORG", SecretKey: "APP.DOMAIN.ORG"}, "APP_DOMAIN_ORG={dotsecenv/APP.DOMAIN.ORG}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ref.Line(); got != tc.want {
				t.Errorf("Line() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveRef(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantEnv   string
		wantLine  string
		wantError bool
	}{
		{"plain upper", "FOO", "FOO", "FOO={dotsecenv/}", false},
		{"plain lower normalises", "cloudflare_token", "CLOUDFLARE_TOKEN", "CLOUDFLARE_TOKEN={dotsecenv/}", false},
		{"namespaced", "prod::DB_PASSWORD", "PROD_DB_PASSWORD", "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}", false},
		{"namespaced mixed case", "Prod::db_password", "PROD_DB_PASSWORD", "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}", false},
		{"dotted name", "APP.DOMAIN.ORG", "APP_DOMAIN_ORG", "APP_DOMAIN_ORG={dotsecenv/APP.DOMAIN.ORG}", false},
		{"namespaced dotted", "svc::APP.DOMAIN", "SVC_APP_DOMAIN", "SVC_APP_DOMAIN={dotsecenv/svc::APP.DOMAIN}", false},
		{"empty invalid", "", "", "", true},
		{"single colon invalid", "ns:KEY", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := DeriveRef(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatalf("DeriveRef(%q) expected error, got %+v", tc.input, ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveRef(%q) unexpected error: %v", tc.input, err)
			}
			if ref.EnvName != tc.wantEnv {
				t.Errorf("EnvName = %q, want %q", ref.EnvName, tc.wantEnv)
			}
			if got := ref.Line(); got != tc.wantLine {
				t.Errorf("Line() = %q, want %q", got, tc.wantLine)
			}
		})
	}
}

func TestReadEnvNames(t *testing.T) {
	t.Run("missing file is empty", func(t *testing.T) {
		set, err := ReadEnvNames(filepath.Join(t.TempDir(), "nope.secenv"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(set) != 0 {
			t.Errorf("expected empty set, got %v", set)
		}
	})

	t.Run("parses LHS names", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".secenv")
		content := "# a comment\n" +
			"\n" +
			"APP_NAME=my-app\n" +
			"  DATABASE_PASSWORD={dotsecenv}\n" +
			"PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}\n" +
			"no_equals_line\n" +
			"   \n" +
			"# KEY=commented\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		set, err := ReadEnvNames(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"APP_NAME", "DATABASE_PASSWORD", "PROD_DB_PASSWORD"}
		for _, w := range want {
			if !set[w] {
				t.Errorf("expected %q in set", w)
			}
		}
		if set["KEY"] {
			t.Error("commented KEY must not be parsed")
		}
		if len(set) != len(want) {
			t.Errorf("set size = %d (%v), want %d", len(set), set, len(want))
		}
	})
}

func TestAppendCreatesFile0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secenv")

	refs := []Ref{
		{EnvName: "FOO", SecretKey: "FOO"},
		{EnvName: "PROD_DB_PASSWORD", SecretKey: "prod::DB_PASSWORD"},
	}
	written, skipped, err := Append(path, refs, nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(written) != 2 || len(skipped) != 0 {
		t.Fatalf("written=%d skipped=%d, want 2/0", len(written), len(skipped))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}

	got, _ := os.ReadFile(path)
	want := "FOO={dotsecenv/}\nPROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}\n"
	if string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestAppendPreservesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secenv")
	// Existing file without a trailing newline, custom mode.
	if err := os.WriteFile(path, []byte("APP_NAME=my-app"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, _, err := Append(path, []Ref{{EnvName: "FOO", SecretKey: "FOO"}}, map[string]bool{"APP_NAME": true})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %o, want 640 (preserved)", perm)
	}

	got, _ := os.ReadFile(path)
	want := "APP_NAME=my-app\nFOO={dotsecenv/}\n"
	if string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestAppendSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secenv")

	refs := []Ref{
		{EnvName: "FOO", SecretKey: "FOO"},
		{EnvName: "BAR", SecretKey: "BAR"},
	}
	written, skipped, err := Append(path, refs, map[string]bool{"FOO": true})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(written) != 1 || written[0].EnvName != "BAR" {
		t.Errorf("written = %+v, want [BAR]", written)
	}
	if len(skipped) != 1 || skipped[0].EnvName != "FOO" {
		t.Errorf("skipped = %+v, want [FOO]", skipped)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "BAR={dotsecenv/}\n" {
		t.Errorf("content = %q", got)
	}
}

func TestAppendIntraRunCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secenv")

	// Two distinct keys derive the same env-var name; second collapses.
	refs := []Ref{
		{EnvName: "PROD_DB_PASSWORD", SecretKey: "prod::DB_PASSWORD"},
		{EnvName: "PROD_DB_PASSWORD", SecretKey: "PROD_DB_PASSWORD"},
	}
	written, skipped, err := Append(path, refs, nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(written) != 1 || len(skipped) != 1 {
		t.Fatalf("written=%d skipped=%d, want 1/1", len(written), len(skipped))
	}
	got, _ := os.ReadFile(path)
	if string(got) != "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}\n" {
		t.Errorf("content = %q", got)
	}
}

func TestAppendEmptyWrittenLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secenv")

	written, skipped, err := Append(path, []Ref{{EnvName: "FOO", SecretKey: "FOO"}}, map[string]bool{"FOO": true})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(written) != 0 || len(skipped) != 1 {
		t.Fatalf("written=%d skipped=%d, want 0/1", len(written), len(skipped))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should not have been created, stat err = %v", err)
	}
}

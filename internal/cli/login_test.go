package cli

import (
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
)

func TestFilterEncryptionCapableKeys(t *testing.T) {
	const (
		fpEnc1     = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
		fpEnc2     = "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"
		fpSignOnly = "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333"
		fpUnknown  = "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
	)

	mock := NewMockGPGClient()
	mock.PublicKeyInfo[fpEnc1] = gpg.KeyInfo{Fingerprint: fpEnc1, CanEncrypt: true}
	mock.PublicKeyInfo[fpEnc2] = gpg.KeyInfo{Fingerprint: fpEnc2, CanEncrypt: true}
	mock.PublicKeyInfo[fpSignOnly] = gpg.KeyInfo{Fingerprint: fpSignOnly, CanEncrypt: false}
	// fpUnknown deliberately absent: GetPublicKeyInfo will error.

	tests := []struct {
		name        string
		input       []gpg.SecretKeyInfo
		wantFPs     []string
		wantSkipped int
	}{
		{
			name:        "empty input",
			input:       nil,
			wantFPs:     nil,
			wantSkipped: 0,
		},
		{
			name: "all capable",
			input: []gpg.SecretKeyInfo{
				{Fingerprint: fpEnc1, UID: "Alice"},
				{Fingerprint: fpEnc2, UID: "Bob"},
			},
			wantFPs:     []string{fpEnc1, fpEnc2},
			wantSkipped: 0,
		},
		{
			name: "mixed capable and sign-only",
			input: []gpg.SecretKeyInfo{
				{Fingerprint: fpEnc1, UID: "Alice"},
				{Fingerprint: fpSignOnly, UID: "Carol (sign-only)"},
				{Fingerprint: fpEnc2, UID: "Bob"},
			},
			wantFPs:     []string{fpEnc1, fpEnc2},
			wantSkipped: 1,
		},
		{
			name: "unknown key (load failure) is filtered",
			input: []gpg.SecretKeyInfo{
				{Fingerprint: fpEnc1, UID: "Alice"},
				{Fingerprint: fpUnknown, UID: "Dave (broken)"},
			},
			wantFPs:     []string{fpEnc1},
			wantSkipped: 1,
		},
		{
			name: "all filtered out",
			input: []gpg.SecretKeyInfo{
				{Fingerprint: fpSignOnly, UID: "Carol"},
				{Fingerprint: fpUnknown, UID: "Dave"},
			},
			wantFPs:     nil,
			wantSkipped: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotSkipped := filterEncryptionCapableKeys(mock, tt.input)
			if gotSkipped != tt.wantSkipped {
				t.Errorf("skipped = %d, want %d", gotSkipped, tt.wantSkipped)
			}
			if len(got) != len(tt.wantFPs) {
				t.Fatalf("got %d keys, want %d: got=%v", len(got), len(tt.wantFPs), got)
			}
			for i, want := range tt.wantFPs {
				if got[i].Fingerprint != want {
					t.Errorf("keys[%d].Fingerprint = %s, want %s", i, got[i].Fingerprint, want)
				}
			}
		})
	}
}

func TestRequireEncryptionCapableKey(t *testing.T) {
	const fp = "1E378219F90018AB2102B2131C238966B12A6F21"

	tests := []struct {
		name    string
		info    *gpg.KeyInfo
		wantErr bool
	}{
		{
			name:    "encryption-capable",
			info:    &gpg.KeyInfo{Fingerprint: fp, CanEncrypt: true},
			wantErr: false,
		},
		{
			name:    "sign-only",
			info:    &gpg.KeyInfo{Fingerprint: fp, CanEncrypt: false},
			wantErr: true,
		},
		{
			name:    "nil info",
			info:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireEncryptionCapableKey(tt.info, fp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("requireEncryptionCapableKey(...) err=%v, wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Message, fp) {
					t.Errorf("error message should mention fingerprint %q: %s", fp, err.Message)
				}
				if !strings.Contains(err.Message, "signing-only") {
					t.Errorf("error message should explain why: %s", err.Message)
				}
				if err.ExitCode != ExitGPGError {
					t.Errorf("exit code = %v, want ExitGPGError", err.ExitCode)
				}
			}
		})
	}
}

func TestShortFingerprint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short", "ABCD", "ABCD"},
		{"exactly 16", "0123456789ABCDEF", "0123456789ABCDEF"},
		{"40-char fingerprint", "1E378219F90018AB2102B2131C238966B12A6F21", "1E378219F90018AB..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shortFingerprint(tt.in); got != tt.want {
				t.Errorf("shortFingerprint(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

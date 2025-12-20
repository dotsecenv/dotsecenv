package gpg

import (
	"testing"
)

func TestInferCurveFromBitLength(t *testing.T) {
	tests := []struct {
		bits   int
		algoID int
		want   string
	}{
		{256, 18, "P-256"},   // ECDH
		{256, 19, "P-256"},   // ECDSA
		{255, 22, "Ed25519"}, // EdDSA
		{384, 19, "P-384"},
		{521, 19, "P-521"},
		{456, 22, "Ed448"}, // EdDSA
		{2048, 1, ""},      // RSA
	}

	for _, tt := range tests {
		got := inferCurveFromBitLength(tt.bits, tt.algoID)
		if got != tt.want {
			t.Errorf("inferCurveFromBitLength(%d, %d) = %q, want %q", tt.bits, tt.algoID, got, tt.want)
		}
	}
}

func TestIsValidCurveName(t *testing.T) {
	tests := []struct {
		curve string
		want  bool
	}{
		{"P-256", true},
		{"Ed25519", true},
		{"invalid char@", false},
		{"", false},
		{"secp256k1", true},
	}

	for _, tt := range tests {
		got := isValidCurveName(tt.curve)
		if got != tt.want {
			t.Errorf("isValidCurveName(%q) = %v, want %v", tt.curve, got, tt.want)
		}
	}
}

func TestGPGClient_ExtractAlgorithmAndCurve(t *testing.T) {
	client := DefaultGPGClient

	tests := []struct {
		full  string
		algo  string
		curve string
	}{
		{"ECC P-384", "ECC", "P-384"},
		{"EdDSA Ed25519", "EdDSA", "Ed25519"},
		{"RSA", "RSA", ""},
		{"", "", ""},
		{"One", "One", ""},
	}

	for _, tt := range tests {
		algo, curve := client.ExtractAlgorithmAndCurve(tt.full)
		if algo != tt.algo || curve != tt.curve {
			t.Errorf("ExtractAlgorithmAndCurve(%q) = (%q, %q), want (%q, %q)", tt.full, algo, curve, tt.algo, tt.curve)
		}
	}
}

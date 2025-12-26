package crypto

import (
	"fmt"
	"regexp"
	"strconv"
)

// AlgorithmValidator validates cryptographic algorithms against a policy.
// It can be used to enforce FIPS 186-5 compliance or custom algorithm policies.
type AlgorithmValidator struct {
	allowedCiphers    map[string]bool
	allowedHashing    map[string]bool
	allowedMac        map[string]bool
	allowedAsymmetric map[string]bool
	allowedSignature  map[string]bool
}

// NewAlgorithmValidator creates a new validator with the specified allowed algorithms.
func NewAlgorithmValidator(
	ciphers, hashing, mac, asymmetric, signature []string,
) AlgorithmValidator {
	av := AlgorithmValidator{
		allowedCiphers:    make(map[string]bool),
		allowedHashing:    make(map[string]bool),
		allowedMac:        make(map[string]bool),
		allowedAsymmetric: make(map[string]bool),
		allowedSignature:  make(map[string]bool),
	}

	for _, c := range ciphers {
		av.allowedCiphers[c] = true
	}
	for _, h := range hashing {
		av.allowedHashing[h] = true
	}
	for _, m := range mac {
		av.allowedMac[m] = true
	}
	for _, a := range asymmetric {
		av.allowedAsymmetric[a] = true
	}
	for _, s := range signature {
		av.allowedSignature[s] = true
	}

	return av
}

// ValidateAsymmetric checks if an asymmetric algorithm is allowed.
func (av AlgorithmValidator) ValidateAsymmetric(algo string) error {
	if !av.allowedAsymmetric[algo] {
		return fmt.Errorf("asymmetric algorithm not allowed: %s", algo)
	}
	return nil
}

// FIPS 186-5 approved algorithm constants.
const (
	FIPSKeyAlgorithmECCP521 = "ECC-P521"
	FIPSKeyAlgorithmRSA4096 = "RSA-4096"
	FIPSCipherAlgorithm     = "AES-256-GCM"
	FIPSHashingAlgorithm    = "SHA-512"
	FIPSMacAlgorithm        = "HMAC-SHA-512"
	FIPSSignatureAlgorithm  = "ECDSA"
)

// ValidateFIPS186_5Compliance checks if an algorithm is FIPS 186-5 approved.
func ValidateFIPS186_5Compliance(algo string) error {
	approvedAlgos := map[string]bool{
		FIPSKeyAlgorithmECCP521: true,
		FIPSKeyAlgorithmRSA4096: true,
		FIPSCipherAlgorithm:     true,
		FIPSHashingAlgorithm:    true,
		FIPSMacAlgorithm:        true,
		FIPSSignatureAlgorithm:  true,
	}

	if !approvedAlgos[algo] {
		return fmt.Errorf("algorithm not FIPS 186-5 approved: %s", algo)
	}
	return nil
}

// ExtractBitLength extracts the bit length from an algorithm name.
// Examples:
//   - "RSA-4096" -> 4096
//   - "RSA-3072" -> 3072
//   - "ECC P-521" -> 521
//   - "ECC P-256" -> 256
//   - "AES-256-GCM" -> 256
//   - "SHA-512" -> 512
//
// Returns 0 if no bit length can be extracted.
func ExtractBitLength(algorithm string) int {
	re := regexp.MustCompile(`(?:[-\s])?(\d+)(?:[-\s])?(?:$|-)`)
	matches := re.FindStringSubmatch(algorithm)
	if len(matches) > 1 {
		if bits, err := strconv.Atoi(matches[1]); err == nil {
			return bits
		}
	}
	return 0
}

// ExtractAlgorithmName extracts the base algorithm name from a full algorithm string.
// Examples:
//   - "RSA-4096" -> "RSA"
//   - "ECC P-521" -> "ECC"
//   - "AES-256-GCM" -> "AES"
//   - "SHA-512" -> "SHA"
//   - "RSA" -> "RSA" (already clean)
func ExtractAlgorithmName(algorithm string) string {
	for i, r := range algorithm {
		if r == '-' || r == ' ' || r == '/' {
			return algorithm[:i]
		}
	}
	return algorithm
}

// GetAlgorithmDetails returns both name and bit length for an algorithm.
func GetAlgorithmDetails(algorithm string) (name string, bits int) {
	return ExtractAlgorithmName(algorithm), ExtractBitLength(algorithm)
}

// NewFIPSValidator creates a new validator enforcing FIPS 186-5 standards.
func NewFIPSValidator() AlgorithmValidator {
	return NewAlgorithmValidator(
		[]string{FIPSCipherAlgorithm},
		[]string{FIPSHashingAlgorithm},
		[]string{FIPSMacAlgorithm},
		[]string{FIPSKeyAlgorithmECCP521, FIPSKeyAlgorithmRSA4096},
		[]string{FIPSSignatureAlgorithm},
	)
}

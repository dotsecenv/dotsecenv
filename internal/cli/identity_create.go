package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
)

// IdentityCreateOptions holds options for the identity create command.
type IdentityCreateOptions struct {
	Algorithm    string // Algorithm to use (ED25519, RSA4096, P384, P521)
	Name         string // User's full name
	Email        string // User's email address
	TemplateOnly bool   // If true, only output the template without generating
}

// IdentityCreate generates a new GPG key or outputs the generation template.
func (c *CLI) IdentityCreate(opts IdentityCreateOptions) *Error {
	// Parse and validate algorithm
	algo, parseErr := gpg.ParseAlgorithm(opts.Algorithm)
	if parseErr != nil {
		return NewError(parseErr.Error(), ExitGeneralError)
	}

	// Validate algorithm against config's approved_algorithms
	algoStr, bits := gpg.GetAlgorithmForValidation(algo)
	if !c.config.IsAlgorithmAllowed(algoStr, bits) {
		return NewError(fmt.Sprintf("algorithm '%s' is not allowed by your configuration\n\n%s\n\nTo use %s, add it to your config's approved_algorithms.\nSee https://dotsecenv.com/concepts/compliance/ for more details.",
			opts.Algorithm, c.config.GetAllowedAlgorithmsString(), opts.Algorithm), ExitAlgorithmNotAllowed)
	}

	// Prompt for name if not provided
	name := opts.Name
	if name == "" {
		var err error
		name, err = c.promptForInput("Enter your full name: ")
		if err != nil {
			return NewError(fmt.Sprintf("failed to read name: %v", err), ExitGeneralError)
		}
		if name == "" {
			return NewError("name cannot be empty", ExitGeneralError)
		}
	}

	// Prompt for email if not provided
	email := opts.Email
	if email == "" {
		var err error
		email, err = c.promptForInput("Enter your email address: ")
		if err != nil {
			return NewError(fmt.Sprintf("failed to read email: %v", err), ExitGeneralError)
		}
		if email == "" {
			return NewError("email cannot be empty", ExitGeneralError)
		}
	}

	// Generate the template
	template, templateErr := gpg.GenerateKeyTemplate(algo, name, email)
	if templateErr != nil {
		return NewError(fmt.Sprintf("failed to generate template: %v", templateErr), ExitGeneralError)
	}

	// If template-only mode, print template and instructions
	if opts.TemplateOnly {
		_, _ = fmt.Fprintf(c.output.Stdout(), "%s", template)
		_, _ = fmt.Fprintf(c.output.Stderr(), "\n# Save the above template to a file (e.g., key-params.txt) and run:\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#   gpg --batch --generate-key key-params.txt\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "# This allows you to:\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#   - Review and customize the template before generation\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#   - Execute key generation directly with GPG for maximum security\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#   - Generate the key on an air-gapped machine\n")
		_, _ = fmt.Fprintf(c.output.Stderr(), "#   - Reduce attack surface by avoiding secret material handling in dotsecenv\n")
		return nil
	}

	// Generate the key using GPG
	_, _ = fmt.Fprintf(c.output.Stdout(), "Generating %s key for %s <%s>...\n", opts.Algorithm, name, email)
	_, _ = fmt.Fprintf(c.output.Stdout(), "GPG will prompt for a passphrase to protect your key.\n\n")

	fingerprint, genErr := c.generateGPGKey(template)
	if genErr != nil {
		return genErr
	}

	// Success! Print helpful output
	_, _ = fmt.Fprintf(c.output.Stdout(), "\nKey generation successful!\n\n")
	_, _ = fmt.Fprintf(c.output.Stdout(), "Created GPG key for %s <%s>\n", name, email)
	_, _ = fmt.Fprintf(c.output.Stdout(), "  Algorithm:   %s\n", opts.Algorithm)
	_, _ = fmt.Fprintf(c.output.Stdout(), "  Fingerprint: %s\n\n", fingerprint)

	// Export and display the public key
	pubKey, pubKeyErr := c.exportPublicKey(fingerprint)
	if pubKeyErr == nil {
		_, _ = fmt.Fprintf(c.output.Stdout(), "To export your public key:\n")
		_, _ = fmt.Fprintf(c.output.Stdout(), "  gpg --armor --export %s\n", fingerprint)
		_, _ = fmt.Fprintf(c.output.Stdout(), "%s\n", pubKey)
	} else {
		_, _ = fmt.Fprintf(c.output.Stdout(), "To export your public key:\n")
		_, _ = fmt.Fprintf(c.output.Stdout(), "  gpg --armor --export %s\n\n", fingerprint)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "To export your secret key (keep this safe!):\n")
	_, _ = fmt.Fprintf(c.output.Stdout(), "  gpg --armor --export-secret-keys %s\n", fingerprint)
	_, _ = fmt.Fprintf(c.output.Stdout(), "  WARNING: Never share your secret key. Store it securely.\n\n")

	_, _ = fmt.Fprintf(c.output.Stdout(), "Next step - login to dotsecenv:\n")
	_, _ = fmt.Fprintf(c.output.Stdout(), "  dotsecenv login %s\n", fingerprint)

	return nil
}

// promptForInput prompts the user for input and returns the trimmed response.
func (c *CLI) promptForInput(prompt string) (string, error) {
	_, _ = fmt.Fprint(c.output.Stderr(), prompt)
	reader := bufio.NewReader(c.stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// generateGPGKey generates a GPG key using the provided template.
// Returns the fingerprint of the generated key.
func (c *CLI) generateGPGKey(template string) (string, *Error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--batch", "--generate-key")
	cmd.Stdin = strings.NewReader(template)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run the command (GPG will use pinentry for passphrase)
	err := cmd.Run()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to generate GPG key: %v\n%s", err, stderr.String()), ExitGPGError)
	}

	// Extract the fingerprint from the most recently created key
	fingerprint, fpErr := c.getLatestKeyFingerprint()
	if fpErr != nil {
		return "", fpErr
	}

	return fingerprint, nil
}

// getLatestKeyFingerprint gets the fingerprint of the most recently created secret key.
func (c *CLI) getLatestKeyFingerprint() (string, *Error) {
	// List secret keys sorted by creation time (newest first)
	cmd := exec.Command(gpg.GetGPGProgram(), "--list-secret-keys", "--with-colons", "--keyid-format", "long")
	output, err := cmd.Output()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to list secret keys: %v", err), ExitGPGError)
	}

	// Parse the output to find the fingerprint
	// GPG output format: sec:...:...:...:KEYID:CREATION_TIME:...
	// We want the fpr line that follows
	var latestFingerprint string
	var latestCreation int64

	lines := strings.Split(string(output), "\n")
	var currentCreation int64
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "sec":
			// Secret key record - get creation time
			if len(parts) > 5 {
				var creation int64
				_, _ = fmt.Sscanf(parts[5], "%d", &creation)
				currentCreation = creation
			}
		case "fpr":
			// Fingerprint record
			if len(parts) >= 10 && parts[9] != "" {
				if currentCreation > latestCreation {
					latestCreation = currentCreation
					latestFingerprint = parts[9]
				}
			}
		}
	}

	if latestFingerprint == "" {
		return "", NewError("could not find fingerprint of generated key", ExitGPGError)
	}

	return latestFingerprint, nil
}

// exportPublicKey exports the public key in ASCII armor format.
func (c *CLI) exportPublicKey(fingerprint string) (string, error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--armor", "--export", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to export public key: %w", err)
	}
	return string(output), nil
}

// IdentityCreateStandalone runs identity create without requiring full CLI initialization.
// This is used when no config exists yet.
func IdentityCreateStandalone(opts IdentityCreateOptions, stdout, stderr, stdin *os.File) *Error {
	// Use default config for algorithm validation
	cfg := config.DefaultConfig()

	// Parse and validate algorithm
	algo, parseErr := gpg.ParseAlgorithm(opts.Algorithm)
	if parseErr != nil {
		return NewError(parseErr.Error(), ExitGeneralError)
	}

	// Validate algorithm against default approved_algorithms
	algoStr, bits := gpg.GetAlgorithmForValidation(algo)
	if !cfg.IsAlgorithmAllowed(algoStr, bits) {
		return NewError(fmt.Sprintf("algorithm '%s' is not allowed by default configuration\n\n%s\n\nTo use %s, first create a config with it enabled.\nSee https://dotsecenv.com/concepts/compliance/ for more details.",
			opts.Algorithm, cfg.GetAllowedAlgorithmsString(), opts.Algorithm), ExitAlgorithmNotAllowed)
	}

	// Prompt for name if not provided
	name := opts.Name
	if name == "" {
		_, _ = fmt.Fprint(stderr, "Enter your full name: ")
		reader := bufio.NewReader(stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return NewError(fmt.Sprintf("failed to read name: %v", err), ExitGeneralError)
		}
		name = strings.TrimSpace(input)
		if name == "" {
			return NewError("name cannot be empty", ExitGeneralError)
		}
	}

	// Prompt for email if not provided
	email := opts.Email
	if email == "" {
		_, _ = fmt.Fprint(stderr, "Enter your email address: ")
		reader := bufio.NewReader(stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return NewError(fmt.Sprintf("failed to read email: %v", err), ExitGeneralError)
		}
		email = strings.TrimSpace(input)
		if email == "" {
			return NewError("email cannot be empty", ExitGeneralError)
		}
	}

	// Generate the template
	template, templateErr := gpg.GenerateKeyTemplate(algo, name, email)
	if templateErr != nil {
		return NewError(fmt.Sprintf("failed to generate template: %v", templateErr), ExitGeneralError)
	}

	// If template-only mode, print template and instructions
	if opts.TemplateOnly {
		_, _ = fmt.Fprintf(stdout, "%s", template)
		_, _ = fmt.Fprintf(stderr, "\n# Save the above template to a file (e.g., key-params.txt) and run:\n")
		_, _ = fmt.Fprintf(stderr, "#   gpg --batch --generate-key key-params.txt\n")
		_, _ = fmt.Fprintf(stderr, "#\n")
		_, _ = fmt.Fprintf(stderr, "# This allows you to:\n")
		_, _ = fmt.Fprintf(stderr, "#   - Review and customize the template before generation\n")
		_, _ = fmt.Fprintf(stderr, "#   - Execute key generation directly with GPG for maximum security\n")
		_, _ = fmt.Fprintf(stderr, "#   - Generate the key on an air-gapped machine\n")
		_, _ = fmt.Fprintf(stderr, "#   - Reduce attack surface by avoiding secret material handling in dotsecenv\n")
		return nil
	}

	// Generate the key using GPG
	_, _ = fmt.Fprintf(stdout, "Generating %s key for %s <%s>...\n", opts.Algorithm, name, email)
	_, _ = fmt.Fprintf(stdout, "GPG will prompt for a passphrase to protect your key.\n\n")

	fingerprint, genErr := generateGPGKeyStandalone(template)
	if genErr != nil {
		return genErr
	}

	// Success! Print helpful output
	_, _ = fmt.Fprintf(stdout, "\nKey generation successful!\n\n")
	_, _ = fmt.Fprintf(stdout, "Created GPG key for %s <%s>\n", name, email)
	_, _ = fmt.Fprintf(stdout, "  Algorithm:   %s\n", opts.Algorithm)
	_, _ = fmt.Fprintf(stdout, "  Fingerprint: %s\n\n", fingerprint)

	// Export and display the public key
	pubKey, pubKeyErr := exportPublicKeyStandalone(fingerprint)
	if pubKeyErr == nil {
		_, _ = fmt.Fprintf(stdout, "To export your public key:\n")
		_, _ = fmt.Fprintf(stdout, "  gpg --armor --export %s\n", fingerprint)
		_, _ = fmt.Fprintf(stdout, "%s\n", pubKey)
	} else {
		_, _ = fmt.Fprintf(stdout, "To export your public key:\n")
		_, _ = fmt.Fprintf(stdout, "  gpg --armor --export %s\n\n", fingerprint)
	}

	_, _ = fmt.Fprintf(stdout, "To export your secret key (keep this safe!):\n")
	_, _ = fmt.Fprintf(stdout, "  gpg --armor --export-secret-keys %s\n", fingerprint)
	_, _ = fmt.Fprintf(stdout, "  WARNING: Never share your secret key. Store it securely.\n\n")

	_, _ = fmt.Fprintf(stdout, "Next step - login to dotsecenv:\n")
	_, _ = fmt.Fprintf(stdout, "  dotsecenv login %s\n", fingerprint)

	return nil
}

func generateGPGKeyStandalone(template string) (string, *Error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--batch", "--generate-key")
	cmd.Stdin = strings.NewReader(template)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to generate GPG key: %v\n%s", err, stderr.String()), ExitGPGError)
	}

	return getLatestKeyFingerprintStandalone()
}

func getLatestKeyFingerprintStandalone() (string, *Error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--list-secret-keys", "--with-colons", "--keyid-format", "long")
	output, err := cmd.Output()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to list secret keys: %v", err), ExitGPGError)
	}

	var latestFingerprint string
	var latestCreation int64

	lines := strings.Split(string(output), "\n")
	var currentCreation int64
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "sec":
			if len(parts) > 5 {
				var creation int64
				_, _ = fmt.Sscanf(parts[5], "%d", &creation)
				currentCreation = creation
			}
		case "fpr":
			if len(parts) >= 10 && parts[9] != "" {
				if currentCreation > latestCreation {
					latestCreation = currentCreation
					latestFingerprint = parts[9]
				}
			}
		}
	}

	if latestFingerprint == "" {
		return "", NewError("could not find fingerprint of generated key", ExitGPGError)
	}

	return latestFingerprint, nil
}

func exportPublicKeyStandalone(fingerprint string) (string, error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--armor", "--export", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to export public key: %w", err)
	}
	return string(output), nil
}

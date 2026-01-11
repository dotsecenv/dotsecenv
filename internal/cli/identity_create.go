package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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
	NoPassphrase bool   // If true, create key without passphrase (for CI/automation)
}

// identityCreateIO holds the I/O streams for identity creation.
type identityCreateIO struct {
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader
}

// IdentityCreate generates a new GPG key or outputs the generation template.
func (c *CLI) IdentityCreate(opts IdentityCreateOptions) *Error {
	io := &identityCreateIO{
		stdout: c.output.Stdout(),
		stderr: c.output.Stderr(),
		stdin:  c.stdin,
	}

	return identityCreateCore(opts, &c.config, io)
}

// IdentityCreateStandalone runs identity create without requiring full CLI initialization.
// This is used when no config exists yet.
func IdentityCreateStandalone(opts IdentityCreateOptions, stdout, stderr, stdin *os.File) *Error {
	// Ensure GPG program is configured (use PATH lookup for standalone mode)
	if err := gpg.ValidateAndSetGPGProgram("PATH"); err != nil {
		return NewError(fmt.Sprintf("GPG not found: %v", err), ExitGPGError)
	}

	io := &identityCreateIO{
		stdout: stdout,
		stderr: stderr,
		stdin:  stdin,
	}

	// Use default config for algorithm validation
	cfg := config.DefaultConfig()

	return identityCreateCore(opts, &cfg, io)
}

// identityCreateCore contains the shared logic for identity creation.
func identityCreateCore(opts IdentityCreateOptions, cfg *config.Config, io *identityCreateIO) *Error {
	// Parse and validate algorithm
	algo, parseErr := gpg.ParseAlgorithm(opts.Algorithm)
	if parseErr != nil {
		return NewError(parseErr.Error(), ExitGeneralError)
	}

	// Validate algorithm against config's approved_algorithms
	algoStr, bits := gpg.GetAlgorithmForValidation(algo)
	if !cfg.IsAlgorithmAllowed(algoStr, bits) {
		return NewError(fmt.Sprintf("algorithm '%s' is not allowed by your configuration\n\n%s\n\nTo use %s, add it to your config's approved_algorithms.\nSee https://dotsecenv.com/concepts/compliance/ for more details.",
			opts.Algorithm, cfg.GetAllowedAlgorithmsString(), opts.Algorithm), ExitAlgorithmNotAllowed)
	}

	// Validate --no-passphrase requires --name and --email
	if opts.NoPassphrase && (opts.Name == "" || opts.Email == "") {
		return NewError("--no-passphrase requires --name and --email flags", ExitGeneralError)
	}

	// Print algorithm before prompting for interactive input
	if opts.Name == "" || opts.Email == "" {
		_, _ = fmt.Fprintf(io.stdout, "Generating %s key...\n", opts.Algorithm)
	}

	// Prompt for name if not provided
	name := opts.Name
	if name == "" {
		var err error
		name, err = promptForInputWith(io.stderr, io.stdin, "Enter your full name: ")
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
		email, err = promptForInputWith(io.stderr, io.stdin, "Enter your email address: ")
		if err != nil {
			return NewError(fmt.Sprintf("failed to read email: %v", err), ExitGeneralError)
		}
		if email == "" {
			return NewError("email cannot be empty", ExitGeneralError)
		}
	}

	// Build template options
	templateOpts := &gpg.KeyTemplateOptions{
		NoPassphrase: opts.NoPassphrase,
	}

	// Generate the template
	template, templateErr := gpg.GenerateKeyTemplate(algo, name, email, templateOpts)
	if templateErr != nil {
		return NewError(fmt.Sprintf("failed to generate template: %v", templateErr), ExitGeneralError)
	}

	// If template-only mode, print shell-friendly wrapper
	if opts.TemplateOnly {
		printTemplateOutput(io.stdout, opts.Algorithm, template)
		return nil
	}

	// Generate the key using GPG
	_, _ = fmt.Fprintf(io.stdout, "Generating %s key for %s <%s>...\n", opts.Algorithm, name, email)
	if opts.NoPassphrase {
		_, _ = fmt.Fprintf(io.stderr, "WARNING: Creating key without passphrase. Only use for CI/automation.\n\n")
	} else {
		_, _ = fmt.Fprintf(io.stdout, "GPG will prompt for a passphrase to protect your key.\n\n")
	}

	fingerprint, genErr := generateGPGKeyWithTemplate(template)
	if genErr != nil {
		return genErr
	}

	// Print success output
	printSuccessOutput(io.stdout, name, email, opts.Algorithm, fingerprint)

	return nil
}

// promptForInputWith prompts the user for input and returns the trimmed response.
func promptForInputWith(w io.Writer, r io.Reader, prompt string) (string, error) {
	_, _ = fmt.Fprint(w, prompt)
	reader := bufio.NewReader(r)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// printTemplateOutput prints the shell-friendly template wrapper.
func printTemplateOutput(w io.Writer, algorithm, template string) {
	_, _ = fmt.Fprintf(w, "#!/bin/bash\n")
	_, _ = fmt.Fprintf(w, "# GPG Key Generation Template\n")
	_, _ = fmt.Fprintf(w, "# Algorithm: %s\n", algorithm)
	_, _ = fmt.Fprintf(w, "#\n")
	_, _ = fmt.Fprintf(w, "# Run: bash <this-file> OR pipe to bash\n\n")
	_, _ = fmt.Fprintf(w, "TEMPLATE_FILE=$(mktemp)\n")
	_, _ = fmt.Fprintf(w, "cat > \"$TEMPLATE_FILE\" << 'DOTSECENV_TEMPLATE'\n")
	_, _ = fmt.Fprintf(w, "%s", template)
	_, _ = fmt.Fprintf(w, "DOTSECENV_TEMPLATE\n\n")
	_, _ = fmt.Fprintf(w, "echo \"Template: $TEMPLATE_FILE\"\n")
	_, _ = fmt.Fprintf(w, "gpg --batch --generate-key \"$TEMPLATE_FILE\"\n")
}

// printSuccessOutput prints the success message and next steps.
func printSuccessOutput(w io.Writer, name, email, algorithm, fingerprint string) {
	_, _ = fmt.Fprintf(w, "\nKey generation successful!\n\n")
	_, _ = fmt.Fprintf(w, "Created GPG key for %s <%s>\n", name, email)
	_, _ = fmt.Fprintf(w, "  Algorithm:   %s\n", algorithm)
	_, _ = fmt.Fprintf(w, "  Fingerprint: %s\n\n", fingerprint)

	// Export and display the public key
	pubKey, pubKeyErr := exportPublicKeyByFingerprint(fingerprint)
	if pubKeyErr == nil {
		_, _ = fmt.Fprintf(w, "To export your public key:\n")
		_, _ = fmt.Fprintf(w, "  gpg --armor --export %s\n", fingerprint)
		_, _ = fmt.Fprintf(w, "%s\n", pubKey)
	} else {
		_, _ = fmt.Fprintf(w, "To export your public key:\n")
		_, _ = fmt.Fprintf(w, "  gpg --armor --export %s\n\n", fingerprint)
	}

	_, _ = fmt.Fprintf(w, "To export your secret key (keep this safe!):\n")
	_, _ = fmt.Fprintf(w, "  gpg --armor --export-secret-keys %s\n", fingerprint)
	_, _ = fmt.Fprintf(w, "  WARNING: Never share your secret key. Store it securely.\n\n")

	_, _ = fmt.Fprintf(w, "Next step - login to dotsecenv:\n")
	_, _ = fmt.Fprintf(w, "  dotsecenv login %s\n", fingerprint)
}

// generateGPGKeyWithTemplate generates a GPG key using the provided template.
// Returns the fingerprint of the generated key.
func generateGPGKeyWithTemplate(template string) (string, *Error) {
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
	return getLatestSecretKeyFingerprint()
}

// getLatestSecretKeyFingerprint gets the fingerprint of the most recently created secret key.
func getLatestSecretKeyFingerprint() (string, *Error) {
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

// exportPublicKeyByFingerprint exports the public key in ASCII armor format.
func exportPublicKeyByFingerprint(fingerprint string) (string, error) {
	cmd := exec.Command(gpg.GetGPGProgram(), "--armor", "--export", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to export public key: %w", err)
	}
	return string(output), nil
}

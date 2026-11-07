package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ErrPinentryRequired identifies an operation that needs pinentry while prompting is disabled.
var ErrPinentryRequired = errors.New("GPG_ERR_NO_PIN_ENTRY: GPG requires pinentry, but --no-pinentry disables it.\n\n" +
	"Complete the required GPG unlock in a separate terminal using the same GPG home, then retry.\n" +
	"If your GPG policy requires interaction for every operation, perform the operation directly outside the agent session")

// runWithAgent executes a private-key operation under this client's pinentry policy.
func (c *GPGClient) runWithAgent(args []string, input []byte) ([]byte, error) {
	args = append(args, "--status-fd=2")
	if c.NoPinentry {
		args = append(args, "--pinentry-mode=error", "--batch", "--no-tty")
	}
	cmd := exec.Command(GetGPGProgram(), args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	result, err := cmd.Output()
	if err == nil {
		return result, nil
	}

	pinentryRequired := false
	for _, line := range strings.Split(stderr.String(), "\n") {
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || (fields[1] != "ERROR" && fields[1] != "FAILURE") {
			continue
		}
		code, _, _ := strings.Cut(fields[3], "_")
		number, parseErr := strconv.ParseUint(code, 10, 32)
		// libgpg-error stores the error source above the low 16-bit error code.
		// GPG_ERR_NO_PIN_ENTRY is 85.
		if (parseErr == nil && number&0xffff == 85) || fields[3] == "NO_PIN_ENTRY" {
			pinentryRequired = true
		}
	}
	if c.NoPinentry && pinentryRequired {
		err = ErrPinentryRequired
	}
	if message := strings.TrimSpace(stderr.String()); message != "" {
		return nil, fmt.Errorf("%w\nGPG error: %s", err, message)
	}
	return nil, fmt.Errorf("GPG operation failed: %w", err)
}

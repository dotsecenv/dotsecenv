package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ErrUserCancelled is returned when the user cancels an interactive prompt (Ctrl-C or Escape)
var ErrUserCancelled = errors.New("cancelled by user")

// selectVaultFromTTY implements a simple list selection using raw terminal mode.
// It reads input from the provided tty file and writes output to stdout.
// Returns the selected index, or ErrUserCancelled if the user presses Ctrl-C or Escape.
func selectVaultFromTTY(options []string, tty *os.File) (int, error) {
	fd := int(tty.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return 0, fmt.Errorf("failed to make raw: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	const (
		HideCursor = "\033[?25l"
		ShowCursor = "\033[?25h"
	)

	fmt.Print(HideCursor)
	defer fmt.Print(ShowCursor)

	current := 0

	render := func() {
		for i, opt := range options {
			if i == current {
				fmt.Printf("\r> %s\r\n", opt)
			} else {
				fmt.Printf("\r  %s\r\n", opt)
			}
		}
		if len(options) > 0 {
			fmt.Printf("\033[%dA", len(options))
		}
	}

	render()

	buf := make([]byte, 3)
	for {
		n, err := tty.Read(buf)
		if err != nil {
			return 0, err
		}

		// Handle Ctrl-C (0x03)
		if n >= 1 && buf[0] == 3 {
			fmt.Printf("\033[%dB", len(options))
			return 0, ErrUserCancelled
		}

		// Handle Escape key (0x1B alone, not part of arrow key sequence)
		if n == 1 && buf[0] == 27 {
			fmt.Printf("\033[%dB", len(options))
			return 0, ErrUserCancelled
		}

		if n == 1 && (buf[0] == '\n' || buf[0] == '\r') {
			fmt.Printf("\033[%dB", len(options))
			return current, nil
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
			switch buf[2] {
			case 65: // Up
				if current > 0 {
					current--
					render()
				}
			case 66: // Down
				if current < len(options)-1 {
					current++
					render()
				}
			}
		}
	}
}

// HandleInteractiveSelection prompts the user to select from options and handles cancellation uniformly.
// It opens /dev/tty directly for input, allowing interactive selection even when stdin is piped.
// Returns the selected index and nil on success, or writes "Cancelled." to stderr and returns an error on cancellation.
func HandleInteractiveSelection(options []string, prompt string, stderr io.Writer) (int, *Error) {
	// Open /dev/tty directly to support interactive selection even when stdin is piped
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return 0, NewError("multiple vaults configured and no terminal available; please specify target vault using -v", ExitGeneralError)
	}
	defer func() { _ = tty.Close() }()

	fd := int(tty.Fd())
	if !term.IsTerminal(fd) {
		return 0, NewError("multiple vaults configured and no terminal available; please specify target vault using -v", ExitGeneralError)
	}

	_, _ = fmt.Fprintf(stderr, "%s\n", prompt)

	idx, err := selectVaultFromTTY(options, tty)
	if err != nil {
		if errors.Is(err, ErrUserCancelled) {
			_, _ = fmt.Fprintf(stderr, "\nCancelled.\n")
			return 0, NewError("", ExitGeneralError)
		}
		return 0, NewError(fmt.Sprintf("selection failed: %v", err), ExitGeneralError)
	}
	return idx, nil
}

// PromptConfirm asks the user for a y/n confirmation.
// Returns true if confirmed, false if declined, or an error on cancellation.
// Opens /dev/tty directly to work even when stdin is piped.
func PromptConfirm(prompt string, stderr io.Writer) (bool, *Error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false, NewError("no terminal available for confirmation", ExitGeneralError)
	}
	defer func() { _ = tty.Close() }()

	fd := int(tty.Fd())
	if !term.IsTerminal(fd) {
		return false, NewError("no terminal available for confirmation", ExitGeneralError)
	}

	_, _ = fmt.Fprintf(stderr, "%s [y/N]: ", prompt)

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return false, NewError(fmt.Sprintf("failed to set raw mode: %v", err), ExitGeneralError)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	buf := make([]byte, 1)
	for {
		_, err := tty.Read(buf)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "\r\n")
			return false, NewError(fmt.Sprintf("failed to read input: %v", err), ExitGeneralError)
		}

		switch buf[0] {
		case 'y', 'Y':
			_, _ = fmt.Fprintf(stderr, "y\r\n")
			return true, nil
		case 'n', 'N', '\r', '\n':
			_, _ = fmt.Fprintf(stderr, "n\r\n")
			return false, nil
		case 3, 27: // Ctrl-C or Escape
			_, _ = fmt.Fprintf(stderr, "\r\nCancelled.\r\n")
			return false, NewError("", ExitGeneralError)
		}
	}
}

package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Handler manages output emission based on mode and format.
// It supports silent mode (suppress warnings) and JSON mode (envelope output).
type Handler struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	silent   bool
	json     bool
	warnings []*Warning
}

// HandlerOption configures a Handler.
type HandlerOption func(*Handler)

// WithSilent sets silent mode (suppress warning output to stderr).
func WithSilent(silent bool) HandlerOption {
	return func(h *Handler) {
		h.silent = silent
	}
}

// WithJSON sets JSON output mode.
func WithJSON(json bool) HandlerOption {
	return func(h *Handler) {
		h.json = json
	}
}

// WithStdin sets the stdin reader.
func WithStdin(stdin io.Reader) HandlerOption {
	return func(h *Handler) {
		h.stdin = stdin
	}
}

// NewHandler creates a new output handler with the given writers and options.
func NewHandler(stdout, stderr io.Writer, opts ...HandlerOption) *Handler {
	h := &Handler{
		stdout:   stdout,
		stderr:   stderr,
		warnings: make([]*Warning, 0),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Warn emits a warning. In text mode, it prints immediately (unless silent).
// In JSON mode, warnings are collected for the envelope.
func (h *Handler) Warn(w *Warning) {
	h.warnings = append(h.warnings, w)

	if !h.silent && !h.json {
		// Immediate emission for text mode
		_, _ = fmt.Fprintf(h.stderr, "warning: %s\n", w.Message)
	}
}

// Warnf creates and emits a warning with a formatted message.
func (h *Handler) Warnf(code Code, format string, args ...interface{}) {
	h.Warn(NewWarningf(code, format, args...))
}

// WarnWithDetails creates and emits a warning with metadata.
func (h *Handler) WarnWithDetails(code Code, message string, details map[string]interface{}) {
	w := NewWarning(code, message).WithDetails(details)
	h.Warn(w)
}

// Error emits an error to stderr (text mode only).
// In JSON mode, errors are included in the envelope via WriteJSON.
func (h *Handler) Error(e *Error) {
	if h.json {
		// Errors collected for envelope
		return
	}
	_, _ = fmt.Fprintf(h.stderr, "%s\n", e.Message)
}

// Errorf creates and emits an error with a formatted message.
func (h *Handler) Errorf(code Code, format string, args ...interface{}) {
	h.Error(NewErrorf(code, format, args...))
}

// Success emits a success message to stdout (text mode only).
func (h *Handler) Success(message string) {
	if !h.json {
		_, _ = fmt.Fprintf(h.stdout, "%s\n", message)
	}
}

// Successf emits a formatted success message to stdout.
func (h *Handler) Successf(format string, args ...interface{}) {
	h.Success(fmt.Sprintf(format, args...))
}

// WriteData writes data output to stdout (text mode only).
// Does not add a newline; caller is responsible for formatting.
func (h *Handler) WriteData(format string, args ...interface{}) {
	if !h.json {
		_, _ = fmt.Fprintf(h.stdout, format, args...)
	}
}

// WriteLine writes a line of output to stdout (text mode only).
// Ensures message ends with newline.
func (h *Handler) WriteLine(message string) {
	if !h.json {
		if !strings.HasSuffix(message, "\n") {
			message += "\n"
		}
		_, _ = fmt.Fprint(h.stdout, message)
	}
}

// WriteJSON writes the JSON envelope with collected warnings and optional error.
// This is the primary output method for JSON mode.
func (h *Handler) WriteJSON(data interface{}, err *Error) error {
	env := NewEnvelope(data)
	env.AddWarnings(h.warnings)
	if err != nil {
		env.SetError(err)
	}
	return env.WriteTo(h.stdout, true)
}

// WriteJSONError writes a JSON envelope containing only an error.
func (h *Handler) WriteJSONError(err *Error) error {
	return h.WriteJSON(nil, err)
}

// GetWarnings returns collected warnings.
func (h *Handler) GetWarnings() []*Warning {
	return h.warnings
}

// ClearWarnings resets the warning collection.
func (h *Handler) ClearWarnings() {
	h.warnings = make([]*Warning, 0)
}

// WarningCount returns the number of collected warnings.
func (h *Handler) WarningCount() int {
	return len(h.warnings)
}

// IsJSON returns whether JSON mode is enabled.
func (h *Handler) IsJSON() bool {
	return h.json
}

// IsSilent returns whether silent mode is enabled.
func (h *Handler) IsSilent() bool {
	return h.silent
}

// IsTerminal returns true if stdin is connected to an interactive terminal.
func (h *Handler) IsTerminal() bool {
	if f, ok := h.stdin.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

// Stdout returns the stdout writer.
func (h *Handler) Stdout() io.Writer {
	return h.stdout
}

// Stderr returns the stderr writer.
func (h *Handler) Stderr() io.Writer {
	return h.stderr
}

// Stdin returns the stdin reader.
func (h *Handler) Stdin() io.Reader {
	return h.stdin
}

// Clone creates a new handler with the same settings but fresh warning collection.
// Useful for per-command handlers.
func (h *Handler) Clone() *Handler {
	return &Handler{
		stdin:    h.stdin,
		stdout:   h.stdout,
		stderr:   h.stderr,
		silent:   h.silent,
		json:     h.json,
		warnings: make([]*Warning, 0),
	}
}

// WithJSONMode returns a new handler with JSON mode set.
// The new handler shares stdout/stderr but has fresh warning collection.
func (h *Handler) WithJSONMode(enabled bool) *Handler {
	return &Handler{
		stdin:    h.stdin,
		stdout:   h.stdout,
		stderr:   h.stderr,
		silent:   h.silent,
		json:     enabled,
		warnings: make([]*Warning, 0),
	}
}

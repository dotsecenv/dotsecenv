package secenvpicker

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
)

// Run launches the picker on the controlling terminal (/dev/tty), so it works
// even when stdin or stdout are redirected, matching the older raw-terminal
// prompts. targetPath is shown on the Apply tab. The returned
// Result has Confirmed=false when the user cancels. An error means no terminal
// was available, letting the caller fall back to batch mode.
func Run(tabs []VaultTab, targetPath string) (Result, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Result{}, fmt.Errorf("no controlling terminal available: %w", err)
	}
	defer func() { _ = tty.Close() }()

	p := tea.NewProgram(
		newModel(tabs, targetPath),
		tea.WithInput(tty),
		tea.WithOutput(tty),
	)
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	m, ok := final.(Model)
	if !ok {
		return Result{}, fmt.Errorf("unexpected final model type %T", final)
	}
	return m.result, nil
}

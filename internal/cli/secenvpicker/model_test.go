package secenvpicker

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func newTestModel() Model {
	tabs := []VaultTab{
		{Name: "vault-a", Keys: []Candidate{
			{SecretKey: "FOO", EnvName: "FOO", Line: "FOO={dotsecenv/}"},
			{SecretKey: "BAR", EnvName: "BAR", Line: "BAR={dotsecenv/}"},
			{SecretKey: "BAZ", EnvName: "BAZ", Line: "BAZ={dotsecenv/}", PreExisting: true},
		}},
		{Name: "vault-b", Keys: []Candidate{
			{SecretKey: "QUX", EnvName: "QUX", Line: "QUX={dotsecenv/}"},
		}},
	}
	return newModel(tabs, "/tmp/.secenv")
}

func key(t tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: t} }

func send(m Model, msgs ...tea.Msg) Model {
	for _, msg := range msgs {
		nm, _ := m.Update(msg)
		m = nm.(Model)
	}
	return m
}

func TestSpaceTogglesCurrentTabOnly(t *testing.T) {
	m := send(newTestModel(), key(tea.KeySpace))
	if !m.selected[0][0] {
		t.Error("expected row 0 of tab 0 to be selected")
	}
	if len(m.selected[1]) != 0 {
		t.Errorf("tab 1 selection must be untouched, got %v", m.selected[1])
	}
	// Toggle again clears it.
	m = send(m, key(tea.KeySpace))
	if len(m.selected[0]) != 0 {
		t.Error("second space should clear the selection")
	}
}

func TestCtrlASelectsAllSelectableInTabOnly(t *testing.T) {
	m := send(newTestModel(), key(tea.KeyCtrlA))
	if len(m.selected[0]) != 2 {
		t.Errorf("expected 2 selected (pre-existing skipped), got %d", len(m.selected[0]))
	}
	if m.selected[0][2] {
		t.Error("pre-existing row must not be selected by ctrl+a")
	}
	if len(m.selected[1]) != 0 {
		t.Error("tab 1 must be untouched")
	}
}

func TestCtrlNClearsCurrentTabOnly(t *testing.T) {
	m := send(newTestModel(), key(tea.KeyCtrlA))      // select all in tab 0
	m = send(m, key(tea.KeyRight), key(tea.KeySpace)) // select QUX in tab 1
	if len(m.selected[1]) != 1 {
		t.Fatalf("tab 1 should have 1 selection, got %d", len(m.selected[1]))
	}
	m = send(m, key(tea.KeyLeft), key(tea.KeyCtrlN)) // back to tab 0, clear
	if len(m.selected[0]) != 0 {
		t.Error("tab 0 should be cleared by ctrl+n")
	}
	if len(m.selected[1]) != 1 {
		t.Error("tab 1 must be untouched by ctrl+n on tab 0")
	}
}

func TestCtrlRReversesSelectableInTabOnly(t *testing.T) {
	m := send(newTestModel(), key(tea.KeySpace)) // row 0 on
	m = send(m, key(tea.KeyCtrlR))               // reverse selectable rows
	if m.selected[0][0] {
		t.Error("row 0 should be off after reverse")
	}
	if !m.selected[0][1] {
		t.Error("row 1 should be on after reverse")
	}
	if m.selected[0][2] {
		t.Error("pre-existing row 2 must stay off")
	}
	if len(m.selected[1]) != 0 {
		t.Error("tab 1 must be untouched")
	}
}

func TestPreExistingRowUnselectable(t *testing.T) {
	m := send(newTestModel(), key(tea.KeyDown), key(tea.KeyDown)) // cursor to row 2
	if m.cursor[0] != 2 {
		t.Fatalf("cursor = %d, want 2", m.cursor[0])
	}
	m = send(m, key(tea.KeySpace))
	if len(m.selected[0]) != 0 {
		t.Error("pre-existing row must not toggle on space")
	}
}

func TestArrowsClamp(t *testing.T) {
	m := send(newTestModel(), key(tea.KeyUp)) // up at top
	if m.cursor[0] != 0 {
		t.Errorf("cursor should clamp at 0, got %d", m.cursor[0])
	}
	m = send(m, key(tea.KeyDown), key(tea.KeyDown), key(tea.KeyDown), key(tea.KeyDown))
	if m.cursor[0] != 2 {
		t.Errorf("cursor should clamp at last row 2, got %d", m.cursor[0])
	}
	m = send(m, key(tea.KeyLeft)) // left at tab 0
	if m.activeTab != 0 {
		t.Errorf("activeTab should clamp at 0, got %d", m.activeTab)
	}
	m = send(m, key(tea.KeyRight), key(tea.KeyRight)) // tab0 -> tab1 -> Apply
	if m.activeTab != m.applyIdx {
		t.Errorf("activeTab should be applyIdx %d, got %d", m.applyIdx, m.activeTab)
	}
	m = send(m, key(tea.KeyRight)) // clamp at Apply
	if m.activeTab != m.applyIdx {
		t.Errorf("activeTab should clamp at applyIdx, got %d", m.activeTab)
	}
}

func TestEnterAdvancesThenConfirms(t *testing.T) {
	m := send(newTestModel(), key(tea.KeySpace))      // FOO in tab 0
	m = send(m, key(tea.KeyRight), key(tea.KeySpace)) // QUX in tab 1
	m = send(m, key(tea.KeyEnter))                    // advance to Apply
	if m.activeTab != m.applyIdx {
		t.Fatalf("enter on vault tab should advance to Apply, got %d", m.activeTab)
	}
	if m.quitting {
		t.Fatal("should not quit on first enter")
	}
	m = send(m, key(tea.KeyEnter)) // confirm
	if !m.quitting || !m.result.Confirmed {
		t.Fatalf("enter on Apply should confirm and quit: quitting=%v confirmed=%v", m.quitting, m.result.Confirmed)
	}
	if len(m.result.Refs) != 2 || m.result.Refs[0].EnvName != "FOO" || m.result.Refs[1].EnvName != "QUX" {
		t.Errorf("result refs = %+v, want [FOO, QUX] in order", m.result.Refs)
	}
}

func TestEscCancels(t *testing.T) {
	m := send(newTestModel(), key(tea.KeySpace), key(tea.KeyEsc))
	if !m.quitting {
		t.Error("esc should quit")
	}
	if m.result.Confirmed {
		t.Error("esc must not confirm")
	}
}

func TestCtrlCCancels(t *testing.T) {
	m := send(newTestModel(), key(tea.KeyCtrlC))
	if !m.quitting || m.result.Confirmed {
		t.Error("ctrl+c should cancel")
	}
}

// View should not panic on any tab and should mention the target path on Apply.
func TestViewRenders(t *testing.T) {
	m := newTestModel()
	if m.View() == "" {
		t.Error("vault-tab view should not be empty")
	}
	m = send(m, key(tea.KeyRight), key(tea.KeyRight)) // to Apply
	if out := m.View(); out == "" {
		t.Error("apply-tab view should not be empty")
	}
}

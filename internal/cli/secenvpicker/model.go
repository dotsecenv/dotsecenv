// Package secenvpicker is the bubbletea TUI for choosing which vault secrets to
// wire into a .secenv file. The Model holds plain data (vault tabs, per-tab
// selection) and knows nothing about vaults or the filesystem, so it can be
// driven and tested with tea.KeyMsg values alone. The terminal wiring lives in
// run.go.
package secenvpicker

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Candidate is one selectable secret: its vault key, the env-var name it would
// bind, the rendered .secenv line, and whether it is already present (in which
// case it is shown but not selectable).
type Candidate struct {
	SecretKey   string
	EnvName     string
	Line        string
	PreExisting bool
}

// VaultTab is one tab in the picker: a vault and its secret keys.
type VaultTab struct {
	Name string
	Keys []Candidate
}

// Result is what the picker returns. Confirmed is false when the user cancels.
type Result struct {
	Confirmed bool
	Refs      []Candidate
}

// Model is the bubbletea model. Selection is tracked per tab, which is what
// keeps ctrl+a/n/r scoped to the active tab without disturbing the others.
type Model struct {
	tabs       []VaultTab
	targetPath string         // shown on the Apply tab
	activeTab  int            // 0..applyIdx; applyIdx is the synthetic "Apply" tab
	applyIdx   int            // == len(tabs)
	cursor     []int          // per-tab cursor row
	selected   []map[int]bool // per-tab selection, keyed by row index
	width      int
	result     Result
	quitting   bool
}

func newModel(tabs []VaultTab, targetPath string) Model {
	cursor := make([]int, len(tabs))
	selected := make([]map[int]bool, len(tabs))
	for i := range tabs {
		selected[i] = make(map[int]bool)
	}
	return Model{
		tabs:       tabs,
		targetPath: targetPath,
		applyIdx:   len(tabs),
		cursor:     cursor,
		selected:   selected,
	}
}

func (m Model) onVaultTab() bool { return m.activeTab < m.applyIdx }
func (m Model) onApplyTab() bool { return m.activeTab == m.applyIdx }

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.result = Result{Confirmed: false}
			m.quitting = true
			return m, tea.Quit

		case "left":
			if m.activeTab > 0 {
				m.activeTab--
			}

		case "right":
			if m.activeTab < m.applyIdx {
				m.activeTab++
			}

		case "up":
			if m.onVaultTab() && m.cursor[m.activeTab] > 0 {
				m.cursor[m.activeTab]--
			}

		case "down":
			if m.onVaultTab() {
				if last := len(m.tabs[m.activeTab].Keys) - 1; m.cursor[m.activeTab] < last {
					m.cursor[m.activeTab]++
				}
			}

		case " ":
			if m.onVaultTab() {
				m.toggleCurrent()
			}

		case "ctrl+a":
			if m.onVaultTab() {
				m.selectAll(m.activeTab)
			}

		case "ctrl+n":
			if m.onVaultTab() {
				m.selectNone(m.activeTab)
			}

		case "ctrl+r":
			if m.onVaultTab() {
				m.reverse(m.activeTab)
			}

		case "enter":
			if m.onApplyTab() {
				m.result = m.collectResult()
				m.quitting = true
				return m, tea.Quit
			}
			m.activeTab = m.applyIdx
		}
	}
	return m, nil
}

func (m *Model) toggleCurrent() {
	t := m.activeTab
	i := m.cursor[t]
	if i < 0 || i >= len(m.tabs[t].Keys) || m.tabs[t].Keys[i].PreExisting {
		return
	}
	if m.selected[t][i] {
		delete(m.selected[t], i)
	} else {
		m.selected[t][i] = true
	}
}

func (m *Model) selectAll(t int) {
	for i, c := range m.tabs[t].Keys {
		if !c.PreExisting {
			m.selected[t][i] = true
		}
	}
}

func (m *Model) selectNone(t int) {
	m.selected[t] = make(map[int]bool)
}

func (m *Model) reverse(t int) {
	for i, c := range m.tabs[t].Keys {
		if c.PreExisting {
			continue
		}
		if m.selected[t][i] {
			delete(m.selected[t], i)
		} else {
			m.selected[t][i] = true
		}
	}
}

// collectResult walks every tab's selection in (tab, row) order.
func (m Model) collectResult() Result {
	var refs []Candidate
	for t := range m.tabs {
		for i, c := range m.tabs[t].Keys {
			if m.selected[t][i] {
				refs = append(refs, c)
			}
		}
	}
	return Result{Confirmed: true, Refs: refs}
}

var (
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Padding(0, 1).Foreground(lipgloss.Color("212"))
	inactiveTabStyle = lipgloss.NewStyle().Padding(0, 1).Faint(true)
	dimStyle         = lipgloss.NewStyle().Faint(true)
	cursorRowStyle   = lipgloss.NewStyle().Bold(true)
	headerStyle      = lipgloss.NewStyle().Bold(true)
	helpStyle        = lipgloss.NewStyle().Faint(true)
)

// View implements tea.Model.
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")
	if m.onApplyTab() {
		b.WriteString(m.renderApply())
	} else {
		b.WriteString(m.renderList())
	}
	b.WriteString("\n\n")
	b.WriteString(m.renderFooter())
	b.WriteString("\n")
	return b.String()
}

func (m Model) renderTabs() string {
	style := func(active bool) lipgloss.Style {
		if active {
			return activeTabStyle
		}
		return inactiveTabStyle
	}
	parts := make([]string, 0, len(m.tabs)+1)
	for i, t := range m.tabs {
		parts = append(parts, style(i == m.activeTab).Render(t.Name))
	}
	parts = append(parts, style(m.onApplyTab()).Render("Apply"))
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m Model) renderList() string {
	t := m.activeTab
	keys := m.tabs[t].Keys
	if len(keys) == 0 {
		return dimStyle.Render("  (no secrets in this vault)")
	}
	var b strings.Builder
	for i, c := range keys {
		cursor := "  "
		if i == m.cursor[t] {
			cursor = "> "
		}
		var row string
		switch {
		case c.PreExisting:
			row = dimStyle.Render(fmt.Sprintf("[-] %s  (already in .secenv)", c.Line))
		default:
			box := "[ ]"
			if m.selected[t][i] {
				box = "[x]"
			}
			row = fmt.Sprintf("%s %s", box, c.Line)
			if i == m.cursor[t] {
				row = cursorRowStyle.Render(row)
			}
		}
		b.WriteString(cursor + row + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m Model) renderApply() string {
	sel := m.collectResult().Refs
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("Will append to %s:", m.targetPath)))
	b.WriteString("\n\n")
	if len(sel) == 0 {
		b.WriteString(dimStyle.Render("  (nothing selected)"))
		return b.String()
	}
	for _, c := range sel {
		b.WriteString("  " + c.Line + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m Model) renderFooter() string {
	if m.onApplyTab() {
		return helpStyle.Render("enter confirm · esc cancel · ←/→ back")
	}
	return helpStyle.Render("←/→ tabs · ↑/↓ move · space toggle · ^a all · ^n none · ^r reverse · enter ▸ Apply · esc cancel")
}

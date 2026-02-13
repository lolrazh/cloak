package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7C3AED")).
			Align(lipgloss.Center)

	connectedDot   = lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E")).Render("●")
	disconnectedDot = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render("●")

	labelStyle = lipgloss.NewStyle().
			Width(14).
			Foreground(lipgloss.Color("#A1A1AA"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F4F4F5"))

	activeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#22C55E"))

	inactiveStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#71717A")).
			Align(lipgloss.Center)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3F3F46")).
			Padding(1, 2)
)

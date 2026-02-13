// Package tui implements the Bubble Tea dashboard for Cloak.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/status"
	"github.com/lolrazh/cloak/internal/tunnel"
)

const pollInterval = 2 * time.Second

// Model is the Bubble Tea model for the dashboard.
type Model struct {
	info    status.Info
	cfg     *config.Config
	spinner spinner.Model
	width   int
	height  int
	busy    bool // true while connecting/disconnecting
	busyMsg string
	err     error
}

// tickMsg triggers a status poll.
type tickMsg time.Time

// statusMsg carries a fresh status snapshot.
type statusMsg status.Info

// actionDoneMsg signals a connect/disconnect finished.
type actionDoneMsg struct{ err error }

// NewModel creates the initial dashboard model.
func NewModel(cfg *config.Config) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED"))

	return Model{
		cfg:     cfg,
		spinner: s,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		pollStatus(m.cfg),
		m.spinner.Tick,
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "c":
			if !m.busy && !m.info.Connected {
				m.busy = true
				m.busyMsg = "Connecting..."
				return m, doConnect(m.cfg)
			}
		case "d":
			if !m.busy && m.info.Connected {
				m.busy = true
				m.busyMsg = "Disconnecting..."
				return m, doDisconnect(m.cfg)
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case statusMsg:
		m.info = status.Info(msg)
		return m, tea.Tick(pollInterval, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})

	case tickMsg:
		return m, pollStatus(m.cfg)

	case actionDoneMsg:
		m.busy = false
		m.err = msg.err
		return m, pollStatus(m.cfg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	var content string

	// Title.
	title := titleStyle.Render("CLOAK VPN")

	// Status line.
	var statusLine string
	if m.info.PermErr != "" {
		statusLine = labelStyle.Render("Status:") + warnDot + " " + warnStyle.Render("Unknown ("+m.info.PermErr+")")
	} else if m.info.StatusErr != "" {
		statusLine = labelStyle.Render("Status:") + warnDot + " " + warnStyle.Render("Unknown ("+m.info.StatusErr+")")
	} else if m.info.Connected {
		statusLine = labelStyle.Render("Status:") + connectedDot + " " + valueStyle.Render("Connected")
	} else {
		statusLine = labelStyle.Render("Status:") + disconnectedDot + " " + valueStyle.Render("Disconnected")
	}

	// Details (only when connected).
	var details string
	if m.info.Connected {
		ip := labelStyle.Render("Public IP:") + valueStyle.Render(m.info.ExternalIP)
		latency := labelStyle.Render("Latency:")
		if m.info.Latency > 0 {
			latency += valueStyle.Render(fmt.Sprintf("%dms", m.info.Latency.Milliseconds()))
		} else {
			latency += valueStyle.Render("--")
		}
		transfer := labelStyle.Render("Transfer:") + valueStyle.Render(
			fmt.Sprintf("↑ %s  ↓ %s",
				status.FormatBytes(m.info.TxBytes),
				status.FormatBytes(m.info.RxBytes)))
		details = ip + "\n" + latency + "\n" + transfer
	}

	// Kill switch.
	var ksLine string
	if m.info.KillSwitchErr != "" {
		ksLine = labelStyle.Render("Kill Switch:") + warnStyle.Render("● Error ("+m.info.KillSwitchErr+")")
	} else if m.info.KillSwitch {
		ksLine = labelStyle.Render("Kill Switch:") + activeStyle.Render("● Active")
	} else {
		ksLine = labelStyle.Render("Kill Switch:") + inactiveStyle.Render("● Inactive")
	}

	// Busy indicator.
	var busyLine string
	if m.busy {
		busyLine = "\n" + m.spinner.View() + " " + m.busyMsg
	}

	// Error.
	var errLine string
	if m.err != nil {
		errLine = "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render(m.err.Error())
	}

	// Help.
	help := helpStyle.Render("[c] Connect  [d] Disconnect  [q] Quit")

	// Assemble.
	content = title + "\n\n" + statusLine + "\n"
	if details != "" {
		content += details + "\n"
	}
	content += ksLine + busyLine + errLine + "\n\n" + help

	box := borderStyle.Render(content)

	// Center in terminal.
	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		box)
}

// pollStatus returns a command that gathers fresh status.
func pollStatus(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var serverIP string
		if cfg.Server != nil {
			serverIP = cfg.Server.Host
		}
		info := status.Gather(serverIP)

		ks := killswitch.New()
		enabled, err := ks.IsEnabled()
		info.KillSwitch = enabled
		if err != nil {
			info.KillSwitchErr = compactErr(err)
		}

		return statusMsg(info)
	}
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	first := strings.TrimSpace(strings.SplitN(err.Error(), "\n", 2)[0])
	if first == "" {
		return "unknown error"
	}
	return first
}

// doConnect returns a command that brings the tunnel up.
func doConnect(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		confPath, err := config.WGConfPath()
		if err != nil {
			return actionDoneMsg{err: err}
		}
		mgr := tunnel.NewManager()

		// Check if already connected to avoid "already exists" errors from wg-quick.
		if up, _ := mgr.IsUp(); up {
			return actionDoneMsg{}
		}

		if err := mgr.Up(confPath); err != nil {
			return actionDoneMsg{err: err}
		}

		// Enable kill switch.
		if cfg.Server != nil {
			ks := killswitch.New()
			if err := ks.Enable(cfg.Server.Host, cfg.Port); err != nil {
				// Fail closed: if kill switch fails, tear down tunnel to avoid leaks.
				if downErr := mgr.Down(confPath); downErr != nil {
					return actionDoneMsg{err: fmt.Errorf("kill switch failed (%v) and rollback failed (%v); tunnel may still be up", err, downErr)}
				}
				return actionDoneMsg{err: fmt.Errorf("kill switch failed, tunnel was brought down: %w", err)}
			}
		}

		return actionDoneMsg{}
	}
}

// doDisconnect returns a command that tears down the tunnel.
func doDisconnect(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var ksErr error
		ks := killswitch.New()
		if err := ks.Disable(); err != nil {
			ksErr = err
		}

		confPath, err := config.WGConfPath()
		if err != nil {
			return actionDoneMsg{err: err}
		}
		mgr := tunnel.NewManager()
		if err := mgr.Down(confPath); err != nil {
			return actionDoneMsg{err: err}
		}

		// Report kill switch error after tunnel is down — teardown still happened.
		if ksErr != nil {
			return actionDoneMsg{err: fmt.Errorf("disconnected but kill switch disable failed: %w", ksErr)}
		}
		return actionDoneMsg{}
	}
}

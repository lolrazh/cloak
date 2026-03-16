// Package tui implements the Bubble Tea dashboard for Cloak.
package tui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/status"
	"github.com/lolrazh/cloak/internal/vpn"
)

const pollInterval = 2 * time.Second

// Model is the Bubble Tea model for the dashboard.
type Model struct {
	info     status.Info
	cfg      *config.Config
	spinner  spinner.Model
	width    int
	height   int
	busy     bool
	busyMsg  string
	err      error
	quitting bool
}

type tickMsg time.Time
type statusMsg status.Info
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
			m.quitting = true
			m.busy = true
			m.busyMsg = "Shutting down..."
			return m, doCleanQuit()
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
				return m, doDisconnect()
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
		if m.quitting {
			return m, tea.Quit
		}
		if msg.err == nil && m.busyMsg == "Connecting..." {
			m.info.Connected = true
		}
		if msg.err == nil && m.busyMsg == "Disconnecting..." {
			m.info.Connected = false
		}
		return m, pollStatus(m.cfg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	title := titleStyle.Render("CLOAK VPN")

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

	var ksLine string
	if m.info.KillSwitchErr != "" {
		ksLine = labelStyle.Render("Kill Switch:") + warnStyle.Render("● Error ("+m.info.KillSwitchErr+")")
	} else if m.info.KillSwitch {
		ksLine = labelStyle.Render("Kill Switch:") + activeStyle.Render("● Active")
	} else {
		ksLine = labelStyle.Render("Kill Switch:") + inactiveStyle.Render("● Inactive")
	}

	var busyLine string
	if m.busy {
		busyLine = "\n" + m.spinner.View() + " " + m.busyMsg
	}

	var errLine string
	if m.err != nil {
		errLine = "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render(m.err.Error())
	}

	help := helpStyle.Render("[c] Connect  [d] Disconnect  [q] Quit")

	content := title + "\n\n" + statusLine + "\n"
	if details != "" {
		content += details + "\n"
	}
	content += ksLine + busyLine + errLine + "\n\n" + help

	box := borderStyle.Render(content)

	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		box)
}

func pollStatus(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		exec.Command("sudo", "-n", "-v").Run()

		var serverIP, serverPublicKey string
		if cfg.Server != nil {
			serverIP = cfg.Server.Host
			serverPublicKey = cfg.Server.PublicKey
		}
		info := status.Gather(serverIP, serverPublicKey)

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

func checkSudo() error {
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		return fmt.Errorf("sudo expired — quit and run: sudo -v")
	}
	return nil
}

func doConnect(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		if err := checkSudo(); err != nil {
			return actionDoneMsg{err: err}
		}
		return actionDoneMsg{err: vpn.Connect(cfg)}
	}
}

func doDisconnect() tea.Cmd {
	return func() tea.Msg {
		if err := checkSudo(); err != nil {
			return actionDoneMsg{err: err}
		}
		return actionDoneMsg{err: vpn.Disconnect()}
	}
}

func doCleanQuit() tea.Cmd {
	return func() tea.Msg {
		ks := killswitch.New()
		if enabled, _ := ks.IsEnabled(); enabled {
			ks.Disable()
		}
		return actionDoneMsg{}
	}
}

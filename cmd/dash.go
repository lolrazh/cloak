package cmd

import (
	"fmt"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/tui"
	"github.com/spf13/cobra"
)

var dashCmd = &cobra.Command{
	Use:   "dash",
	Short: "Open the live TUI dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config (run `cloak init` first): %w", err)
		}

		// Preflight: validate and cache sudo credentials before entering TUI.
		// This prompts for password once in the normal terminal, instead of
		// having the first poll/action fail silently inside the alt-screen.
		fmt.Println("Requesting sudo access for VPN operations...")
		if err := exec.Command("sudo", "-v").Run(); err != nil {
			return fmt.Errorf("sudo access required for dashboard (run with sudo or check credentials): %w", err)
		}

		model := tui.NewModel(cfg)
		p := tea.NewProgram(model, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dashCmd)
}

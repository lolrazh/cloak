package cmd

import (
	"fmt"

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

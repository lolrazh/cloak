package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/tui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloak",
	Short: "Cloak — a personal WireGuard VPN manager",
	Long: `Cloak wraps WireGuard to automate server provisioning,
key management, connect/disconnect, kill switch, and monitoring
for your personal VPN.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Try to load config.
		cfg, err := config.Load()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("loading config: %w", err)
			}
			// No config — run setup wizard.
			cfg, err = runSetup()
			if err != nil {
				return err
			}
		}

		// 2. Verify server is configured.
		if cfg.Server == nil {
			return fmt.Errorf("config exists but no server configured — delete ~/.config/cloak/ and run `cloak` again")
		}

		// 3. Cache sudo credentials before entering TUI.
		fmt.Println("Requesting sudo access...")
		if err := exec.Command("sudo", "-v").Run(); err != nil {
			return fmt.Errorf("sudo access required: %w", err)
		}

		// 4. Launch TUI dashboard.
		model := tui.NewModel(cfg)
		p := tea.NewProgram(model, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

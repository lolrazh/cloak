package cmd

import (
	"fmt"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/status"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show VPN connection status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config (run `cloak init` first): %w", err)
		}

		var serverIP string
		if cfg.Server != nil {
			serverIP = cfg.Server.Host
		}

		info := status.Gather(serverIP)

		// Check kill switch.
		ks := killswitch.New()
		enabled, ksErr := ks.IsEnabled()
		info.KillSwitch = enabled
		if ksErr != nil {
			info.KillSwitchErr = ksErr.Error()
		}

		// Display.
		if info.PermErr != "" {
			fmt.Printf("Status:      Unknown (%s)\n", info.PermErr)
		} else if info.StatusErr != "" {
			fmt.Printf("Status:      Unknown (%s)\n", info.StatusErr)
		} else if info.Connected {
			fmt.Println("Status:      Connected")
			fmt.Printf("Public IP:   %s\n", info.ExternalIP)
			if info.Latency > 0 {
				fmt.Printf("Latency:     %dms\n", info.Latency.Milliseconds())
			}
			fmt.Printf("Transfer:    ↑ %s  ↓ %s\n",
				status.FormatBytes(info.TxBytes),
				status.FormatBytes(info.RxBytes))
			if info.LastHandshake > 0 {
				fmt.Printf("Handshake:   %s ago\n", info.LastHandshake)
			}
		} else {
			fmt.Println("Status:      Disconnected")
		}

		if info.KillSwitchErr != "" {
			fmt.Printf("Kill Switch: Error (%s)\n", info.KillSwitchErr)
		} else if info.KillSwitch {
			fmt.Println("Kill Switch: Active")
		} else {
			fmt.Println("Kill Switch: Inactive")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

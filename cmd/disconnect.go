package cmd

import (
	"fmt"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/tunnel"
	"github.com/spf13/cobra"
)

var disconnectCmd = &cobra.Command{
	Use:     "disconnect",
	Aliases: []string{"off"},
	Short:   "Disconnect from the VPN",
	RunE: func(cmd *cobra.Command, args []string) error {
		confPath, err := config.WGConfPath()
		if err != nil {
			return fmt.Errorf("WG config path: %w", err)
		}

		mgr := tunnel.NewManager()

		up, err := mgr.IsUp()
		if err != nil {
			return fmt.Errorf("checking tunnel status: %w", err)
		}
		if !up {
			fmt.Println("Already disconnected.")
			return nil
		}

		// Disable kill switch first (so the tunnel teardown traffic isn't blocked).
		ks := killswitch.New()
		if enabled, _ := ks.IsEnabled(); enabled {
			fmt.Println("Disabling kill switch...")
			if err := ks.Disable(); err != nil {
				fmt.Printf("Warning: kill switch disable failed: %v\n", err)
			}
		}

		fmt.Println("Disconnecting...")
		if err := mgr.Down(confPath); err != nil {
			return fmt.Errorf("bringing tunnel down: %w", err)
		}

		fmt.Println("Disconnected.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(disconnectCmd)
}

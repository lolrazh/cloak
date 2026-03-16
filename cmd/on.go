package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/status"
	"github.com/lolrazh/cloak/internal/vpn"
	"github.com/spf13/cobra"
)

var noKillswitch bool

var onCmd = &cobra.Command{
	Use:   "on",
	Short: "Connect to the VPN (headless)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("no config found — run `cloak` first to set up")
		}
		if cfg.Server == nil {
			return fmt.Errorf("no server configured — run `cloak` first to set up")
		}

		if _, err := exec.LookPath("wg-quick"); err != nil {
			return fmt.Errorf("wg-quick not found in PATH (install wireguard-tools)")
		}

		confPath, err := config.WGConfPath()
		if err != nil {
			return fmt.Errorf("WG config path: %w", err)
		}
		if _, err := os.Stat(confPath); err != nil {
			return fmt.Errorf("WG config not found at %s — run `cloak` first to set up", confPath)
		}

		fmt.Println("Connecting...")
		if err := vpn.Connect(cfg); err != nil {
			return err
		}

		ip := status.FetchExternalIP()
		if ip == "unknown" {
			fmt.Println("Connected (could not verify external IP).")
		} else {
			fmt.Printf("Connected. External IP: %s\n", ip)
		}

		return nil
	},
}

func init() {
	onCmd.Flags().BoolVar(&noKillswitch, "no-killswitch", false, "Disable kill switch")
	rootCmd.AddCommand(onCmd)
}

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/status"
	"github.com/lolrazh/cloak/internal/tunnel"
	"github.com/spf13/cobra"
)

var noKillswitch bool

var connectCmd = &cobra.Command{
	Use:     "connect",
	Aliases: []string{"on"},
	Short:   "Connect to the VPN",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config (run `cloak init` first): %w", err)
		}
		if cfg.Server == nil {
			return fmt.Errorf("no server configured (run `cloak server setup` first)")
		}

		// Preflight checks.
		if _, err := exec.LookPath("wg-quick"); err != nil {
			return fmt.Errorf("wg-quick not found in PATH (install wireguard-tools)")
		}

		confPath, err := config.WGConfPath()
		if err != nil {
			return fmt.Errorf("WG config path: %w", err)
		}
		if _, err := os.Stat(confPath); err != nil {
			return fmt.Errorf("WG config not found at %s (run `cloak server setup` first)", confPath)
		}

		mgr := tunnel.NewManager()

		fmt.Println("Connecting...")
		if err := mgr.Up(confPath); err != nil {
			return fmt.Errorf("bringing tunnel up: %w", err)
		}

		// Enable kill switch unless opted out.
		if !noKillswitch {
			ks := killswitch.New()
			fmt.Println("Enabling kill switch...")
			if err := ks.Enable(cfg.Server.Host, cfg.Port); err != nil {
				// Fail closed: if kill switch fails, tear down the tunnel to avoid leaks.
				if downErr := mgr.Down(confPath); downErr != nil {
					return fmt.Errorf("kill switch failed (%v) and rollback failed (%v); tunnel may still be up", err, downErr)
				}
				return fmt.Errorf("kill switch failed, tunnel was brought down: %w", err)
			}
		}

		// Verify by checking external IP.
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
	connectCmd.Flags().BoolVar(&noKillswitch, "no-killswitch", false, "Disable kill switch")
	rootCmd.AddCommand(connectCmd)
}

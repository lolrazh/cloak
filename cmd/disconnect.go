package cmd

import (
	"fmt"
	"os/exec"
	"runtime"

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
		// Ensure sudo credentials are cached for kill switch and tunnel operations.
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			fmt.Println("Requesting sudo access...")
			if err := exec.Command("sudo", "-v").Run(); err != nil {
				return fmt.Errorf("sudo access required for disconnect: %w", err)
			}
		}

		// Always attempt kill switch disable first, even if tunnel appears down.
		// The tunnel can drop unexpectedly while kill switch rules remain active,
		// leaving the user with no internet. A redundant disable is harmless.
		ks := killswitch.New()
		fmt.Println("Disabling kill switch...")
		if err := ks.Disable(); err != nil {
			fmt.Printf("Warning: kill switch disable failed: %v\n", err)
		}

		confPath, err := config.WGConfPath()
		if err != nil {
			return fmt.Errorf("WG config path: %w", err)
		}

		mgr := tunnel.NewManager()

		fmt.Println("Disconnecting...")
		if err := mgr.Down(confPath); err != nil {
			return fmt.Errorf("bringing tunnel down: %w", err)
		}

		// Safety net: restore DNS in case wg-quick down didn't fully clean up.
		restoreDNS()

		fmt.Println("Disconnected.")
		return nil
	},
}

// restoreDNS resets DNS to DHCP defaults as a safety net after disconnect.
func restoreDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	// Reset DNS on common macOS interfaces to use DHCP-provided DNS.
	for _, iface := range []string{"Wi-Fi", "Ethernet"} {
		exec.Command("networksetup", "-setdnsservers", iface, "Empty").CombinedOutput()
	}
}

func init() {
	rootCmd.AddCommand(disconnectCmd)
}

package cmd

import (
	"fmt"
	"os/exec"

	"github.com/lolrazh/cloak/internal/vpn"
	"github.com/spf13/cobra"
)

var disconnectCmd = &cobra.Command{
	Use:     "disconnect",
	Aliases: []string{"off"},
	Short:   "Disconnect from the VPN",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			fmt.Println("Requesting sudo access...")
			if err := exec.Command("sudo", "-v").Run(); err != nil {
				return fmt.Errorf("sudo access required for disconnect: %w", err)
			}
		}

		fmt.Println("Disconnecting...")
		if err := vpn.Disconnect(); err != nil {
			return err
		}

		fmt.Println("Disconnected.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(disconnectCmd)
}

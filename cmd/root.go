package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloak",
	Short: "Cloak — a personal WireGuard VPN manager",
	Long: `Cloak wraps WireGuard to automate server provisioning,
key management, connect/disconnect, kill switch, and monitoring
for your personal VPN.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

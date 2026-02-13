package cmd

import (
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage VPN server",
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

package cmd

import (
	"fmt"

	"github.com/lolrazh/cloak/internal/config"
	sshpkg "github.com/lolrazh/cloak/internal/ssh"
	"github.com/spf13/cobra"
)

var destroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Remove WireGuard from the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		if cfg.Server == nil {
			return fmt.Errorf("no server configured")
		}

		fmt.Printf("Connecting to %s@%s...\n", cfg.Server.User, cfg.Server.Host)
		client, err := sshpkg.Connect(cfg.Server.Host, cfg.Server.User, cfg.Server.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("SSH connect: %w", err)
		}
		defer client.Close()

		fmt.Println("Removing WireGuard from server...")
		cmds := []string{
			"systemctl stop wg-quick@wg0 || true",
			"systemctl disable wg-quick@wg0 || true",
			"rm -f /etc/wireguard/wg0.conf",
		}
		for _, c := range cmds {
			if _, err := client.RunSudo(c); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}
		}

		cfg.Server = nil
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Println("Server WireGuard config removed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(destroyCmd)
}

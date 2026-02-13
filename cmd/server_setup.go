package cmd

import (
	"fmt"
	"os"

	"github.com/lolrazh/cloak/internal/config"
	sshpkg "github.com/lolrazh/cloak/internal/ssh"
	"github.com/spf13/cobra"
)

var serverSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Provision a VPN server via SSH",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		sshKey, _ := cmd.Flags().GetString("ssh-key")
		user, _ := cmd.Flags().GetString("user")

		if host == "" {
			return fmt.Errorf("--host is required")
		}
		if sshKey == "" {
			return fmt.Errorf("--ssh-key is required")
		}

		// Load existing config (must have run `cloak init` first).
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config (did you run `cloak init`?): %w", err)
		}

		// Store server info in config.
		cfg.Server = &config.ServerConfig{
			Host:       host,
			User:       user,
			SSHKeyPath: sshKey,
		}

		fmt.Printf("Connecting to %s@%s...\n", user, host)
		client, err := sshpkg.Connect(host, user, sshKey)
		if err != nil {
			return fmt.Errorf("SSH connect: %w", err)
		}
		defer client.Close()

		fmt.Println("Provisioning server...")
		result, err := sshpkg.Provision(client, cfg)
		if err != nil {
			return fmt.Errorf("provisioning: %w", err)
		}

		// Update config with server public key and endpoint.
		cfg.Server.PublicKey = result.ServerPublicKey
		cfg.Server.Endpoint = fmt.Sprintf("%s:%d", host, cfg.Port)

		// Save client WireGuard config.
		wgPath, err := config.WGConfPath()
		if err != nil {
			return fmt.Errorf("WG config path: %w", err)
		}
		if err := os.WriteFile(wgPath, []byte(result.ClientConfig), 0600); err != nil {
			return fmt.Errorf("writing WG config: %w", err)
		}

		// Save updated cloak config.
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Println("\nServer provisioned successfully!")
		fmt.Printf("  Server public key: %s\n", result.ServerPublicKey)
		fmt.Printf("  Client config: %s\n", wgPath)
		fmt.Println("\nRun `cloak on` to connect.")
		return nil
	},
}

func init() {
	serverSetupCmd.Flags().String("host", "", "Server IP or hostname")
	serverSetupCmd.Flags().String("ssh-key", "", "Path to SSH private key")
	serverSetupCmd.Flags().String("user", "ubuntu", "SSH username")

	serverCmd.AddCommand(serverSetupCmd)
}

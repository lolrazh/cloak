package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
	sshpkg "github.com/lolrazh/cloak/internal/ssh"
)

func runSetup() (*config.Config, error) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("\nWelcome to Cloak.\n\n")

	// 1. Prompt for server IP (required).
	host := prompt(scanner, "Server IP: ", "")
	if host == "" {
		return nil, fmt.Errorf("server IP is required")
	}

	// 2. Auto-detect SSH key.
	keyPath := detectSSHKey()
	if keyPath != "" {
		fmt.Printf("SSH key:    %s\n", keyPath)
	} else {
		keyPath = prompt(scanner, "SSH key path: ", "")
		if keyPath == "" {
			return nil, fmt.Errorf("SSH key path is required")
		}
	}

	// 3. Prompt for SSH user.
	user := prompt(scanner, "SSH user [root]: ", "root")

	fmt.Println("\nSetting up...")

	// 4. Generate WireGuard keys.
	kp, err := config.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating keys: %w", err)
	}

	cfg := config.Defaults()
	cfg.PrivateKey = config.KeyToBase64(kp.Private)
	cfg.PublicKey = config.KeyToBase64(kp.Public)
	cfg.Server = &config.ServerConfig{
		Host:       host,
		User:       user,
		SSHKeyPath: keyPath,
	}

	// 5. Save initial config so provision can read it.
	if err := config.Save(&cfg); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	// 6. SSH connect + provision.
	client, err := sshpkg.Connect(host, user, keyPath)
	if err != nil {
		return nil, fmt.Errorf("SSH connect: %w", err)
	}
	defer client.Close()

	result, err := sshpkg.Provision(client, &cfg)
	if err != nil {
		return nil, fmt.Errorf("provisioning: %w", err)
	}

	// 7. Save server public key and endpoint.
	cfg.Server.PublicKey = result.ServerPublicKey
	cfg.Server.Endpoint = fmt.Sprintf("%s:%d", host, cfg.Port)

	// 8. Save client WireGuard config.
	wgPath, err := config.WGConfPath()
	if err != nil {
		return nil, fmt.Errorf("WG config path: %w", err)
	}
	if err := os.WriteFile(wgPath, []byte(result.ClientConfig), 0600); err != nil {
		return nil, fmt.Errorf("writing WG config: %w", err)
	}

	// 9. Save final config.
	if err := config.Save(&cfg); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	fmt.Print("Server ready!\n\n")
	return &cfg, nil
}

func detectSSHKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func prompt(scanner *bufio.Scanner, label, defaultVal string) string {
	fmt.Print(label)
	scanner.Scan()
	val := strings.TrimSpace(scanner.Text())
	if val == "" {
		return defaultVal
	}
	return val
}

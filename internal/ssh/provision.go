package ssh

import (
	"fmt"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/wgconfig"
	"github.com/lolrazh/cloak/internal/wgkeys"
)

// ProvisionResult contains the output of a successful server provisioning.
type ProvisionResult struct {
	ServerPublicKey string
	ClientConfig    string
}

// Provision sets up WireGuard on the remote server.
// Steps:
//  1. Detect OS (apt vs dnf)
//  2. Install wireguard-tools
//  3. Enable IP forwarding
//  4. Detect default network interface
//  5. Generate server key pair
//  6. Upload server WireGuard config
//  7. Open firewall port
//  8. Enable and start WireGuard
//  9. Return client config
func Provision(client *Client, cfg *config.Config) (*ProvisionResult, error) {
	steps := []struct {
		name string
		fn   func() error
	}{}

	var pkgMgr string // "apt" or "dnf"
	var defaultIface string
	var serverKP wgkeys.KeyPair

	// 1. Detect package manager.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Detecting OS",
		fn: func() error {
			out, err := client.Run("cat /etc/os-release")
			if err != nil {
				return fmt.Errorf("reading os-release: %w", err)
			}
			lower := strings.ToLower(out)
			switch {
			case strings.Contains(lower, "ubuntu"), strings.Contains(lower, "debian"):
				pkgMgr = "apt"
			case strings.Contains(lower, "oracle"), strings.Contains(lower, "centos"),
				strings.Contains(lower, "rhel"), strings.Contains(lower, "fedora"),
				strings.Contains(lower, "alma"), strings.Contains(lower, "rocky"):
				pkgMgr = "dnf"
			default:
				return fmt.Errorf("unsupported OS: %s", out)
			}
			fmt.Printf("  Detected package manager: %s\n", pkgMgr)
			return nil
		},
	})

	// 2. Install WireGuard.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Installing WireGuard",
		fn: func() error {
			var cmd string
			switch pkgMgr {
			case "apt":
				cmd = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq wireguard-tools"
			case "dnf":
				cmd = "dnf install -y -q epel-release && dnf install -y -q wireguard-tools"
			}
			_, err := client.RunSudo(cmd)
			return err
		},
	})

	// 3. Enable IP forwarding.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Enabling IP forwarding",
		fn: func() error {
			cmds := []string{
				"sysctl -w net.ipv4.ip_forward=1",
				"sed -i '/^#*net.ipv4.ip_forward/c\\net.ipv4.ip_forward=1' /etc/sysctl.conf",
			}
			for _, cmd := range cmds {
				if _, err := client.RunSudo(cmd); err != nil {
					return err
				}
			}
			return nil
		},
	})

	// 4. Detect default network interface.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Detecting default interface",
		fn: func() error {
			out, err := client.Run("ip route show default | awk '{print $5}' | head -1")
			if err != nil {
				return fmt.Errorf("detecting default interface: %w", err)
			}
			defaultIface = strings.TrimSpace(out)
			if defaultIface == "" {
				return fmt.Errorf("could not detect default network interface")
			}
			fmt.Printf("  Default interface: %s\n", defaultIface)
			return nil
		},
	})

	// 5. Generate server key pair.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Generating server keys",
		fn: func() error {
			var err error
			serverKP, err = wgkeys.Generate()
			return err
		},
	})

	// 6. Upload server WireGuard config.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Uploading server config",
		fn: func() error {
			serverConf, err := wgconfig.RenderServer(wgconfig.ServerData{
				ServerAddress:    "10.0.0.1/24",
				Port:             cfg.Port,
				ServerPrivateKey: serverKP.Private.String(),
				DefaultInterface: defaultIface,
				ClientPublicKey:  cfg.PublicKey,
				ClientAddress:    "10.0.0.2",
			})
			if err != nil {
				return fmt.Errorf("rendering server config: %w", err)
			}

			// Write config via stdin (clean, no shell escaping issues).
			if err := client.WriteFile("/etc/wireguard/wg0.conf", serverConf, "600"); err != nil {
				return fmt.Errorf("uploading config: %w", err)
			}
			return nil
		},
	})

	// 7. Open firewall port.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Opening firewall port",
		fn: func() error {
			cmds := []string{
				fmt.Sprintf("iptables -I INPUT -p udp --dport %d -j ACCEPT", cfg.Port),
				"iptables-save > /etc/iptables/rules.v4 || true",
			}
			// Also try firewalld for Oracle Linux / CentOS.
			if pkgMgr == "dnf" {
				cmds = append(cmds,
					fmt.Sprintf("firewall-cmd --add-port=%d/udp --permanent 2>/dev/null || true", cfg.Port),
					"firewall-cmd --reload 2>/dev/null || true",
				)
			}
			for _, cmd := range cmds {
				// Best-effort; some may fail if tools aren't installed.
				client.RunSudo(cmd)
			}
			return nil
		},
	})

	// 8. Enable and start WireGuard.
	steps = append(steps, struct {
		name string
		fn   func() error
	}{
		name: "Starting WireGuard",
		fn: func() error {
			cmds := []string{
				"systemctl enable wg-quick@wg0",
				"systemctl restart wg-quick@wg0",
			}
			for _, cmd := range cmds {
				if _, err := client.RunSudo(cmd); err != nil {
					return err
				}
			}
			return nil
		},
	})

	// Execute all steps.
	for i, step := range steps {
		fmt.Printf("[%d/%d] %s...\n", i+1, len(steps), step.name)
		if err := step.fn(); err != nil {
			return nil, fmt.Errorf("step %q failed: %w", step.name, err)
		}
	}

	// 9. Generate client config.
	clientConf, err := wgconfig.RenderClient(wgconfig.ClientData{
		ClientAddress:    "10.0.0.2",
		ClientPrivateKey: cfg.PrivateKey,
		ServerPublicKey:  serverKP.Public.String(),
		ServerEndpoint:   cfg.Server.Host,
		Port:             cfg.Port,
	})
	if err != nil {
		return nil, fmt.Errorf("rendering client config: %w", err)
	}

	return &ProvisionResult{
		ServerPublicKey: serverKP.Public.String(),
		ClientConfig:    clientConf,
	}, nil
}

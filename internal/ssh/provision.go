package ssh

import (
	"encoding/binary"
	"fmt"
	"net"
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

type step struct {
	name string
	fn   func() error
}

// Provision sets up WireGuard on the remote server and returns
// the server public key and a ready-to-use client config.
func Provision(client *Client, cfg *config.Config) (*ProvisionResult, error) {
	serverCIDR, clientCIDR, clientIP, err := subnetDetails(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", cfg.Subnet, err)
	}

	var pkgMgr string
	var defaultIface string
	var serverKP wgkeys.KeyPair

	steps := []step{
		{"Detecting OS", func() error {
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
		}},
		{"Installing WireGuard", func() error {
			var cmd string
			switch pkgMgr {
			case "apt":
				cmd = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq wireguard-tools"
			case "dnf":
				cmd = "dnf install -y -q epel-release && dnf install -y -q wireguard-tools"
			}
			_, err := client.RunSudo(cmd)
			return err
		}},
		{"Enabling IP forwarding", func() error {
			for _, cmd := range []string{
				"sysctl -w net.ipv4.ip_forward=1",
				"sed -i '/^#*net.ipv4.ip_forward/c\\net.ipv4.ip_forward=1' /etc/sysctl.conf",
			} {
				if _, err := client.RunSudo(cmd); err != nil {
					return err
				}
			}
			return nil
		}},
		{"Detecting default interface", func() error {
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
		}},
		{"Generating server keys", func() error {
			var err error
			serverKP, err = wgkeys.Generate()
			return err
		}},
		{"Uploading server config", func() error {
			serverConf, err := wgconfig.RenderServer(wgconfig.ServerData{
				ServerAddress:    serverCIDR,
				Port:             cfg.Port,
				ServerPrivateKey: serverKP.Private.String(),
				DefaultInterface: defaultIface,
				ClientPublicKey:  cfg.PublicKey,
				ClientAddress:    clientIP,
			})
			if err != nil {
				return fmt.Errorf("rendering server config: %w", err)
			}
			return client.WriteFile("/etc/wireguard/wg0.conf", serverConf, "600")
		}},
		{"Opening firewall port", func() error {
			cmds := []string{
				fmt.Sprintf("iptables -I INPUT -p udp --dport %d -j ACCEPT", cfg.Port),
				"iptables-save > /etc/iptables/rules.v4 || true",
			}
			if pkgMgr == "dnf" {
				cmds = append(cmds,
					fmt.Sprintf("firewall-cmd --add-port=%d/udp --permanent 2>/dev/null || true", cfg.Port),
					"firewall-cmd --reload 2>/dev/null || true",
				)
			}
			for _, cmd := range cmds {
				client.RunSudo(cmd) // best-effort
			}
			return nil
		}},
		{"Starting WireGuard", func() error {
			for _, cmd := range []string{
				"systemctl enable wg-quick@wg0",
				"systemctl restart wg-quick@wg0",
			} {
				if _, err := client.RunSudo(cmd); err != nil {
					return err
				}
			}
			return nil
		}},
	}

	for i, s := range steps {
		fmt.Printf("[%d/%d] %s...\n", i+1, len(steps), s.name)
		if err := s.fn(); err != nil {
			return nil, fmt.Errorf("step %q failed: %w", s.name, err)
		}
	}

	clientConf, err := wgconfig.RenderClient(wgconfig.ClientData{
		ClientAddress:    clientCIDR,
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

// subnetDetails derives server/client addresses from a CIDR subnet.
// e.g. "10.0.0.0/24" -> ("10.0.0.1/24", "10.0.0.2/24", "10.0.0.2", nil)
func subnetDetails(subnet string) (serverCIDR, clientCIDR, clientIP string, err error) {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", "", fmt.Errorf("parsing subnet: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", "", fmt.Errorf("only IPv4 subnets supported, got %s", subnet)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return "", "", "", fmt.Errorf("only IPv4 subnets supported, got %s", subnet)
	}
	if ones > 30 {
		return "", "", "", fmt.Errorf("subnet too small, need at least /30")
	}

	base := binary.BigEndian.Uint32(ip4)
	server := uint32ToIP(base + 1)
	client := uint32ToIP(base + 2)
	if !ipNet.Contains(server) || !ipNet.Contains(client) {
		return "", "", "", fmt.Errorf("subnet %s does not have enough host addresses", subnet)
	}

	serverCIDR = fmt.Sprintf("%s/%d", server.String(), ones)
	clientCIDR = fmt.Sprintf("%s/%d", client.String(), ones)
	clientIP = client.String()
	return serverCIDR, clientCIDR, clientIP, nil
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

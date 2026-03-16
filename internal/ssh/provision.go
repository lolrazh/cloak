package ssh

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
)

type ProvisionResult struct {
	ServerPublicKey string
	ClientConfig    string
}

type step struct {
	name string
	fn   func() error
}

func Provision(client *Client, cfg *config.Config) (*ProvisionResult, error) {
	serverCIDR, clientCIDR, clientIP, err := subnetDetails(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", cfg.Subnet, err)
	}

	var pkgMgr, defaultIface string
	var serverKP config.KeyPair

	steps := []step{
		{"Detecting OS", func() error {
			out, err := client.Run("cat /etc/os-release")
			if err != nil {
				return err
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
				return fmt.Errorf("unsupported OS")
			}
			fmt.Printf("  Package manager: %s\n", pkgMgr)
			return nil
		}},
		{"Installing WireGuard", func() error {
			var cmd string
			if pkgMgr == "apt" {
				cmd = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq wireguard-tools"
			} else {
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
				return err
			}
			defaultIface = strings.TrimSpace(out)
			if defaultIface == "" {
				return fmt.Errorf("could not detect default network interface")
			}
			fmt.Printf("  Interface: %s\n", defaultIface)
			return nil
		}},
		{"Generating server keys", func() error {
			serverKP, err = config.GenerateKeyPair()
			return err
		}},
		{"Uploading server config", func() error {
			conf := serverConf(serverCIDR, cfg.Port, config.KeyToBase64(serverKP.Private),
				defaultIface, cfg.PublicKey, clientIP)
			return client.WriteFile("/etc/wireguard/wg0.conf", conf, "600")
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
				client.RunSudo(cmd)
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
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}

	serverPub := config.KeyToBase64(serverKP.Public)
	return &ProvisionResult{
		ServerPublicKey: serverPub,
		ClientConfig:    clientConf(clientCIDR, cfg.PrivateKey, serverPub, cfg.Server.Host, cfg.Port),
	}, nil
}

func serverConf(addr string, port int, privKey, iface, clientPub, clientIP string) string {
	return fmt.Sprintf(`[Interface]
Address = %s
ListenPort = %d
PrivateKey = %s

PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE; iptables -t mangle -A FORWARD -i %%i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t mangle -A FORWARD -o %%i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE; iptables -t mangle -D FORWARD -i %%i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t mangle -D FORWARD -o %%i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, addr, port, privKey, iface, iface, clientPub, clientIP)
}

func clientConf(addr, privKey, serverPub, endpoint string, port int) string {
	return fmt.Sprintf(`[Interface]
Address = %s
MTU = 1420
PrivateKey = %s
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, addr, privKey, serverPub, endpoint, port)
}

func subnetDetails(subnet string) (serverCIDR, clientCIDR, clientIP string, err error) {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", "", err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", "", fmt.Errorf("only IPv4 supported")
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", "", "", fmt.Errorf("need IPv4 subnet /30 or larger")
	}

	base := binary.BigEndian.Uint32(ip4)
	server := make(net.IP, 4)
	client := make(net.IP, 4)
	binary.BigEndian.PutUint32(server, base+1)
	binary.BigEndian.PutUint32(client, base+2)

	if !ipNet.Contains(server) || !ipNet.Contains(client) {
		return "", "", "", fmt.Errorf("subnet too small")
	}

	return fmt.Sprintf("%s/%d", server, ones),
		fmt.Sprintf("%s/%d", client, ones),
		client.String(), nil
}

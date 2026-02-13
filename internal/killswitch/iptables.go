//go:build linux

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IPTablesKillSwitch implements KillSwitch using Linux iptables.
type IPTablesKillSwitch struct {
	backupPath string
}

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	configDir, _ := os.UserHomeDir()
	base := filepath.Join(configDir, ".config", "cloak")
	return &IPTablesKillSwitch{
		backupPath: filepath.Join(base, "iptables-backup.rules"),
	}
}

func (ks *IPTablesKillSwitch) Enable(serverIP string, serverPort int) error {
	// Backup current iptables rules.
	out, err := exec.Command("sudo", "iptables-save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("backing up iptables: %w", err)
	}
	if err := os.WriteFile(ks.backupPath, out, 0600); err != nil {
		return fmt.Errorf("writing iptables backup: %w", err)
	}

	// Apply kill switch rules.
	rules := [][]string{
		// Allow loopback.
		{"iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		// Allow traffic to/from VPN server.
		{"iptables", "-A", "OUTPUT", "-d", serverIP, "-p", "udp", "--dport",
			fmt.Sprintf("%d", serverPort), "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-s", serverIP, "-p", "udp", "--sport",
			fmt.Sprintf("%d", serverPort), "-j", "ACCEPT"},
		// Allow all traffic on WireGuard interface.
		{"iptables", "-A", "INPUT", "-i", "wg0", "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-o", "wg0", "-j", "ACCEPT"},
		// Block DNS outside tunnel (DNS leak protection).
		{"iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP"},
		{"iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DROP"},
		// Block everything else.
		{"iptables", "-A", "OUTPUT", "-j", "DROP"},
		{"iptables", "-A", "INPUT", "-j", "DROP"},
	}

	// Flush existing rules first.
	exec.Command("sudo", "iptables", "-F").CombinedOutput()

	for _, rule := range rules {
		args := append([]string{"sudo"}, rule...)
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables rule %v: %w\n%s", rule, err, out)
		}
	}

	// Add a comment rule so we can detect if kill switch is active.
	exec.Command("sudo", "iptables", "-A", "INPUT", "-m", "comment",
		"--comment", "cloak-killswitch", "-j", "RETURN").CombinedOutput()

	return nil
}

func (ks *IPTablesKillSwitch) Disable() error {
	if _, err := os.Stat(ks.backupPath); err == nil {
		out, err := exec.Command("sudo", "iptables-restore", ks.backupPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("restoring iptables: %w\n%s", err, out)
		}
		os.Remove(ks.backupPath)
	} else {
		exec.Command("sudo", "iptables", "-F").CombinedOutput()
	}
	return nil
}

func (ks *IPTablesKillSwitch) IsEnabled() (bool, error) {
	out, err := exec.Command("sudo", "iptables", "-S").CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(out), "cloak-killswitch"), nil
}

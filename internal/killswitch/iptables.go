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
// Uses a dedicated chain (CLOAK) to avoid destroying existing firewall policy.
type IPTablesKillSwitch struct {
	backupPath string
}

const chainName = "CLOAK"

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	configDir, _ := os.UserHomeDir()
	base := filepath.Join(configDir, ".config", "cloak")
	return &IPTablesKillSwitch{
		backupPath: filepath.Join(base, "iptables-backup.rules"),
	}
}

func (ks *IPTablesKillSwitch) Enable(serverIP string, serverPort int) error {
	// Backup current iptables rules (full state, all chains).
	out, err := exec.Command("sudo", "iptables-save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("backing up iptables: %w", err)
	}
	if err := os.WriteFile(ks.backupPath, out, 0600); err != nil {
		return fmt.Errorf("writing iptables backup: %w", err)
	}

	// Backup ip6tables too.
	if out6, err := exec.Command("sudo", "ip6tables-save").CombinedOutput(); err == nil {
		if err := os.WriteFile(ks.backupPath+".v6", out6, 0600); err != nil {
			return fmt.Errorf("writing ip6tables backup: %w", err)
		}
	}

	// Create a dedicated chain so we don't touch existing rules.
	cmds := [][]string{
		// Create CLOAK chain (ignore error if it already exists).
		{"iptables", "-N", chainName},
		// Flush it in case of leftover rules.
		{"iptables", "-F", chainName},
		// Populate CLOAK chain rules.
		{"iptables", "-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-d", serverIP, "-p", "udp", "--dport",
			fmt.Sprintf("%d", serverPort), "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-s", serverIP, "-p", "udp", "--sport",
			fmt.Sprintf("%d", serverPort), "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-i", "wg0", "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-o", "wg0", "-j", "ACCEPT"},
		// Block DNS outside tunnel.
		{"iptables", "-A", chainName, "-p", "udp", "--dport", "53", "-j", "DROP"},
		{"iptables", "-A", chainName, "-p", "tcp", "--dport", "53", "-j", "DROP"},
		// Block everything else.
		{"iptables", "-A", chainName, "-j", "DROP"},
		// Jump to CLOAK from OUTPUT and INPUT at the top of the chain.
		{"iptables", "-I", "OUTPUT", "1", "-j", chainName},
		{"iptables", "-I", "INPUT", "1", "-j", chainName},
	}

	// Create chain first (may already exist, that's fine).
	exec.Command("sudo", "iptables", "-N", chainName).CombinedOutput()
	exec.Command("sudo", "iptables", "-F", chainName).CombinedOutput()

	// Skip the first two commands (create + flush, already done above).
	for _, rule := range cmds[2:] {
		args := append([]string{"sudo"}, rule...)
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables rule %v: %w\n%s", rule, err, out)
		}
	}

	// Block IPv6 entirely to prevent leaks.
	exec.Command("sudo", "ip6tables", "-N", chainName).CombinedOutput()
	exec.Command("sudo", "ip6tables", "-F", chainName).CombinedOutput()
	ip6cmds := [][]string{
		{"ip6tables", "-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"ip6tables", "-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		{"ip6tables", "-A", chainName, "-j", "DROP"},
		{"ip6tables", "-I", "OUTPUT", "1", "-j", chainName},
		{"ip6tables", "-I", "INPUT", "1", "-j", chainName},
	}
	for _, rule := range ip6cmds {
		args := append([]string{"sudo"}, rule...)
		exec.Command(args[0], args[1:]...).CombinedOutput()
	}

	return nil
}

func (ks *IPTablesKillSwitch) Disable() error {
	var firstErr error

	if _, err := os.Stat(ks.backupPath); err == nil {
		out, err := exec.Command("sudo", "-n", "iptables-restore", ks.backupPath).CombinedOutput()
		if err != nil {
			removeChain("iptables")
			firstErr = fmt.Errorf("iptables-restore failed (sudo expired? run: sudo iptables -F): %s", strings.TrimSpace(string(out)))
		} else {
			os.Remove(ks.backupPath)
		}
	} else {
		removeChain("iptables")
	}

	// Restore IPv6.
	v6Backup := ks.backupPath + ".v6"
	if _, err := os.Stat(v6Backup); err == nil {
		out, err := exec.Command("sudo", "-n", "ip6tables-restore", v6Backup).CombinedOutput()
		if err != nil {
			removeChain("ip6tables")
			if firstErr == nil {
				firstErr = fmt.Errorf("ip6tables-restore failed: %s", strings.TrimSpace(string(out)))
			}
		} else {
			os.Remove(v6Backup)
		}
	} else {
		removeChain("ip6tables")
	}

	return firstErr
}

// removeChain removes the CLOAK chain from the given iptables command.
func removeChain(ipt string) {
	// Remove jump rules from INPUT/OUTPUT first.
	exec.Command("sudo", "-n", ipt, "-D", "OUTPUT", "-j", chainName).CombinedOutput()
	exec.Command("sudo", "-n", ipt, "-D", "INPUT", "-j", chainName).CombinedOutput()
	// Flush and delete our chain.
	exec.Command("sudo", "-n", ipt, "-F", chainName).CombinedOutput()
	exec.Command("sudo", "-n", ipt, "-X", chainName).CombinedOutput()
}

func (ks *IPTablesKillSwitch) IsEnabled() (bool, error) {
	out, err := exec.Command("sudo", "-n", "iptables", "-L", chainName).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("checking iptables kill switch state: %w\n%s", err, out)
	}
	// Chain exists and has rules — kill switch is active.
	return strings.Contains(string(out), "DROP"), nil
}

//go:build linux

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
)

// IPTablesKillSwitch implements KillSwitch using Linux iptables.
// Uses a dedicated chain (CLOAK) to avoid destroying existing firewall policy.
type IPTablesKillSwitch struct {
	backupPath string
}

const chainName = "CLOAK"

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	base, _ := config.Dir()
	return &IPTablesKillSwitch{
		backupPath: filepath.Join(base, "iptables-backup.rules"),
	}
}

// sudoRun runs an iptables/ip6tables command with sudo, returning combined output.
func sudoRun(args ...string) ([]byte, error) {
	return exec.Command("sudo", args...).CombinedOutput()
}

func (ks *IPTablesKillSwitch) Enable(serverIP string, serverPort int) error {
	// Backup current rules.
	out, err := sudoRun("iptables-save")
	if err != nil {
		return fmt.Errorf("backing up iptables: %w", err)
	}
	if err := os.WriteFile(ks.backupPath, out, 0600); err != nil {
		return fmt.Errorf("writing iptables backup: %w", err)
	}
	if out6, err := sudoRun("ip6tables-save"); err == nil {
		if err := os.WriteFile(ks.backupPath+".v6", out6, 0600); err != nil {
			return fmt.Errorf("writing ip6tables backup: %w", err)
		}
	}

	// Create/flush our chain (idempotent).
	sudoRun("iptables", "-N", chainName)
	sudoRun("iptables", "-F", chainName)

	// IPv4 rules.
	port := fmt.Sprintf("%d", serverPort)
	rules := [][]string{
		{"-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-d", serverIP, "-p", "udp", "--dport", port, "-j", "ACCEPT"},
		{"-A", chainName, "-s", serverIP, "-p", "udp", "--sport", port, "-j", "ACCEPT"},
		{"-A", chainName, "-i", "wg0", "-j", "ACCEPT"},
		{"-A", chainName, "-o", "wg0", "-j", "ACCEPT"},
		{"-A", chainName, "-p", "udp", "--dport", "53", "-j", "DROP"},
		{"-A", chainName, "-p", "tcp", "--dport", "53", "-j", "DROP"},
		{"-A", chainName, "-j", "DROP"},
		{"-I", "OUTPUT", "1", "-j", chainName},
		{"-I", "INPUT", "1", "-j", chainName},
	}
	for _, r := range rules {
		args := append([]string{"iptables"}, r...)
		if out, err := sudoRun(args...); err != nil {
			return fmt.Errorf("iptables %v: %w\n%s", r, err, out)
		}
	}

	// Block IPv6 entirely.
	sudoRun("ip6tables", "-N", chainName)
	sudoRun("ip6tables", "-F", chainName)
	for _, r := range [][]string{
		{"-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-j", "DROP"},
		{"-I", "OUTPUT", "1", "-j", chainName},
		{"-I", "INPUT", "1", "-j", chainName},
	} {
		args := append([]string{"ip6tables"}, r...)
		sudoRun(args...)
	}

	return nil
}

func (ks *IPTablesKillSwitch) Disable() error {
	var firstErr error

	if _, err := os.Stat(ks.backupPath); err == nil {
		out, err := sudoRun("-n", "iptables-restore", ks.backupPath)
		if err != nil {
			removeChain("iptables")
			firstErr = fmt.Errorf("iptables-restore failed (sudo expired? run: sudo iptables -F): %s", strings.TrimSpace(string(out)))
		} else {
			os.Remove(ks.backupPath)
		}
	} else {
		removeChain("iptables")
	}

	v6Backup := ks.backupPath + ".v6"
	if _, err := os.Stat(v6Backup); err == nil {
		out, err := sudoRun("-n", "ip6tables-restore", v6Backup)
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

func removeChain(ipt string) {
	sudoRun("-n", ipt, "-D", "OUTPUT", "-j", chainName)
	sudoRun("-n", ipt, "-D", "INPUT", "-j", chainName)
	sudoRun("-n", ipt, "-F", chainName)
	sudoRun("-n", ipt, "-X", chainName)
}

func (ks *IPTablesKillSwitch) IsEnabled() (bool, error) {
	out, err := sudoRun("-n", "iptables", "-L", chainName)
	if err != nil {
		return false, fmt.Errorf("checking iptables kill switch state: %w\n%s", err, out)
	}
	return strings.Contains(string(out), "DROP"), nil
}

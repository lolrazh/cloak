//go:build linux

package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
)

const chainName = "CLOAK"

func backupPath() string {
	dir, _ := config.Dir()
	return filepath.Join(dir, "iptables-backup.rules")
}

func sudoRun(args ...string) ([]byte, error) {
	return exec.Command("sudo", args...).CombinedOutput()
}

func enableKillSwitch(serverIP string, serverPort int) error {
	bp := backupPath()

	out, err := sudoRun("iptables-save")
	if err != nil {
		return fmt.Errorf("backing up iptables: %w", err)
	}
	if err := os.WriteFile(bp, out, 0600); err != nil {
		return err
	}
	if out6, err := sudoRun("ip6tables-save"); err == nil {
		os.WriteFile(bp+".v6", out6, 0600)
	}

	sudoRun("iptables", "-N", chainName)
	sudoRun("iptables", "-F", chainName)

	port := fmt.Sprintf("%d", serverPort)
	for _, r := range [][]string{
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
	} {
		if out, err := sudoRun(append([]string{"iptables"}, r...)...); err != nil {
			return fmt.Errorf("iptables %v: %w\n%s", r, err, out)
		}
	}

	sudoRun("ip6tables", "-N", chainName)
	sudoRun("ip6tables", "-F", chainName)
	for _, r := range [][]string{
		{"-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		{"-A", chainName, "-j", "DROP"},
		{"-I", "OUTPUT", "1", "-j", chainName},
		{"-I", "INPUT", "1", "-j", chainName},
	} {
		sudoRun(append([]string{"ip6tables"}, r...)...)
	}
	return nil
}

func disableKillSwitch() error {
	bp := backupPath()
	var firstErr error

	if _, err := os.Stat(bp); err == nil {
		if out, err := sudoRun("-n", "iptables-restore", bp); err != nil {
			removeChain("iptables")
			firstErr = fmt.Errorf("iptables-restore failed: %s", strings.TrimSpace(string(out)))
		} else {
			os.Remove(bp)
		}
	} else {
		removeChain("iptables")
	}

	v6 := bp + ".v6"
	if _, err := os.Stat(v6); err == nil {
		if out, err := sudoRun("-n", "ip6tables-restore", v6); err != nil {
			removeChain("ip6tables")
			if firstErr == nil {
				firstErr = fmt.Errorf("ip6tables-restore failed: %s", strings.TrimSpace(string(out)))
			}
		} else {
			os.Remove(v6)
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

func isKillSwitchEnabled() (bool, error) {
	out, err := sudoRun("-n", "iptables", "-L", chainName)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "DROP"), nil
}

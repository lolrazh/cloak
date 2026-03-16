//go:build darwin

package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
)

const anchorName = "com.apple/cloak"

func pfPath(name string) string {
	dir, _ := config.Dir()
	return filepath.Join(dir, name)
}

func enableKillSwitch(serverIP string, serverPort int) error {
	rulesPath := pfPath("pf-cloak.conf")
	wasEnabledPath := pfPath("pf-was-enabled")

	if pfIsEnabled() {
		os.WriteFile(wasEnabledPath, []byte("1"), 0600)
	} else {
		os.Remove(wasEnabledPath)
	}

	ifaceRules := buildWGInterfaceRules()
	rules := fmt.Sprintf(`block drop quick inet6 all
pass quick on lo0 all
pass out quick proto udp to %s port %d
%s
block drop quick proto {tcp, udp} to any port 53
block drop all
`, serverIP, serverPort, ifaceRules)

	if err := os.WriteFile(rulesPath, []byte(rules), 0600); err != nil {
		return err
	}

	if out, err := exec.Command("sudo", "pfctl", "-e").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "already enabled") {
			return fmt.Errorf("enabling pf: %w\n%s", err, out)
		}
	}
	if out, err := exec.Command("sudo", "pfctl", "-a", anchorName, "-f", rulesPath).CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf rules: %w\n%s", err, out)
	}
	return nil
}

func disableKillSwitch() error {
	rulesPath := pfPath("pf-cloak.conf")
	wasEnabledPath := pfPath("pf-was-enabled")

	var restoreErr error
	if out, err := exec.Command("sudo", "-n", "pfctl", "-a", anchorName, "-F", "all").CombinedOutput(); err != nil {
		restoreErr = fmt.Errorf("pf flush failed: %s", strings.TrimSpace(string(out)))
	}

	if _, err := os.Stat(wasEnabledPath); err != nil { // file missing = pf wasn't enabled before
		if out, err := exec.Command("sudo", "-n", "pfctl", "-d").CombinedOutput(); err != nil && restoreErr == nil {
			restoreErr = fmt.Errorf("pf disable failed: %s", strings.TrimSpace(string(out)))
		}
	}

	if restoreErr != nil {
		return restoreErr
	}
	os.Remove(rulesPath)
	os.Remove(pfPath("pf-backup.conf"))
	os.Remove(wasEnabledPath)
	return nil
}

func isKillSwitchEnabled() (bool, error) {
	if !pfIsEnabled() {
		return false, nil
	}
	rulesPath := pfPath("pf-cloak.conf")
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		return false, nil
	}
	out, err := exec.Command("sudo", "-n", "pfctl", "-a", anchorName, "-s", "rules").CombinedOutput()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

func buildWGInterfaceRules() string {
	if ifaces := detectWGInterfaces(); len(ifaces) > 0 {
		lines := make([]string, len(ifaces))
		for i, iface := range ifaces {
			lines[i] = fmt.Sprintf("pass quick on %s all", iface)
		}
		return strings.Join(lines, "\n")
	}
	// Fallback: allow utun0-31 if detection fails.
	lines := make([]string, 32)
	for i := range lines {
		lines[i] = fmt.Sprintf("pass quick on utun%d all", i)
	}
	return strings.Join(lines, "\n")
}

func detectWGInterfaces() []string {
	out, err := exec.Command("sudo", "-n", "wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		return nil
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	sort.Strings(fields)
	return fields
}

func pfIsEnabled() bool {
	out, err := exec.Command("sudo", "-n", "pfctl", "-s", "info").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: Enabled")
}

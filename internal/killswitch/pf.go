//go:build darwin

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// PFKillSwitch implements KillSwitch using macOS's pf (Packet Filter).
type PFKillSwitch struct {
	backupPath       string // Path to backed-up pf rules.
	rulesPath        string // Path to cloak's pf anchor rules.
	pfWasEnabledPath string // Marker file: pf was already enabled before us.
	anchorName       string // pf anchor where Cloak rules are loaded.
}

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	configDir, _ := os.UserHomeDir()
	base := filepath.Join(configDir, ".config", "cloak")
	return &PFKillSwitch{
		backupPath:       filepath.Join(base, "pf-backup.conf"),
		rulesPath:        filepath.Join(base, "pf-cloak.conf"),
		pfWasEnabledPath: filepath.Join(base, "pf-was-enabled"),
		anchorName:       "com.apple/cloak",
	}
}

func (ks *PFKillSwitch) Enable(serverIP string, serverPort int) error {
	// Record whether pf was already enabled so we can restore that state.
	if pfIsEnabled() {
		os.WriteFile(ks.pfWasEnabledPath, []byte("1"), 0600)
	} else {
		os.Remove(ks.pfWasEnabledPath)
	}

	ifaceRules := buildWGInterfaceRules()

	rules := fmt.Sprintf(`# Cloak VPN Kill Switch
# Block all IPv6 (prevents IPv6 leak outside tunnel)
block drop quick inet6 all
# Allow loopback
pass quick on lo0 all
# Allow traffic to VPN server (needed to maintain tunnel)
pass out quick proto udp to %s port %d
# Allow all traffic on WireGuard interface
%s
# Block DNS outside tunnel (DNS leak protection)
block drop quick proto {tcp, udp} to any port 53
# Block everything else
block drop all
`, serverIP, serverPort, ifaceRules)

	if err := os.WriteFile(ks.rulesPath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("writing pf rules: %w", err)
	}

	// Enable pf and load rules into a dedicated anchor.
	// Using com.apple/* keeps Cloak isolated and avoids replacing the global ruleset.
	if out, err := exec.Command("sudo", "pfctl", "-e").CombinedOutput(); err != nil {
		// "already enabled" is fine, any other error is a problem.
		if !strings.Contains(string(out), "already enabled") {
			return fmt.Errorf("enabling pf: %w\n%s", err, out)
		}
	}
	if out, err := exec.Command("sudo", "pfctl", "-a", ks.anchorName, "-f", ks.rulesPath).CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf anchor rules: %w\n%s", err, out)
	}

	return nil
}

func (ks *PFKillSwitch) Disable() error {
	// Use sudo -n (non-interactive) throughout. If credentials expired,
	// we must fail loudly rather than hang or silently leave pf blocking traffic.
	var restoreErr error

	// Remove Cloak rules from our dedicated anchor only.
	if out, err := exec.Command("sudo", "-n", "pfctl", "-a", ks.anchorName, "-F", "all").CombinedOutput(); err != nil {
		restoreErr = fmt.Errorf("pf anchor flush failed (sudo expired? run: sudo pfctl -a %s -F all): %s", ks.anchorName, strings.TrimSpace(string(out)))
	}

	// If pf was NOT enabled before we touched it, disable it again.
	_, wasEnabled := os.Stat(ks.pfWasEnabledPath) // err == nil means file exists
	if wasEnabled != nil {
		if out, err := exec.Command("sudo", "-n", "pfctl", "-d").CombinedOutput(); err != nil && restoreErr == nil {
			restoreErr = fmt.Errorf("pf disable failed (sudo expired? run: sudo pfctl -d): %s", strings.TrimSpace(string(out)))
		}
	}

	// Only clean up state files after successful restore.
	// If restore failed, keep files so a retry can still find them.
	if restoreErr != nil {
		return restoreErr
	}

	os.Remove(ks.rulesPath)
	os.Remove(ks.backupPath)
	os.Remove(ks.pfWasEnabledPath)
	return nil
}

func (ks *PFKillSwitch) IsEnabled() (bool, error) {
	// We only consider Cloak kill switch active when:
	// 1) pf is currently enabled, and
	// 2) our generated rules file still exists.
	//
	// This avoids false positives from generic pf rules like "block drop all"
	// that may exist outside Cloak.
	if !pfIsEnabled() {
		return false, nil
	}
	if _, err := os.Stat(ks.rulesPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("checking pf kill switch state file: %w", err)
	}
	out, err := exec.Command("sudo", "-n", "pfctl", "-a", ks.anchorName, "-s", "rules").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("checking pf kill switch anchor rules: %w\n%s", err, out)
	}
	return strings.TrimSpace(string(out)) != "", nil
}

func buildWGInterfaceRules() string {
	ifaces := detectWGInterfaces()
	if len(ifaces) > 0 {
		lines := make([]string, 0, len(ifaces))
		for _, iface := range ifaces {
			lines = append(lines, fmt.Sprintf("pass quick on %s all", iface))
		}
		return strings.Join(lines, "\n")
	}

	// Fallback: allow a wide utun range if detection fails.
	lines := make([]string, 0, 32)
	for i := 0; i <= 31; i++ {
		lines = append(lines, fmt.Sprintf("pass quick on utun%d all", i))
	}
	return strings.Join(lines, "\n")
}

// detectWGInterfaces returns active WireGuard interface names (e.g. "utun4", "utun8").
func detectWGInterfaces() []string {
	out, err := exec.Command("sudo", "-n", "wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		return nil
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(fields))
	for _, iface := range fields {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		set[iface] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}

	result := make([]string, 0, len(set))
	for iface := range set {
		result = append(result, iface)
	}
	sort.Strings(result)
	return result
}

// pfIsEnabled checks whether pf is currently enabled.
func pfIsEnabled() bool {
	out, err := exec.Command("sudo", "-n", "pfctl", "-s", "info").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: Enabled")
}

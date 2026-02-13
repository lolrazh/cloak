//go:build darwin

package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PFKillSwitch implements KillSwitch using macOS's pf (Packet Filter).
type PFKillSwitch struct {
	backupPath    string // Path to backed-up pf rules.
	rulesPath     string // Path to cloak's pf anchor rules.
	pfWasEnabledPath string // Marker file: pf was already enabled before us.
}

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	configDir, _ := os.UserHomeDir()
	base := filepath.Join(configDir, ".config", "cloak")
	return &PFKillSwitch{
		backupPath:       filepath.Join(base, "pf-backup.conf"),
		rulesPath:        filepath.Join(base, "pf-cloak.conf"),
		pfWasEnabledPath: filepath.Join(base, "pf-was-enabled"),
	}
}

func (ks *PFKillSwitch) Enable(serverIP string, serverPort int) error {
	// Record whether pf was already enabled so we can restore that state.
	if pfIsEnabled() {
		os.WriteFile(ks.pfWasEnabledPath, []byte("1"), 0600)
	} else {
		os.Remove(ks.pfWasEnabledPath)
	}

	// Build kill switch rules.
	// Allow: loopback, VPN server endpoint, WireGuard interface, block everything else.
	rules := fmt.Sprintf(`# Cloak VPN Kill Switch
# Block all IPv6 (prevents IPv6 leak outside tunnel)
block drop quick inet6 all
# Allow loopback
pass quick on lo0 all
# Allow traffic to VPN server (needed to maintain tunnel)
pass out quick proto udp to %s port %d
# Allow all traffic on WireGuard interfaces (utun*)
pass quick on utun0 all
pass quick on utun1 all
pass quick on utun2 all
pass quick on utun3 all
# Block DNS outside tunnel (DNS leak protection)
block drop quick proto {tcp, udp} to any port 53
# Block everything else
block drop all
`, serverIP, serverPort)

	if err := os.WriteFile(ks.rulesPath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("writing pf rules: %w", err)
	}

	// Enable pf and load our rules.
	if out, err := exec.Command("sudo", "pfctl", "-e").CombinedOutput(); err != nil {
		// "already enabled" is fine, any other error is a problem.
		if !strings.Contains(string(out), "already enabled") {
			return fmt.Errorf("enabling pf: %w\n%s", err, out)
		}
	}
	if out, err := exec.Command("sudo", "pfctl", "-f", ks.rulesPath).CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf rules: %w\n%s", err, out)
	}

	return nil
}

func (ks *PFKillSwitch) Disable() error {
	// Restore macOS default pf rules from /etc/pf.conf.
	// This is the system-managed config with proper anchor definitions —
	// much safer than trying to replay captured pfctl -sr output.
	if _, err := os.Stat("/etc/pf.conf"); err == nil {
		if out, err := exec.Command("sudo", "pfctl", "-f", "/etc/pf.conf").CombinedOutput(); err != nil {
			// If restore fails, flush everything as a fallback.
			exec.Command("sudo", "pfctl", "-F", "all").CombinedOutput()
			fmt.Fprintf(os.Stderr, "Warning: restoring /etc/pf.conf failed: %s\n", out)
		}
	} else {
		exec.Command("sudo", "pfctl", "-F", "all").CombinedOutput()
	}

	// If pf was NOT enabled before we touched it, disable it again.
	_, wasEnabled := os.Stat(ks.pfWasEnabledPath) // err == nil means file exists
	if wasEnabled != nil {
		exec.Command("sudo", "pfctl", "-d").CombinedOutput()
	}

	// Clean up our files.
	os.Remove(ks.rulesPath)
	os.Remove(ks.backupPath)
	os.Remove(ks.pfWasEnabledPath)
	return nil
}

func (ks *PFKillSwitch) IsEnabled() (bool, error) {
	out, err := exec.Command("sudo", "pfctl", "-sr").CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(out), "Cloak VPN Kill Switch") ||
		strings.Contains(string(out), "block drop all"), nil
}

// pfIsEnabled checks whether pf is currently enabled.
func pfIsEnabled() bool {
	out, err := exec.Command("sudo", "pfctl", "-s", "info").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: Enabled")
}

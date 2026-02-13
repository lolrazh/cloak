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
	backupPath string // Path to backed-up pf rules.
	rulesPath  string // Path to cloak's pf anchor rules.
}

// New returns a platform-specific KillSwitch.
func New() KillSwitch {
	configDir, _ := os.UserHomeDir()
	base := filepath.Join(configDir, ".config", "cloak")
	return &PFKillSwitch{
		backupPath: filepath.Join(base, "pf-backup.conf"),
		rulesPath:  filepath.Join(base, "pf-cloak.conf"),
	}
}

func (ks *PFKillSwitch) Enable(serverIP string, serverPort int) error {
	// Backup current pf state.
	out, err := exec.Command("sudo", "pfctl", "-sr").CombinedOutput()
	if err != nil {
		// pf may not have rules loaded — that's OK.
		out = []byte("# no existing rules\n")
	}
	if err := os.WriteFile(ks.backupPath, out, 0600); err != nil {
		return fmt.Errorf("backing up pf rules: %w", err)
	}

	// Build kill switch rules.
	// Allow: loopback, VPN server endpoint, WireGuard interface, block everything else.
	rules := fmt.Sprintf(`# Cloak VPN Kill Switch
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

	// Enable pf and load rules.
	cmds := []struct{ args []string }{
		{[]string{"sudo", "pfctl", "-e"}},              // Enable pf (may already be enabled).
		{[]string{"sudo", "pfctl", "-f", ks.rulesPath}}, // Load our rules.
	}
	for _, cmd := range cmds {
		exec.Command(cmd.args[0], cmd.args[1:]...).CombinedOutput()
	}

	return nil
}

func (ks *PFKillSwitch) Disable() error {
	// Restore backup rules if they exist.
	if _, err := os.Stat(ks.backupPath); err == nil {
		exec.Command("sudo", "pfctl", "-f", ks.backupPath).CombinedOutput()
		os.Remove(ks.backupPath)
	} else {
		// No backup — just flush all rules and disable pf.
		exec.Command("sudo", "pfctl", "-F", "all").CombinedOutput()
		exec.Command("sudo", "pfctl", "-d").CombinedOutput()
	}

	os.Remove(ks.rulesPath)
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

// Package vpn manages the WireGuard tunnel, kill switch, and DNS.
package vpn

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/lolrazh/cloak/internal/config"
)

// Connect brings the tunnel up and enables the kill switch.
// Fail-closed: if the kill switch fails, the tunnel is torn down.
func Connect(cfg *config.Config) error {
	confPath, err := config.WGConfPath()
	if err != nil {
		return err
	}

	if isUp() {
		if cfg.Server != nil {
			enableKillSwitch(cfg.Server.Host, cfg.Port)
		}
		return nil
	}

	if err := tunnelUp(confPath); err != nil {
		return err
	}

	if cfg.Server != nil {
		if err := enableKillSwitch(cfg.Server.Host, cfg.Port); err != nil {
			tunnelDown(confPath)
			return fmt.Errorf("kill switch failed, tunnel brought down: %w", err)
		}
	}
	return nil
}

// Disconnect tears down the kill switch, tunnel, and restores DNS.
func Disconnect() error {
	ksErr := disableKillSwitch()

	confPath, err := config.WGConfPath()
	if err != nil {
		return err
	}
	if err := tunnelDown(confPath); err != nil {
		return err
	}

	restoreDNS()

	if ksErr != nil {
		return fmt.Errorf("disconnected but kill switch failed: %w", ksErr)
	}
	return nil
}

// Cleanup is best-effort teardown for signal handlers.
func Cleanup() {
	disableKillSwitch()
	if isUp() {
		if p, err := config.WGConfPath(); err == nil {
			tunnelDown(p)
		}
	}
	restoreDNS()
}

// IsKillSwitchEnabled reports whether kill switch firewall rules are active.
func IsKillSwitchEnabled() (bool, error) {
	return isKillSwitchEnabled()
}

// --- tunnel helpers (wg-quick wrapper) ---

func tunnelUp(confPath string) error {
	out, err := exec.Command("sudo", "wg-quick", "up", confPath).CombinedOutput()
	if err != nil {
		s := strings.ToLower(string(out))
		if strings.Contains(s, "already exists") || strings.Contains(s, "exists as") {
			return nil
		}
		return fmt.Errorf("wg-quick up: %w\n%s", err, out)
	}
	return nil
}

func tunnelDown(confPath string) error {
	out, err := exec.Command("sudo", "wg-quick", "down", confPath).CombinedOutput()
	if err != nil {
		s := strings.ToLower(string(out))
		if strings.Contains(s, "is not a wireguard interface") || strings.Contains(s, "unable to access interface") {
			return nil
		}
		return fmt.Errorf("wg-quick down: %w\n%s", err, out)
	}
	return nil
}

func isUp() bool {
	out, err := exec.Command("sudo", "-n", "wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

func restoreDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	for _, iface := range []string{"Wi-Fi", "Ethernet"} {
		exec.Command("networksetup", "-setdnsservers", iface, "Empty").CombinedOutput()
	}
}

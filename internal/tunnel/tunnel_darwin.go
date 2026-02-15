//go:build darwin

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"
)

// DarwinManager manages WireGuard via wg-quick on macOS.
// Requires wireguard-tools: `brew install wireguard-tools`
type DarwinManager struct{}

// NewManager returns a platform-specific tunnel manager.
func NewManager() Manager {
	return &DarwinManager{}
}

func (m *DarwinManager) Up(confPath string) error {
	// wg-quick on macOS uses wireguard-go userspace + utun interfaces.
	out, err := exec.Command("sudo", "wg-quick", "up", confPath).CombinedOutput()
	if err != nil {
		// Make connect idempotent: if interface already exists, treat as success.
		if isAlreadyUpOutput(string(out)) {
			return nil
		}
		return fmt.Errorf("wg-quick up: %w\n%s", err, out)
	}
	return nil
}

func (m *DarwinManager) Down(confPath string) error {
	out, err := exec.Command("sudo", "wg-quick", "down", confPath).CombinedOutput()
	if err != nil {
		// Make disconnect idempotent: if interface is already gone, treat as success.
		if isAlreadyDownOutput(string(out)) {
			return nil
		}
		return fmt.Errorf("wg-quick down: %w\n%s", err, out)
	}
	return nil
}

func (m *DarwinManager) IsUp() (bool, error) {
	out, err := exec.Command("sudo", "wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		// wg show fails if no interfaces — that means not up.
		return false, nil
	}
	return strings.TrimSpace(string(out)) != "", nil
}

func isAlreadyDownOutput(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "is not a wireguard interface") ||
		strings.Contains(s, "unable to access interface")
}

func isAlreadyUpOutput(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "already exists") ||
		strings.Contains(s, "exists as")
}

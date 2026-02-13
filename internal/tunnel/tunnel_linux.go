//go:build linux

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"
)

// LinuxManager manages WireGuard via wg-quick on Linux.
// Uses the kernel WireGuard module when available.
type LinuxManager struct{}

// NewManager returns a platform-specific tunnel manager.
func NewManager() Manager {
	return &LinuxManager{}
}

func (m *LinuxManager) Up(confPath string) error {
	out, err := exec.Command("sudo", "wg-quick", "up", confPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up: %w\n%s", err, out)
	}
	return nil
}

func (m *LinuxManager) Down(confPath string) error {
	out, err := exec.Command("sudo", "wg-quick", "down", confPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick down: %w\n%s", err, out)
	}
	return nil
}

func (m *LinuxManager) IsUp() (bool, error) {
	out, err := exec.Command("sudo", "wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(out), "wg0"), nil
}

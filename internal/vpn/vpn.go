// Package vpn orchestrates tunnel + kill switch operations.
package vpn

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/tunnel"
)

// Connect brings the tunnel up and enables the kill switch.
// Fail-closed: if the kill switch fails, the tunnel is torn down.
func Connect(cfg *config.Config) error {
	confPath, err := config.WGConfPath()
	if err != nil {
		return fmt.Errorf("WG config path: %w", err)
	}

	mgr := tunnel.NewManager()

	// Idempotent: if already up, just ensure kill switch is active.
	if up, _ := mgr.IsUp(); up {
		if cfg.Server != nil {
			ks := killswitch.New()
			ks.Enable(cfg.Server.Host, cfg.Port)
		}
		return nil
	}

	if err := mgr.Up(confPath); err != nil {
		return fmt.Errorf("bringing tunnel up: %w", err)
	}

	if cfg.Server != nil {
		ks := killswitch.New()
		if err := ks.Enable(cfg.Server.Host, cfg.Port); err != nil {
			if downErr := mgr.Down(confPath); downErr != nil {
				return fmt.Errorf("kill switch failed (%v) and rollback failed (%v)", err, downErr)
			}
			return fmt.Errorf("kill switch failed, tunnel brought down: %w", err)
		}
	}

	return nil
}

// Disconnect tears down the kill switch, tunnel, and restores DNS.
func Disconnect() error {
	ks := killswitch.New()
	ksErr := ks.Disable()

	confPath, err := config.WGConfPath()
	if err != nil {
		return fmt.Errorf("WG config path: %w", err)
	}

	mgr := tunnel.NewManager()
	if err := mgr.Down(confPath); err != nil {
		return fmt.Errorf("bringing tunnel down: %w", err)
	}

	restoreDNS()

	if ksErr != nil {
		return fmt.Errorf("disconnected but kill switch disable failed: %w", ksErr)
	}
	return nil
}

// Cleanup is a best-effort teardown for signal handlers.
// It never returns errors — just tries to clean up whatever it can.
func Cleanup() {
	ks := killswitch.New()
	ks.Disable()

	mgr := tunnel.NewManager()
	if up, _ := mgr.IsUp(); up {
		if confPath, err := config.WGConfPath(); err == nil {
			mgr.Down(confPath)
		}
	}

	restoreDNS()
}

func restoreDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	for _, iface := range []string{"Wi-Fi", "Ethernet"} {
		exec.Command("networksetup", "-setdnsservers", iface, "Empty").CombinedOutput()
	}
}

// Package tunnel manages the WireGuard tunnel lifecycle.
//
// It provides a platform-independent interface with platform-specific
// implementations selected via Go build tags (tunnel_linux.go, tunnel_darwin.go).
package tunnel

import "strings"

// Manager controls the WireGuard tunnel.
type Manager interface {
	// Up brings the WireGuard tunnel up using the given config path.
	Up(confPath string) error

	// Down tears down the WireGuard tunnel.
	Down(confPath string) error

	// IsUp returns true if the WireGuard tunnel is currently active.
	IsUp() (bool, error)
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

// Package tunnel manages the WireGuard tunnel lifecycle.
//
// It provides a platform-independent interface with platform-specific
// implementations selected via Go build tags (tunnel_linux.go, tunnel_darwin.go).
package tunnel

// Manager controls the WireGuard tunnel.
type Manager interface {
	// Up brings the WireGuard tunnel up using the given config path.
	Up(confPath string) error

	// Down tears down the WireGuard tunnel.
	Down(confPath string) error

	// IsUp returns true if the WireGuard tunnel is currently active.
	IsUp() (bool, error)
}

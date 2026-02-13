// Package killswitch manages firewall rules to prevent traffic leaks
// outside the WireGuard tunnel.
//
// When enabled, it blocks all network traffic except:
//   - Traffic through the WireGuard interface (wg0 / utun*)
//   - Traffic to the VPN server endpoint (needed to establish the tunnel)
//   - Loopback traffic
//
// DNS leak protection blocks port 53 outside the tunnel, forcing all
// DNS queries through the tunnel's configured DNS (1.1.1.1).
package killswitch

// KillSwitch controls platform-specific firewall rules.
type KillSwitch interface {
	// Enable activates the kill switch, backing up existing rules first.
	Enable(serverIP string, serverPort int) error

	// Disable removes kill switch rules and restores the original state.
	Disable() error

	// IsEnabled returns true if kill switch rules are currently active.
	IsEnabled() (bool, error)
}

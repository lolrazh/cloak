// Package status gathers VPN connection metrics.
//
// It parses `wg show` output for handshake time and transfer stats,
// checks the external IP, and measures latency to the server.
package status

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
)

// Info holds a snapshot of VPN connection status.
type Info struct {
	Connected     bool
	ExternalIP    string
	Latency       time.Duration
	LastHandshake time.Duration // Time since last handshake.
	TxBytes       int64
	RxBytes       int64
	KillSwitch    bool
	KillSwitchErr string // Non-empty if kill switch check failed.
	PermErr       string // Non-empty if sudo/permission check failed.
	StatusErr     string // Non-empty if status check failed for other reasons.
}

// GatherAll collects VPN status including kill switch state.
func GatherAll(cfg *config.Config) Info {
	var serverIP, serverPublicKey string
	if cfg.Server != nil {
		serverIP = cfg.Server.Host
		serverPublicKey = cfg.Server.PublicKey
	}
	info := gather(serverIP, serverPublicKey)

	ks := killswitch.New()
	enabled, err := ks.IsEnabled()
	info.KillSwitch = enabled
	if err != nil {
		info.KillSwitchErr = err.Error()
	}

	return info
}

func gather(serverIP, serverPublicKey string) Info {
	info := Info{}

	// Check if the configured Cloak peer is present in wg dump output.
	// Use a 3-second timeout so dashboard polling doesn't hang on sudo prompts.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wgOut, err := exec.CommandContext(ctx, "sudo", "-n", "wg", "show", "all", "dump").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(wgOut))
		info.PermErr, info.StatusErr = classifyWGShowError(err, outStr, ctx.Err() != nil)
		info.Connected = false
		return info
	}
	if len(strings.TrimSpace(string(wgOut))) == 0 {
		info.Connected = false
		return info
	}

	stats, ok := findMatchingPeerStats(string(wgOut), serverIP, serverPublicKey)
	if !ok {
		info.Connected = false
		return info
	}

	info.Connected = true
	info.RxBytes = stats.rxBytes
	info.TxBytes = stats.txBytes
	if stats.latestHandshakeUnix > 0 {
		hs := time.Unix(stats.latestHandshakeUnix, 0)
		if now := time.Now(); now.After(hs) {
			info.LastHandshake = now.Sub(hs)
		}
	}

	// Get external IP.
	info.ExternalIP = FetchExternalIP()

	// Measure latency to server.
	if serverIP != "" {
		info.Latency = measureLatency(serverIP)
	}

	return info
}

type peerStats struct {
	latestHandshakeUnix int64
	rxBytes             int64
	txBytes             int64
}

func findMatchingPeerStats(dump, serverIP, serverPublicKey string) (peerStats, bool) {
	var currentInterface string
	for _, rawLine := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) == 5 {
			// Interface line:
			// interface-name, private-key, public-key, listen-port, fwmark
			currentInterface = strings.TrimSpace(fields[0])
			continue
		}
		if len(fields) < 8 || currentInterface == "" {
			continue
		}

		// Peer line:
		// public-key, preshared-key, endpoint, allowed-ips,
		// latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
		peerPublicKey := strings.TrimSpace(fields[0])
		endpoint := strings.TrimSpace(fields[2])
		if !matchesPeer(peerPublicKey, endpoint, serverIP, serverPublicKey) {
			continue
		}

		latestHandshake, _ := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64)
		rxBytes, _ := strconv.ParseInt(strings.TrimSpace(fields[5]), 10, 64)
		txBytes, _ := strconv.ParseInt(strings.TrimSpace(fields[6]), 10, 64)

		return peerStats{
			latestHandshakeUnix: latestHandshake,
			rxBytes:             rxBytes,
			txBytes:             txBytes,
		}, true
	}
	return peerStats{}, false
}

func matchesPeer(peerPublicKey, endpoint, serverIP, serverPublicKey string) bool {
	return (serverPublicKey != "" && peerPublicKey == serverPublicKey) ||
		(serverIP != "" && endpointMatchesHost(endpoint, serverIP))
}

func endpointMatchesHost(endpoint, host string) bool {
	if endpoint == "" || endpoint == "(none)" || host == "" {
		return false
	}

	endpointHost := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		endpointHost = h
	} else {
		// Fallback for endpoints not in host:port form.
		if i := strings.LastIndex(endpoint, ":"); i > 0 {
			endpointHost = endpoint[:i]
		}
	}

	endpointHost = strings.Trim(endpointHost, "[]")
	host = strings.Trim(host, "[]")
	return strings.EqualFold(endpointHost, host)
}

func classifyWGShowError(err error, out string, timedOut bool) (permErr, statusErr string) {
	if timedOut {
		return "", "status check timed out"
	}

	lowerOut := strings.ToLower(out)
	lowerErr := strings.ToLower(err.Error())
	if isPermissionError(lowerOut) || isPermissionError(lowerErr) {
		return "sudo auth required — run `sudo -v` first", ""
	}

	msg := out
	if msg == "" {
		msg = err.Error()
	}
	first := strings.TrimSpace(strings.SplitN(msg, "\n", 2)[0])
	if first == "" {
		first = "unknown status error"
	}
	return "", first
}

func isPermissionError(s string) bool {
	markers := []string{
		"a password is required",
		"password is required",
		"terminal is required to read the password",
		"no tty present and no askpass program specified",
		"permission denied",
		"not in the sudoers file",
		"sorry, try again",
		"authentication failure",
		"must be run as root",
		"operation not permitted",
	}
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// FetchExternalIP returns the public IP via api.ipify.org, or "unknown" on failure.
func FetchExternalIP() string {
	// Force IPv4 dialer — the kill switch blocks all IPv6, so a dual-stack
	// dial would stall waiting for the IPv6 attempt to timeout first.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(body))
}

func measureLatency(host string) time.Duration {
	// Use ICMP ping via the system ping command.
	// TCP-based probes fail because the server only listens on UDP.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host).CombinedOutput()
	if err != nil {
		return 0
	}
	return parsePingRTT(string(out))
}

// parsePingRTT extracts the round-trip time from ping output.
// macOS format: "round-trip min/avg/max/stddev = 1.234/1.234/1.234/0.000 ms"
func parsePingRTT(output string) time.Duration {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "round-trip") && !strings.Contains(line, "rtt") {
			continue
		}
		// Extract the avg value from "min/avg/max/stddev = X/Y/Z/W ms"
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[eqIdx+1:])
		parts := strings.Fields(rest)
		if len(parts) < 1 {
			continue
		}
		vals := strings.Split(parts[0], "/")
		if len(vals) < 2 {
			continue
		}
		avg, err := strconv.ParseFloat(vals[1], 64)
		if err != nil {
			continue
		}
		return time.Duration(avg * float64(time.Millisecond))
	}
	return 0
}

// FormatBytes converts bytes to a human-readable string.
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

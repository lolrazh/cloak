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

// Gather collects current VPN status information.
// serverIP and serverPublicKey identify the expected Cloak peer.
func Gather(serverIP, serverPublicKey string) Info {
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
	info.ExternalIP = fetchExternalIP()

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
	if serverPublicKey != "" && peerPublicKey == serverPublicKey {
		return true
	}
	if serverIP != "" && endpointMatchesHost(endpoint, serverIP) {
		return true
	}
	return false
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

// parseWGShow extracts handshake and transfer info from `wg show` output.
func parseWGShow(output string, info *Info) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "latest handshake:") {
			info.LastHandshake = parseHandshake(line)
		}

		if strings.HasPrefix(line, "transfer:") {
			parseLine := strings.TrimPrefix(line, "transfer:")
			parseLine = strings.TrimSpace(parseLine)
			parts := strings.Split(parseLine, ",")
			if len(parts) >= 2 {
				info.RxBytes = parseBytes(strings.TrimSpace(parts[0]))
				info.TxBytes = parseBytes(strings.TrimSpace(parts[1]))
			}
		}
	}
}

// parseHandshake parses "latest handshake: X minutes, Y seconds ago".
func parseHandshake(line string) time.Duration {
	s := strings.TrimPrefix(line, "latest handshake:")
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "ago")
	s = strings.TrimSpace(s)

	var total time.Duration
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part)
		if len(fields) != 2 {
			continue
		}
		val, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(fields[1], "second"):
			total += time.Duration(val) * time.Second
		case strings.HasPrefix(fields[1], "minute"):
			total += time.Duration(val) * time.Minute
		case strings.HasPrefix(fields[1], "hour"):
			total += time.Duration(val) * time.Hour
		}
	}
	return total
}

// parseBytes parses "123.45 MiB received" → bytes.
func parseBytes(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	unit := strings.ToLower(fields[1])
	switch {
	case strings.HasPrefix(unit, "kib"):
		return int64(val * 1024)
	case strings.HasPrefix(unit, "mib"):
		return int64(val * 1024 * 1024)
	case strings.HasPrefix(unit, "gib"):
		return int64(val * 1024 * 1024 * 1024)
	case strings.HasPrefix(unit, "b"):
		return int64(val)
	default:
		return int64(val)
	}
}

func fetchExternalIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
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
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0
	}
	conn.Close()
	return time.Since(start)
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

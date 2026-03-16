// Package status gathers VPN connection metrics from wg show.
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
	"github.com/lolrazh/cloak/internal/vpn"
)

type Info struct {
	Connected     bool
	ExternalIP    string
	Latency       time.Duration
	LastHandshake time.Duration
	TxBytes, RxBytes int64
	KillSwitch    bool
	KillSwitchErr string
	PermErr       string
	StatusErr     string
}

// GatherAll collects VPN + kill switch status.
func GatherAll(cfg *config.Config) Info {
	var serverIP, serverPub string
	if cfg.Server != nil {
		serverIP = cfg.Server.Host
		serverPub = cfg.Server.PublicKey
	}

	info := gather(serverIP, serverPub)
	info.KillSwitch, _ = vpn.IsKillSwitchEnabled()
	return info
}

func gather(serverIP, serverPub string) Info {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sudo", "-n", "wg", "show", "all", "dump").CombinedOutput()
	if err != nil {
		s := strings.ToLower(string(out) + err.Error())
		if ctx.Err() != nil {
			return Info{StatusErr: "timed out"}
		}
		if strings.Contains(s, "password") || strings.Contains(s, "permission denied") {
			return Info{PermErr: "sudo required — run `sudo -v`"}
		}
		return Info{StatusErr: firstLine(string(out), err.Error())}
	}

	dump := string(out)
	if strings.TrimSpace(dump) == "" {
		return Info{}
	}

	rx, tx, hs, ok := findPeerStats(dump, serverIP, serverPub)
	if !ok {
		return Info{}
	}

	info := Info{Connected: true, RxBytes: rx, TxBytes: tx}
	if hs > 0 {
		info.LastHandshake = time.Since(time.Unix(hs, 0))
	}
	info.ExternalIP = FetchExternalIP()
	if serverIP != "" {
		info.Latency = measureLatency(serverIP)
	}
	return info
}

func findPeerStats(dump, serverIP, serverPub string) (rx, tx, handshake int64, ok bool) {
	var hasInterface bool
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) == 5 {
			hasInterface = true
			continue
		}
		if len(fields) < 8 || !hasInterface {
			continue
		}
		peerKey, endpoint := fields[0], fields[2]
		if (serverPub != "" && peerKey == serverPub) || (serverIP != "" && endpointHas(endpoint, serverIP)) {
			hs, _ := strconv.ParseInt(fields[4], 10, 64)
			r, _ := strconv.ParseInt(fields[5], 10, 64)
			t, _ := strconv.ParseInt(fields[6], 10, 64)
			return r, t, hs, true
		}
	}
	return 0, 0, 0, false
}

func endpointHas(endpoint, host string) bool {
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.EqualFold(h, host)
	}
	return false
}

func firstLine(parts ...string) string {
	for _, p := range parts {
		if s := strings.TrimSpace(strings.SplitN(p, "\n", 2)[0]); s != "" {
			return s
		}
	}
	return "unknown error"
}

// FetchExternalIP returns the public IP or "unknown".
func FetchExternalIP() string {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp4", addr)
		},
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: transport}).Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func measureLatency(host string) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host).CombinedOutput()
	if err != nil {
		return 0
	}
	// Parse "round-trip min/avg/max/stddev = X/Y/Z/W ms"
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "="); i >= 0 && (strings.Contains(line, "round-trip") || strings.Contains(line, "rtt")) {
			if vals := strings.Split(strings.Fields(strings.TrimSpace(line[i+1:]))[0], "/"); len(vals) >= 2 {
				if avg, err := strconv.ParseFloat(vals[1], 64); err == nil {
					return time.Duration(avg * float64(time.Millisecond))
				}
			}
		}
	}
	return 0
}

func FormatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

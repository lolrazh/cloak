package status

import (
	"testing"
	"time"
)

func TestParseWGShow(t *testing.T) {
	output := `interface: wg0
  public key: abc123
  private key: (hidden)
  listening port: 51820

peer: xyz789
  endpoint: 203.0.113.42:51820
  allowed ips: 0.0.0.0/0
  latest handshake: 1 minute, 30 seconds ago
  transfer: 45.67 MiB received, 12.34 MiB sent
`

	info := &Info{}
	parseWGShow(output, info)

	// Handshake should be 90 seconds.
	if info.LastHandshake != 90*time.Second {
		t.Errorf("LastHandshake = %v, want %v", info.LastHandshake, 90*time.Second)
	}

	// Transfer: 45.67 MiB received.
	rxMiB := 45.67
	expectedRx := int64(rxMiB * 1024 * 1024)
	if abs(info.RxBytes-expectedRx) > 1024 {
		t.Errorf("RxBytes = %d, want ~%d", info.RxBytes, expectedRx)
	}

	// Transfer: 12.34 MiB sent.
	txMiB := 12.34
	expectedTx := int64(txMiB * 1024 * 1024)
	if abs(info.TxBytes-expectedTx) > 1024 {
		t.Errorf("TxBytes = %d, want ~%d", info.TxBytes, expectedTx)
	}
}

func TestParseHandshake(t *testing.T) {
	tests := []struct {
		line string
		want time.Duration
	}{
		{"latest handshake: 30 seconds ago", 30 * time.Second},
		{"latest handshake: 2 minutes, 15 seconds ago", 2*time.Minute + 15*time.Second},
		{"latest handshake: 1 hour, 5 minutes ago", 1*time.Hour + 5*time.Minute},
	}
	for _, tt := range tests {
		got := parseHandshake(tt.line)
		if got != tt.want {
			t.Errorf("parseHandshake(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"100 B received", 100},
		{"1.5 KiB received", 1536},
		{"10.0 MiB sent", 10 * 1024 * 1024},
		{"2.5 GiB received", int64(2.5 * 1024 * 1024 * 1024)},
	}
	for _, tt := range tests {
		got := parseBytes(tt.input)
		if abs(got-tt.want) > 1 {
			t.Errorf("parseBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024 * 5, "5.0 MB"},
		{1024 * 1024 * 1024 * 2, "2.0 GB"},
	}
	for _, tt := range tests {
		got := FormatBytes(tt.input)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

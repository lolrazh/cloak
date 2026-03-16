package status

import (
	"fmt"
	"testing"
)

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

func TestClassifyWGShowError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		out        string
		timedOut   bool
		wantPerm   bool
		wantStatus bool
	}{
		{
			name:       "permission required",
			err:        fmt.Errorf("exit status 1"),
			out:        "sudo: a password is required",
			wantPerm:   true,
			wantStatus: false,
		},
		{
			name:       "timeout",
			err:        fmt.Errorf("signal: killed"),
			timedOut:   true,
			wantPerm:   false,
			wantStatus: true,
		},
		{
			name:       "generic wg failure",
			err:        fmt.Errorf("exit status 1"),
			out:        "wg: command not found",
			wantPerm:   false,
			wantStatus: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permErr, statusErr := classifyWGShowError(tt.err, tt.out, tt.timedOut)
			if tt.wantPerm && permErr == "" {
				t.Fatalf("expected permission error, got empty")
			}
			if !tt.wantPerm && permErr != "" {
				t.Fatalf("expected no permission error, got %q", permErr)
			}
			if tt.wantStatus && statusErr == "" {
				t.Fatalf("expected status error, got empty")
			}
			if !tt.wantStatus && statusErr != "" {
				t.Fatalf("expected no status error, got %q", statusErr)
			}
		})
	}
}

func TestFindMatchingPeerStatsByPublicKey(t *testing.T) {
	dump := "" +
		"utun5\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t198.51.100.10:51820\t0.0.0.0/0\t1700000000\t100\t200\t25\n" +
		"utun7\tprivB\tpubB\t0\toff\n" +
		"peer-2\t(none)\t203.0.113.42:51820\t0.0.0.0/0\t1700000010\t300\t400\t25\n"

	stats, ok := findMatchingPeerStats(dump, "", "peer-2")
	if !ok {
		t.Fatalf("expected peer match by public key")
	}
	if stats.latestHandshakeUnix != 1700000010 || stats.rxBytes != 300 || stats.txBytes != 400 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestFindMatchingPeerStatsByEndpoint(t *testing.T) {
	dump := "" +
		"wg0\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t203.0.113.42:51820\t0.0.0.0/0\t1700000005\t111\t222\t25\n"

	stats, ok := findMatchingPeerStats(dump, "203.0.113.42", "")
	if !ok {
		t.Fatalf("expected peer match by endpoint host")
	}
	if stats.rxBytes != 111 || stats.txBytes != 222 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestFindMatchingPeerStatsNoMatch(t *testing.T) {
	dump := "" +
		"wg0\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t192.0.2.10:51820\t0.0.0.0/0\t1700000005\t111\t222\t25\n"

	if _, ok := findMatchingPeerStats(dump, "203.0.113.42", "peer-2"); ok {
		t.Fatalf("expected no match")
	}
}

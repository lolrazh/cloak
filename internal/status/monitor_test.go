package status

import "testing"

func TestFormatBytes(t *testing.T) {
	for _, tt := range []struct {
		in   int64
		want string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024 * 5, "5.0 MB"},
		{1024 * 1024 * 1024 * 2, "2.0 GB"},
	} {
		if got := FormatBytes(tt.in); got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFindPeerStatsByPublicKey(t *testing.T) {
	dump := "utun5\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t198.51.100.10:51820\t0.0.0.0/0\t1700000000\t100\t200\t25\n" +
		"utun7\tprivB\tpubB\t0\toff\n" +
		"peer-2\t(none)\t203.0.113.42:51820\t0.0.0.0/0\t1700000010\t300\t400\t25\n"

	rx, tx, hs, ok := findPeerStats(dump, "", "peer-2")
	if !ok || rx != 300 || tx != 400 || hs != 1700000010 {
		t.Fatalf("unexpected: rx=%d tx=%d hs=%d ok=%v", rx, tx, hs, ok)
	}
}

func TestFindPeerStatsByEndpoint(t *testing.T) {
	dump := "wg0\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t203.0.113.42:51820\t0.0.0.0/0\t1700000005\t111\t222\t25\n"

	rx, tx, _, ok := findPeerStats(dump, "203.0.113.42", "")
	if !ok || rx != 111 || tx != 222 {
		t.Fatalf("unexpected: rx=%d tx=%d ok=%v", rx, tx, ok)
	}
}

func TestFindPeerStatsNoMatch(t *testing.T) {
	dump := "wg0\tprivA\tpubA\t0\toff\n" +
		"peer-1\t(none)\t192.0.2.10:51820\t0.0.0.0/0\t1700000005\t111\t222\t25\n"

	if _, _, _, ok := findPeerStats(dump, "203.0.113.42", "peer-2"); ok {
		t.Fatal("expected no match")
	}
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/lolrazh/cloak/cmd"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/tunnel"
)

func main() {
	// Handle SIGINT/SIGTERM: clean disconnect before exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
		cleanup()
		os.Exit(0)
	}()

	_ = ctx // passed to commands in future iterations
	cmd.Execute()
}

// cleanup attempts a graceful disconnect on signal.
func cleanup() {
	// Disable kill switch first.
	ks := killswitch.New()
	if err := ks.Disable(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: kill switch disable failed during cleanup: %v\n", err)
	}

	mgr := tunnel.NewManager()
	up, _ := mgr.IsUp()
	if up {
		fmt.Fprintln(os.Stderr, "\nCaught signal, cleaning up...")

		// Bring tunnel down.
		confPath := findWGConf()
		if confPath != "" {
			mgr.Down(confPath)
		}
	}

	// Safety net: restore DNS.
	if runtime.GOOS == "darwin" {
		for _, iface := range []string{"Wi-Fi", "Ethernet"} {
			exec.Command("networksetup", "-setdnsservers", iface, "Empty").CombinedOutput()
		}
	}
}

func findWGConf() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := home + "/.config/cloak/wg0.conf"
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

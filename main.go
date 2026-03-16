package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/lolrazh/cloak/cmd"
	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/killswitch"
	"github.com/lolrazh/cloak/internal/tunnel"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cleanup()
		os.Exit(0)
	}()

	cmd.Execute()
}

func cleanup() {
	ks := killswitch.New()
	if err := ks.Disable(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: kill switch disable failed during cleanup: %v\n", err)
	}

	mgr := tunnel.NewManager()
	if up, _ := mgr.IsUp(); up {
		fmt.Fprintln(os.Stderr, "\nCaught signal, cleaning up...")
		if confPath, err := config.WGConfPath(); err == nil {
			mgr.Down(confPath)
		}
	}

	if runtime.GOOS == "darwin" {
		for _, iface := range []string{"Wi-Fi", "Ethernet"} {
			exec.Command("networksetup", "-setdnsservers", iface, "Empty").CombinedOutput()
		}
	}
}

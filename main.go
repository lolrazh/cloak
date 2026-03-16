package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lolrazh/cloak/cmd"
	"github.com/lolrazh/cloak/internal/vpn"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nCaught signal, cleaning up...")
		vpn.Cleanup()
		os.Exit(0)
	}()

	cmd.Execute()
}

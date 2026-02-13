package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/lolrazh/cloak/internal/config"
	"github.com/lolrazh/cloak/internal/wgkeys"
	"github.com/spf13/cobra"
)

var forceInit bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Cloak config and generate WireGuard keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if config already exists.
		if _, err := config.Load(); err == nil && !forceInit {
			return fmt.Errorf("config already exists (use --force to overwrite)")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) && !forceInit {
			return fmt.Errorf("reading existing config: %w", err)
		}

		// Generate key pair.
		kp, err := wgkeys.Generate()
		if err != nil {
			return fmt.Errorf("generating keys: %w", err)
		}

		// Build config with defaults + generated keys.
		cfg := config.Defaults()
		cfg.PrivateKey = kp.Private.String()
		cfg.PublicKey = kp.Public.String()

		// Save.
		if err := config.Save(&cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		path, _ := config.FilePath()
		fmt.Println("Cloak initialized.")
		fmt.Printf("  Config: %s\n", path)
		fmt.Printf("  Public key: %s\n", cfg.PublicKey)
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Overwrite existing config")
	rootCmd.AddCommand(initCmd)
}

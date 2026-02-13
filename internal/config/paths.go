// Package config handles Cloak's configuration storage.
//
// Config lives at ~/.config/cloak/cloak.yaml with 0600 permissions.
// WireGuard configs are generated at ~/.config/cloak/wg0.conf.
package config

import (
	"os"
	"path/filepath"
)

const (
	dirName    = "cloak"
	configFile = "cloak.yaml"
	wgConfFile = "wg0.conf"
)

// Dir returns the Cloak config directory.
// Prefers XDG_CONFIG_HOME if set, otherwise falls back to ~/.config.
func Dir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, dirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", dirName), nil
}

// FilePath returns the full path to cloak.yaml.
func FilePath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFile), nil
}

// WGConfPath returns the full path to wg0.conf.
func WGConfPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, wgConfFile), nil
}

// EnsureDir creates the config directory if it doesn't exist (0700 perms).
func EnsureDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

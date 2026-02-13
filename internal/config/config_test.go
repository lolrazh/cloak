package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Subnet != "10.0.0.0/24" {
		t.Errorf("Subnet = %q, want %q", cfg.Subnet, "10.0.0.0/24")
	}
	if cfg.Port != 51820 {
		t.Errorf("Port = %d, want %d", cfg.Port, 51820)
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Use a temp directory as config dir.
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg := Defaults()
	cfg.PrivateKey = "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2"
	cfg.PublicKey = "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3"

	if err := Save(&cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file exists with correct permissions.
	path := filepath.Join(tmpDir, dirName, configFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config file not found: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("config file perms = %o, want 0600", perm)
	}

	// Load it back.
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.PrivateKey != cfg.PrivateKey {
		t.Errorf("PrivateKey = %q, want %q", loaded.PrivateKey, cfg.PrivateKey)
	}
	if loaded.PublicKey != cfg.PublicKey {
		t.Errorf("PublicKey = %q, want %q", loaded.PublicKey, cfg.PublicKey)
	}
	if loaded.Port != cfg.Port {
		t.Errorf("Port = %d, want %d", loaded.Port, cfg.Port)
	}
}

func TestLoadMissing(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	_, err := Load()
	if !os.IsNotExist(err) {
		t.Errorf("Load() on missing file: got %v, want os.ErrNotExist", err)
	}
}

func TestSaveWithServer(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg := Defaults()
	cfg.PrivateKey = "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2"
	cfg.PublicKey = "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3"
	cfg.Server = &ServerConfig{
		Host:       "203.0.113.42",
		User:       "ubuntu",
		SSHKeyPath: "/home/user/.ssh/id_ed25519",
		PublicKey:  "c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1",
		Endpoint:   "203.0.113.42:51820",
	}

	if err := Save(&cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.Server == nil {
		t.Fatal("Server config is nil after load")
	}
	if loaded.Server.Host != "203.0.113.42" {
		t.Errorf("Server.Host = %q, want %q", loaded.Server.Host, "203.0.113.42")
	}
}

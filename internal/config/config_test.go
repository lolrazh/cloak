package config

import (
	"encoding/base64"
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
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg := Defaults()
	cfg.PrivateKey = "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2"
	cfg.PublicKey = "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3"

	if err := Save(&cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	path := filepath.Join(tmpDir, dirName, configFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config file not found: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("config file perms = %o, want 0600", perm)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.PrivateKey != cfg.PrivateKey || loaded.PublicKey != cfg.PublicKey || loaded.Port != cfg.Port {
		t.Errorf("round-trip mismatch: got %+v", loaded)
	}
}

func TestLoadMissing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := Load()
	if !os.IsNotExist(err) {
		t.Errorf("Load() on missing file: got %v, want os.ErrNotExist", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if kp.Private == [keyLen]byte{} || kp.Public == [keyLen]byte{} {
		t.Fatal("generated zero key")
	}
	if kp.Private == kp.Public {
		t.Fatal("private and public keys are identical")
	}
	// Clamping checks.
	if kp.Private[0]&7 != 0 {
		t.Errorf("first byte low 3 bits not cleared: %08b", kp.Private[0])
	}
	if kp.Private[31]&128 != 0 {
		t.Errorf("last byte bit 7 not cleared: %08b", kp.Private[31])
	}
	if kp.Private[31]&64 == 0 {
		t.Errorf("last byte bit 6 not set: %08b", kp.Private[31])
	}
}

func TestKeyToBase64(t *testing.T) {
	kp, _ := GenerateKeyPair()
	s := KeyToBase64(kp.Private)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(b) != keyLen {
		t.Fatalf("decoded key length = %d, want %d", len(b), keyLen)
	}
}

func TestUniqueKeys(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if kp1.Private == kp2.Private {
		t.Fatal("two generated private keys are identical")
	}
}

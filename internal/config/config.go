// Package config handles Cloak's configuration, paths, and WireGuard key generation.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

const (
	dirName    = "cloak"
	configFile = "cloak.yaml"
	wgConfFile = "wg0.conf"
	keyLen     = 32
)

// Config is the top-level Cloak configuration stored in cloak.yaml.
type Config struct {
	PrivateKey string        `yaml:"private_key"`
	PublicKey  string        `yaml:"public_key"`
	Subnet     string        `yaml:"subnet"`
	Port       int           `yaml:"port"`
	Server     *ServerConfig `yaml:"server,omitempty"`
}

type ServerConfig struct {
	Host       string `yaml:"host"`
	User       string `yaml:"user"`
	SSHKeyPath string `yaml:"ssh_key_path"`
	PublicKey  string `yaml:"public_key"`
	Endpoint   string `yaml:"endpoint"`
}

func Defaults() Config {
	return Config{Subnet: "10.0.0.0/24", Port: 51820}
}

// --- Paths ---

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

func FilePath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFile), nil
}

func WGConfPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, wgConfFile), nil
}

func EnsureDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return dir, os.MkdirAll(dir, 0700)
}

// --- Load / Save ---

func Load() (*Config, error) {
	path, err := FilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

func Save(cfg *Config) error {
	if _, err := EnsureDir(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	path, err := FilePath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// --- WireGuard Keys ---

type KeyPair struct {
	Private [keyLen]byte
	Public  [keyLen]byte
}

func GenerateKeyPair() (KeyPair, error) {
	var priv [keyLen]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	var kp KeyPair
	kp.Private = priv
	copy(kp.Public[:], pub)
	return kp, nil
}

func KeyToBase64(k [keyLen]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

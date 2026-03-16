package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Cloak configuration stored in cloak.yaml.
type Config struct {
	// Client WireGuard keys (base64-encoded).
	PrivateKey string `yaml:"private_key"`
	PublicKey  string `yaml:"public_key"`

	// Network defaults.
	Subnet string `yaml:"subnet"`
	Port   int    `yaml:"port"`

	// Server info (populated after `cloak server setup`).
	Server *ServerConfig `yaml:"server,omitempty"`
}

// ServerConfig holds the provisioned server details.
type ServerConfig struct {
	Host       string `yaml:"host"`
	User       string `yaml:"user"`
	SSHKeyPath string `yaml:"ssh_key_path"`
	PublicKey  string `yaml:"public_key"`
	Endpoint   string `yaml:"endpoint"`
}

// Defaults returns a Config with sensible default values (keys empty).
func Defaults() Config {
	return Config{
		Subnet: "10.0.0.0/24",
		Port:   51820,
	}
}

// Load reads and parses cloak.yaml. Returns os.ErrNotExist if the file is missing.
func Load() (*Config, error) {
	path, err := FilePath()
	if err != nil {
		return nil, fmt.Errorf("config path: %w", err)
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

// Save writes the config to cloak.yaml with 0600 permissions.
func Save(cfg *Config) error {
	if _, err := EnsureDir(); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	path, err := FilePath()
	if err != nil {
		return fmt.Errorf("config path: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

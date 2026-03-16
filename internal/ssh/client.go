// Package ssh provides SSH client and server provisioning.
package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lolrazh/cloak/internal/config"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	conn *ssh.Client
	user string
}

func Connect(host, user, keyPath string) (*Client, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: tofuCallback(host),
		Timeout:         10 * time.Second,
	}

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	return &Client{conn: conn, user: user}, nil
}

func (c *Client) Run(cmd string) (string, error) {
	s, err := c.conn.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	if err != nil {
		return string(out), fmt.Errorf("%q: %w\n%s", cmd, err, out)
	}
	return string(out), nil
}

func (c *Client) RunSudo(cmd string) (string, error) { return c.Run("sudo " + cmd) }

func (c *Client) WriteFile(path, content, mode string) error {
	cmd := fmt.Sprintf("cat > %s && chmod %s %s", path, mode, path)
	if c.user != "root" {
		cmd = "sudo sh -c '" + cmd + "'"
	}
	s, err := c.conn.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Stdin = strings.NewReader(content)
	out, err := s.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("writing %s: %w\n%s", path, err, out)
	}
	return nil
}

func (c *Client) Close() error { return c.conn.Close() }

// --- TOFU host key verification ---

func knownHostsPath() string {
	dir, _ := config.Dir()
	return filepath.Join(dir, "known_hosts")
}

func tofuCallback(host string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		path := knownHostsPath()
		known := loadKnownHosts(path)

		bareHost := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			bareHost = h
		}

		if saved, ok := known[bareHost]; ok {
			if saved != fp {
				return fmt.Errorf("HOST KEY MISMATCH for %s!\n  Expected: %s\n  Got: %s\nRemove old entry from: %s",
					bareHost, saved, fp, path)
			}
			return nil
		}

		fmt.Printf("  Trusting new host key for %s: %s\n", bareHost, fp)
		known[bareHost] = fp
		return saveKnownHosts(path, known)
	}
}

func loadKnownHosts(path string) map[string]string {
	known := make(map[string]string)
	data, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(data), "\n") {
		if parts := strings.SplitN(line, " ", 2); len(parts) == 2 {
			known[parts[0]] = parts[1]
		}
	}
	return known
}

func saveKnownHosts(path string, known map[string]string) error {
	lines := make([]string, 0, len(known))
	for host, fp := range known {
		lines = append(lines, host+" "+fp)
	}
	os.MkdirAll(filepath.Dir(path), 0700)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

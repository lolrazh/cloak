// Package ssh provides SSH client functionality for server provisioning.
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

// Client wraps an SSH connection to a remote server.
type Client struct {
	conn *ssh.Client
	host string
	user string
}

// Connect establishes an SSH connection to the given host.
// Uses Trust On First Use (TOFU) for host key verification:
// first connection saves the key, subsequent connections verify it.
func Connect(host, user, keyPath string) (*Client, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key %s: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: tofuHostKeyCallback(host),
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

	return &Client{conn: conn, host: host, user: user}, nil
}

// Run executes a command on the remote server and returns combined output.
func (c *Client) Run(cmd string) (string, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return string(out), fmt.Errorf("running %q: %w\noutput: %s", cmd, err, out)
	}
	return string(out), nil
}

// RunSudo executes a command with sudo on the remote server.
func (c *Client) RunSudo(cmd string) (string, error) {
	return c.Run("sudo " + cmd)
}

// WriteFile writes content to a remote file path via stdin.
func (c *Client) WriteFile(path, content string, mode string) error {
	cmd := fmt.Sprintf("cat > %s && chmod %s %s", path, mode, path)
	if c.user != "root" {
		cmd = "sudo sh -c '" + cmd + "'"
	}

	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	defer session.Close()

	session.Stdin = strings.NewReader(content)
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("writing %s: %w\noutput: %s", path, err, out)
	}
	return nil
}

// Close terminates the SSH connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func knownHostsPath() string {
	dir, _ := config.Dir()
	return filepath.Join(dir, "known_hosts")
}

// tofuHostKeyCallback implements Trust On First Use:
// first connection saves the fingerprint, subsequent connections verify it.
func tofuHostKeyCallback(host string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		khPath := knownHostsPath()

		known := loadKnownHosts(khPath)
		bareHost := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			bareHost = h
		}

		if saved, ok := known[bareHost]; ok {
			if saved != fingerprint {
				return fmt.Errorf(
					"HOST KEY MISMATCH for %s!\n"+
						"  Expected: %s\n"+
						"  Got:      %s\n"+
						"This could indicate a MITM attack.\n"+
						"If the server was reprovisioned, remove the old entry from:\n  %s",
					bareHost, saved, fingerprint, khPath)
			}
			return nil
		}

		fmt.Printf("  Trusting new host key for %s: %s\n", bareHost, fingerprint)
		known[bareHost] = fingerprint
		return saveKnownHosts(khPath, known)
	}
}

func loadKnownHosts(path string) map[string]string {
	known := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return known
	}
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
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

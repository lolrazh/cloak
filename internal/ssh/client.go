// Package ssh provides SSH client functionality for server provisioning.
package ssh

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client wraps an SSH connection to a remote server.
type Client struct {
	conn *ssh.Client
	host string
	user string
}

// Connect establishes an SSH connection to the given host.
func Connect(host, user, keyPath string) (*Client, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key %s: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// TODO(M8): Store and verify host keys in ~/.config/cloak/known_hosts.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	conn, err := ssh.Dial("tcp", addr, config)
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

// WriteFile writes content to a remote file path via stdin (avoids shell escaping issues).
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

// Package wgconfig renders WireGuard configuration files from templates.
package wgconfig

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// ServerData holds values for the server WireGuard config template.
type ServerData struct {
	ServerAddress    string // e.g. "10.0.0.1/24"
	Port             int
	ServerPrivateKey string
	DefaultInterface string // e.g. "eth0"
	ClientPublicKey  string
	ClientAddress    string // e.g. "10.0.0.2"
}

// ClientData holds values for the client WireGuard config template.
type ClientData struct {
	ClientAddress    string // e.g. "10.0.0.2/24"
	ClientPrivateKey string
	ServerPublicKey  string
	ServerEndpoint   string // IP or hostname
	Port             int
}

// RenderServer renders the server WireGuard config.
func RenderServer(data ServerData) (string, error) {
	return render("templates/server.conf.tmpl", data)
}

// RenderClient renders the client WireGuard config.
func RenderClient(data ClientData) (string, error) {
	return render("templates/client.conf.tmpl", data)
}

func render(name string, data any) (string, error) {
	tmplBytes, err := templateFS.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("reading template %s: %w", name, err)
	}

	tmpl, err := template.New(name).Parse(string(tmplBytes))
	if err != nil {
		return "", fmt.Errorf("parsing template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template %s: %w", name, err)
	}
	return buf.String(), nil
}

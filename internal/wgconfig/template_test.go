package wgconfig

import (
	"strings"
	"testing"
)

func TestRenderServer(t *testing.T) {
	data := ServerData{
		ServerAddress:    "10.0.0.1/24",
		Port:             51820,
		ServerPrivateKey: "SERVER_PRIVATE_KEY",
		DefaultInterface: "eth0",
		ClientPublicKey:  "CLIENT_PUBLIC_KEY",
		ClientAddress:    "10.0.0.2",
	}

	out, err := RenderServer(data)
	if err != nil {
		t.Fatalf("RenderServer() error: %v", err)
	}

	checks := []string{
		"Address = 10.0.0.1/24",
		"ListenPort = 51820",
		"PrivateKey = SERVER_PRIVATE_KEY",
		"MASQUERADE",
		"eth0",
		"PublicKey = CLIENT_PUBLIC_KEY",
		"AllowedIPs = 10.0.0.2/32",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("server config missing %q\nGot:\n%s", want, out)
		}
	}
}

func TestRenderClient(t *testing.T) {
	data := ClientData{
		ClientAddress:    "10.0.0.2",
		ClientPrivateKey: "CLIENT_PRIVATE_KEY",
		ServerPublicKey:  "SERVER_PUBLIC_KEY",
		ServerEndpoint:   "203.0.113.42",
		Port:             51820,
	}

	out, err := RenderClient(data)
	if err != nil {
		t.Fatalf("RenderClient() error: %v", err)
	}

	checks := []string{
		"Address = 10.0.0.2/24",
		"PrivateKey = CLIENT_PRIVATE_KEY",
		"DNS = 1.1.1.1",
		"PublicKey = SERVER_PUBLIC_KEY",
		"Endpoint = 203.0.113.42:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("client config missing %q\nGot:\n%s", want, out)
		}
	}
}

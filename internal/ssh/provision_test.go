package ssh

import "testing"

func TestSubnetDetails(t *testing.T) {
	tests := []struct {
		name           string
		subnet         string
		wantServerCIDR string
		wantClientCIDR string
		wantClientIP   string
		wantErr        bool
	}{
		{
			name:           "24-bit subnet",
			subnet:         "10.0.0.0/24",
			wantServerCIDR: "10.0.0.1/24",
			wantClientCIDR: "10.0.0.2/24",
			wantClientIP:   "10.0.0.2",
		},
		{
			name:           "16-bit subnet",
			subnet:         "10.9.0.0/16",
			wantServerCIDR: "10.9.0.1/16",
			wantClientCIDR: "10.9.0.2/16",
			wantClientIP:   "10.9.0.2",
		},
		{
			name:           "30-bit subnet",
			subnet:         "192.168.1.252/30",
			wantServerCIDR: "192.168.1.253/30",
			wantClientCIDR: "192.168.1.254/30",
			wantClientIP:   "192.168.1.254",
		},
		{
			name:    "too small subnet /31",
			subnet:  "10.0.0.0/31",
			wantErr: true,
		},
		{
			name:    "too small subnet /32",
			subnet:  "10.0.0.1/32",
			wantErr: true,
		},
		{
			name:    "ipv6 unsupported",
			subnet:  "fd00::/64",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotServerCIDR, gotClientCIDR, gotClientIP, err := subnetDetails(tt.subnet)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("subnetDetails(%q) error = nil, want non-nil", tt.subnet)
				}
				return
			}
			if err != nil {
				t.Fatalf("subnetDetails(%q) error = %v", tt.subnet, err)
			}
			if gotServerCIDR != tt.wantServerCIDR {
				t.Errorf("server CIDR = %q, want %q", gotServerCIDR, tt.wantServerCIDR)
			}
			if gotClientCIDR != tt.wantClientCIDR {
				t.Errorf("client CIDR = %q, want %q", gotClientCIDR, tt.wantClientCIDR)
			}
			if gotClientIP != tt.wantClientIP {
				t.Errorf("client IP = %q, want %q", gotClientIP, tt.wantClientIP)
			}
		})
	}
}

package filter

import "testing"

func TestIsSystem(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST.", true},
		{"localdomain", true},
		{"localhost.localdomain", true},
		{"0.in-addr.arpa", true},
		{"127.in-addr.arpa", true},
		{"0.0.127.in-addr.arpa", true},
		{"255.in-addr.arpa", true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", true},
		{"10.in-addr.arpa", true},
		{"16.172.in-addr.arpa", true},
		{"31.172.in-addr.arpa", true},
		{"168.192.in-addr.arpa", true},
		{".", true},
		{"32.172.in-addr.arpa", false},
		{"15.172.in-addr.arpa", false},
		{"2.0.192.in-addr.arpa", false},
		{"example.com", false},
		{"localhost.example.com", false},
		{"1.168.192.in-addr.arpa", false},
	}
	for _, tt := range tests {
		if got := IsSystem(tt.name); got != tt.want {
			t.Errorf("IsSystem(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if len(SystemZones()) != 27 {
		t.Errorf("system zone count %d", len(SystemZones()))
	}
}

func TestExcluder(t *testing.T) {
	e := NewExcluder([]string{"*.local", "Server-Hostname.example.net.", "*.local"}, []string{"dev-*.example.com"})
	tests := []struct {
		name, want string
	}{
		{"printer.local", "*.local"},
		{"a.b.local", "*.local"},
		{"server-hostname.example.net", "server-hostname.example.net"},
		{"SERVER-HOSTNAME.EXAMPLE.NET.", "server-hostname.example.net"},
		{"dev-1.example.com", "dev-*.example.com"},
		{"example.com", ""},
		{"local", ""},
	}
	for _, tt := range tests {
		if got := e.Match(tt.name); got != tt.want {
			t.Errorf("Match(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	if len(e.Patterns()) != 3 {
		t.Errorf("patterns %v", e.Patterns())
	}
	var nilEx *Excluder
	if nilEx.Match("x") != "" {
		t.Error("nil excluder matched")
	}
}

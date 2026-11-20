package version

import "testing"

func TestLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
		{"1.2.3", "1.10.0", true},
		{"v1.2.3", "1.2.3", false},
		{"1.2.3-rc1", "1.2.3", true},
		{"1.2.3", "1.2.3-rc1", false},
		{"0.1.0-dev", "0.1.0", true},
		{"1.2.3-a", "1.2.3-b", true},
		{"junk", "1.0.0", false},
		{"1.0.0", "junk", false},
		{"1.0.0+build", "1.0.0", false},
	}
	for _, tt := range tests {
		if got := Less(tt.a, tt.b); got != tt.want {
			t.Errorf("Less(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
	if UserAgent() != "paneldns-agent/"+Version {
		t.Fatal(UserAgent())
	}
}

package source

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

// noListenerCheck stands in for the /proc check where the test server runs
// as the test user.
func noListenerCheck(string) error { return nil }

const passwd = "root:x:0:0::/root:/bin/sh\npdns:x:996:994::/var/spool/powerdns:/sbin/nologin\nmallory:x:1001:1001::/home/mallory:/bin/bash\n"

// /proc/net/tcp lines: 127.0.0.1:8081 is 0100007F:1F91, 0.0.0.0:8081 is
// 00000000:1F91; state 0A is LISTEN; the eighth field is the uid.
const tcpHead = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpLine(local, st, uid string) string {
	return "   0: " + local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000   " + uid + "        0 12345 1 0000000000000000 100 0 0 10 0\n"
}

func fakeSystem(tcp, tcp6 string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		switch p {
		case "/proc/net/tcp":
			return []byte(tcpHead + tcp), nil
		case "/proc/net/tcp6":
			return []byte(tcpHead + tcp6), nil
		case "/etc/passwd":
			return []byte(passwd), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestCheckListener(t *testing.T) {
	const base = "http://127.0.0.1:8081"
	tests := []struct {
		name, tcp, tcp6, want string
	}{
		{"pdns on loopback", tcpLine("0100007F:1F91", "0A", "996"), "", ""},
		{"pdns on any address", tcpLine("00000000:1F91", "0A", "996"), "", ""},
		{"root (a proxy)", tcpLine("0100007F:1F91", "0A", "0"), "", ""},
		// A local user holding the port while PowerDNS restarts.
		{"user squats the port", tcpLine("0100007F:1F91", "0A", "1001"), "", "uid 1001"},
		{"user on the v6 wildcard", tcpLine("00000000:1F91", "0A", "996"),
			"   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1\n", "uid 1001"},
		// An established connection (01) or another port is not a listener.
		{"no listener", tcpLine("0100007F:1F91", "01", "1001") + tcpLine("0100007F:1F92", "0A", "1001"), "", "nothing listens"},
	}
	for _, tt := range tests {
		err := checkListener(base, fakeSystem(tt.tcp, tt.tcp6))
		if tt.want == "" && err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
		if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: got %v, want %q", tt.name, err, tt.want)
		}
	}
	if err := checkListener("http://[::1]:8081", fakeSystem("", "   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   996        0 1 1\n")); err != nil {
		t.Errorf("pdns on ::1: %v", err)
	}
}

// The key is never sent when the check fails.
func TestPowerDNSChecksListenerBeforeSendingKey(t *testing.T) {
	keyFile := path.Join(t.TempDir(), "key")
	os.WriteFile(keyFile, []byte("secret-test-key\n"), 0o600)
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-Key")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	p := &PowerDNS{BaseURL: srv.URL, KeyFile: keyFile, CheckListener: func(base string) error {
		return checkListener(base, fakeSystem(tcpLine("0100007F:"+strings.ToUpper(srvPortHex(srv.URL)), "0A", "1001"), ""))
	}}
	if _, err := p.List(context.Background()); err == nil || !strings.Contains(err.Error(), "uid 1001") {
		t.Fatalf("got %v", err)
	}
	if got != "" {
		t.Fatalf("the key was sent to a listener owned by a user: %q", got)
	}
}

func srvPortHex(raw string) string {
	u, _ := url.Parse(raw)
	n, _ := strconv.Atoi(u.Port())
	return fmt.Sprintf("%04X", n)
}

package protocol

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientDebugValidResponseHidesInputs(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) {
		p, err := ReadPacket(c)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = c.Write(MakeResponse(2, p, []byte("transport-secret"), nil))
	})
	host, port, _ := net.SplitHostPort(addr)
	var lines []string
	result, err := Exchange(Config{Host: host, Port: port, ServerName: "localhost", CA: ca, Secret: "transport-secret", Timeout: 3 * time.Second, Trace: func(s string) { lines = append(lines, s) }}, Request{Kind: "auth", Username: "user-private", Password: "password-private", Extra: "NAS-Identifier = attribute-private"})
	if err != nil || result.Code != 2 {
		t.Fatalf("exchange failed: %v", err)
	}
	all := strings.Join(lines, "\n")
	for _, stage := range []string{"TLS handshake", "verification succeeded", "RADIUS request sent", "response ID, code, authenticator"} {
		if !strings.Contains(all, stage) {
			t.Errorf("missing stage %q in %s", stage, all)
		}
	}
	for _, forbidden := range []string{"transport-secret", "user-private", "password-private", "attribute-private", "localhost", "PRIVATE KEY"} {
		if strings.Contains(all, forbidden) {
			t.Errorf("sensitive value %q in debug output", forbidden)
		}
	}
}

func TestClientDebugForgedResponseDoesNotLeak(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) { p, _ := ReadPacket(c); _, _ = c.Write(MakeResponse(2, p, []byte("wrong"), nil)) })
	host, port, _ := net.SplitHostPort(addr)
	var lines []string
	_, err := Exchange(Config{Host: host, Port: port, ServerName: "localhost", CA: ca, Secret: "transport-secret", Timeout: time.Second, Trace: func(s string) { lines = append(lines, s) }}, Request{Kind: "auth", Username: "user-private", Password: "password-private"})
	if err == nil {
		t.Fatal("forgery accepted")
	}
	all := strings.Join(lines, "\n")
	if !strings.Contains(all, "response authenticator mismatch") {
		t.Errorf("missing fixed reason: %s", all)
	}
	for _, forbidden := range []string{"transport-secret", "user-private", "password-private"} {
		if strings.Contains(all, forbidden) {
			t.Errorf("sensitive value %q in debug", forbidden)
		}
	}
}

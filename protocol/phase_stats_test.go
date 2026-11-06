package protocol

import (
	"net"
	"testing"
	"time"
)

func TestObservedExchangePhasesRealTLSServer(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) {
		p, e := ReadPacket(c)
		if e != nil {
			t.Error(e)
			return
		}
		c.Write(MakeResponse(2, p, []byte("radsec"), nil))
	})
	h, port, _ := net.SplitHostPort(addr)
	res, e := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"prepare", "tcp dial", "tls handshake", "request write", "response read", "response verify"} {
		if _, ok := res.Observations.Phases[name]; !ok {
			t.Errorf("unobserved %s", name)
		}
	}
	if res.Observations.RequestBytes < 20 || res.Observations.ResponseBytes != 20 || res.Observations.PeerCerts != 1 || !res.Observations.TLSObserved {
		t.Fatalf("observations: %+v", res.Observations)
	}
}
func TestDialFailureDoesNotInventLaterPhases(t *testing.T) {
	res, e := Exchange(Config{Host: "127.0.0.1", Port: "1", Secret: "radsec", Timeout: 100 * time.Millisecond}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e == nil {
		t.Fatal("expected dial failure")
	}
	for _, name := range []string{"tls handshake", "request write", "response read", "response verify"} {
		if _, ok := res.Observations.Phases[name]; ok {
			t.Errorf("fabricated %s", name)
		}
	}
}

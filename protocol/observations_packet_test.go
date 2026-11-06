package protocol

import (
	"net"
	"testing"
	"time"
)

func TestPacketObservationsCountOnlyCompleteExchange(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) {
		p, err := ReadPacket(c)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = c.Write(MakeResponse(2, p, []byte("radsec"), nil))
		if err != nil {
			t.Error(err)
		}
	})
	host, port, _ := net.SplitHostPort(addr)
	r, err := Exchange(Config{Host: host, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: 3 * time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Observations.RequestPackets != 1 || r.Observations.ResponsePackets != 1 {
		t.Fatalf("packet counts: %+v", r.Observations)
	}
}

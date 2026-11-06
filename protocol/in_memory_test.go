package protocol

import (
	"net"
	"os"
	"testing"
)

func TestP12InMemoryInput(t *testing.T) {
	_, cert, key := localTLS(t, func(net.Conn) {})
	path := pfxFixture(t, cert, key, cert, "bundle-password")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	crt, err := loadP12(Config{P12Data: data, P12Pass: "bundle-password"})
	if err != nil || len(crt.Certificate) == 0 {
		t.Fatalf("in-memory P12 failed: %v", err)
	}
}

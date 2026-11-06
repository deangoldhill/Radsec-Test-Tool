package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// A RadSec server may advertise a CA hint unrelated to the configured P12.
// The explicitly selected identity should still be offered, leaving the server
// to accept/reject it according to its own certificate-verification policy.
func TestP12IsPresentedDespiteUnrelatedAdvertisedClientCA(t *testing.T) {
	testP12OfferWithUnrelatedCA(t, false)
}

func TestSavedP12IsPresentedDespiteUnrelatedAdvertisedClientCA(t *testing.T) {
	testP12OfferWithUnrelatedCA(t, true)
}

func testP12OfferWithUnrelatedCA(t *testing.T, saved bool) {
	t.Helper()
	_, serverPEM, serverKey := localTLS(t, func(net.Conn) {})
	serverCert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	unrelated := &x509.Certificate{
		SerialNumber: big.NewInt(983), Subject: pkix.Name{CommonName: "Unrelated Client Issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	unrelatedDER, err := x509.CreateCertificate(rand.Reader, unrelated, unrelated, &unrelatedKey.PublicKey, unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCert, err := x509.ParseCertificate(unrelatedDER)
	if err != nil {
		t.Fatal(err)
	}
	advertised := x509.NewCertPool()
	advertised.AddCert(unrelatedCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert, ClientCAs: advertised,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	received := make(chan bool, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			received <- false
			return
		}
		defer raw.Close()
		conn := raw.(*tls.Conn)
		if err := conn.Handshake(); err != nil {
			received <- false
			return
		}
		received <- len(conn.ConnectionState().PeerCertificates) > 0
		p, err := ReadPacket(conn)
		if err == nil {
			conn.Write(MakeResponse(2, p, []byte("radsec"), nil))
		}
	}()
	path := pfxFixture(t, serverPEM, serverKey, serverPEM, "p12-password")
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	cfg := Config{Host: host, Port: port, ServerName: "localhost", CA: serverPEM,
		P12Pass: "p12-password", Secret: "radsec", Timeout: 3 * time.Second}
	if saved {
		cfg.P12Data, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		cfg.P12Path = path
	}
	result, err := Exchange(cfg, Request{Kind: "auth", Username: "alice", Password: "password"})
	if err != nil || result.Code != 2 {
		t.Fatalf("P12 not offered/accepted: result=%+v err=%v", result, err)
	}
	if !<-received {
		t.Fatal("server did not receive the configured client certificate")
	}
}

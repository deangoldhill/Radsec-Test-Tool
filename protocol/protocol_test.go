package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func localTLS(t *testing.T, handle func(net.Conn), requireClient ...bool) (string, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if len(requireClient) > 0 && requireClient[0] {
		pool := x509.NewCertPool()
		parsed, _ := x509.ParseCertificate(der)
		pool.AddCert(parsed)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.MaxVersion = tls.VersionTLS12
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			if tc, ok := c.(*tls.Conn); ok {
				if e := tc.Handshake(); e != nil {
					t.Logf("server handshake: %v", e)
					return
				}
			}
			handle(c)
		}
	}()
	return ln.Addr().String(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
func TestTLSAccessAcceptAndAuthenticator(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) {
		p, e := ReadPacket(c)
		if e != nil {
			t.Error(e)
			return
		}
		if p[0] != 1 {
			t.Errorf("code %d", p[0])
		}
		if !bytes.Contains(p[20:], []byte("alice")) {
			t.Error("missing username")
		}
		if !VerifyMessageAuthenticator(p, []byte("radsec"), nil) {
			t.Error("request MA invalid")
		}
		r := MakeResponse(2, p, []byte("radsec"), nil)
		c.Write(r)
	})
	h, port, _ := net.SplitHostPort(addr)
	r, e := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: 3 * time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	if r.Code != 2 {
		t.Fatalf("code %d", r.Code)
	}
}
func TestRejectUntrustedServer(t *testing.T) {
	addr, _, _ := localTLS(t, func(c net.Conn) {})
	h, p, _ := net.SplitHostPort(addr)
	_, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e == nil || !strings.Contains(e.Error(), "certificate") {
		t.Fatalf("wanted certificate error: %v", e)
	}
}
func TestRejectForgedResponse(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) { p, _ := ReadPacket(c); r := MakeResponse(2, p, []byte("wrong"), nil); c.Write(r) })
	h, p, _ := net.SplitHostPort(addr)
	_, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e == nil || !strings.Contains(e.Error(), "authenticator") {
		t.Fatalf("wanted authenticator error: %v", e)
	}
}
func TestAccountingStatusAndAuthenticator(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) {
		p, e := ReadPacket(c)
		if e != nil {
			t.Error(e)
			return
		}
		if p[0] != 4 || !bytes.Contains(p, []byte("session-1")) {
			t.Error("bad accounting request")
		}
		r := MakeResponse(5, p, []byte("radsec"), nil)
		c.Write(r)
	})
	h, p, _ := net.SplitHostPort(addr)
	r, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "acct", Username: "alice", Status: "Interim-Update", SessionID: "session-1", SessionTime: 12})
	if e != nil || r.Code != 5 {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestExtraAttributesRejectSecretsAndMalformed(t *testing.T) {
	for _, s := range []string{"User-Password = abc", "Message-Authenticator = 00", "NAS-IP-Address = not-an-ip", "Unknown = x"} {
		_, e := ParseAttributes(s)
		if e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	a, e := ParseAttributes("NAS-IP-Address = 192.0.2.2; NAS-Identifier = lab")
	if e != nil || len(a) == 0 {
		t.Fatalf("%v %v", a, e)
	}
}

func TestMutualTLSClientCertificate(t *testing.T) {
	addr, ca, key := localTLS(t, func(c net.Conn) {
		p, e := ReadPacket(c)
		if e != nil {
			t.Error(e)
			return
		}
		c.Write(MakeResponse(2, p, []byte("radsec"), nil))
	}, true)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if e := os.WriteFile(certPath, ca, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	h, p, _ := net.SplitHostPort(addr)
	r, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CA: ca, CertPath: certPath, KeyPath: keyPath, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e != nil || r.Code != 2 {
		t.Fatalf("%+v %v", r, e)
	}
}
func pfxFixture(t *testing.T, certPEM, keyPEM, chainPEM []byte, password string) string {
	t.Helper()
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	chainBlock, _ := pem.Decode(chainPEM)
	if certBlock == nil || keyBlock == nil || chainBlock == nil {
		t.Fatal("invalid fixture PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := x509.ParseCertificate(chainBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.Encode(key, cert, []*x509.Certificate{chain}, password)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestP12MutualTLSAndChain(t *testing.T) {
	addr, serverCA, key := localTLS(t, func(c net.Conn) {
		p, err := ReadPacket(c)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = c.Write(MakeResponse(2, p, []byte("radsec"), nil))
		if err != nil {
			t.Error(err)
		}
	}, true)
	_, chain, _ := localTLS(t, func(net.Conn) {})
	path := pfxFixture(t, serverCA, key, chain, "correct-password")
	cert, err := loadP12(Config{P12Path: path, P12Pass: "correct-password"})
	if err != nil || len(cert.Certificate) != 2 {
		t.Fatalf("PFX chain length %d, err %v", len(cert.Certificate), err)
	}
	caPath := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caPath, serverCA, 0600); err != nil {
		t.Fatal(err)
	}
	h, p, _ := net.SplitHostPort(addr)
	r, err := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CAPath: caPath, P12Path: path, P12Pass: "correct-password", Secret: "radsec", Timeout: 3 * time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err != nil || r.Code != 2 {
		t.Fatalf("PFX mTLS: code %d, err %v", r.Code, err)
	}
}

func TestP12WrongPasswordRejected(t *testing.T) {
	_, cert, key := localTLS(t, func(net.Conn) {})
	path := pfxFixture(t, cert, key, cert, "correct-password")
	_, err := loadP12(Config{P12Path: path, P12Pass: "wrong-password"})
	if err == nil || strings.Contains(err.Error(), "correct-password") || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("wrong PFX password not safely rejected: %v", err)
	}
}

func TestP12AndPEMPathsMutuallyExclusive(t *testing.T) {
	for _, c := range []Config{{P12Path: "unused.pfx", CertPath: "unused.pem"}, {P12Path: "unused.pfx", KeyPath: "unused.key"}} {
		c.Secret = "radsec"
		_, err := Exchange(c, Request{Kind: "auth", Username: "alice", Password: "secret"})
		if err == nil || !strings.Contains(err.Error(), "P12") {
			t.Fatalf("mixed client credentials not rejected: %v", err)
		}
	}
}

func TestP12ChainDoesNotTrustServer(t *testing.T) {
	addr, serverCA, key := localTLS(t, func(net.Conn) {})
	_, unrelatedCA, _ := localTLS(t, func(net.Conn) {})
	path := pfxFixture(t, serverCA, key, serverCA, "correct-password")
	caPath := filepath.Join(t.TempDir(), "unrelated-ca.pem")
	if err := os.WriteFile(caPath, unrelatedCA, 0600); err != nil {
		t.Fatal(err)
	}
	h, p, _ := net.SplitHostPort(addr)
	_, err := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CAPath: caPath, P12Path: path, P12Pass: "correct-password", Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("client chain trusted as server CA: %v", err)
	}
}

func TestRejectBlankOrOversizedAuthPassword(t *testing.T) {
	for _, password := range []string{"", strings.Repeat("x", 129)} {
		_, e := build(Request{Kind: "auth", Username: "alice", Password: password}, "radsec")
		if e == nil {
			t.Errorf("accepted password length %d", len(password))
		}
	}
}

func TestWrongExplicitCARejected(t *testing.T) {
	addr, _, _ := localTLS(t, func(c net.Conn) {})
	_, wrong, _ := localTLS(t, func(c net.Conn) {})
	h, p, _ := net.SplitHostPort(addr)
	_, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CA: wrong, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e == nil || !strings.Contains(e.Error(), "certificate") {
		t.Fatalf("wrong CA accepted: %v", e)
	}
}
func TestValidAccessRejectIsNotTransportFailure(t *testing.T) {
	addr, ca, _ := localTLS(t, func(c net.Conn) { p, _ := ReadPacket(c); c.Write(MakeResponse(3, p, []byte("radsec"), nil)) })
	h, p, _ := net.SplitHostPort(addr)
	r, e := Exchange(Config{Host: h, Port: p, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if e != nil || r.Code != 3 || r.Name != "Access-Reject" {
		t.Fatalf("%+v %v", r, e)
	}
}

// The GUI deliberately does not use the peer certificate's SAN as an identity
// check, but it must still require a trusted CA, valid dates, and server auth.
func TestTrustedChainWithoutHostnameMatch(t *testing.T) {
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
	h, port, _ := net.SplitHostPort(addr)
	c := Config{Host: h, Port: port, ServerName: "not-in-the-san.example", SNI: "routing.example", SkipHostnameVerification: true, CA: ca, Secret: "radsec", Timeout: 3 * time.Second}
	r, err := Exchange(c, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err != nil || r.Code != 2 {
		t.Fatalf("trusted server with unrelated hostname rejected: result=%+v err=%v", r, err)
	}
}

func TestNoHostnameMatchStillRejectsUntrustedChain(t *testing.T) {
	addr, _, _ := localTLS(t, func(net.Conn) {})
	_, wrongCA, _ := localTLS(t, func(net.Conn) {})
	h, port, _ := net.SplitHostPort(addr)
	_, err := Exchange(Config{Host: h, Port: port, SNI: "routing.example", SkipHostnameVerification: true, CA: wrongCA, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("accepted server with untrusted chain: %v", err)
	}
}

func TestStrictHostnameVerificationRemainsDefault(t *testing.T) {
	addr, ca, _ := localTLS(t, func(net.Conn) {})
	h, port, _ := net.SplitHostPort(addr)
	_, err := Exchange(Config{Host: h, Port: port, ServerName: "not-in-the-san.example", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "secret"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("strict default accepted hostname mismatch: %v", err)
	}
}

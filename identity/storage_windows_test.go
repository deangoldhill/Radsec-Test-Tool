//go:build windows

package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"testing"
	"time"
)

func TestDPAPIRoundtripAndForget(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.Modern2023.Encode(key, cert, nil, "private-data")
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{P12: p12, Password: "private-data"}
	if err := Save(p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(os.Getenv("APPDATA"), "RadSecConnectionLab", "identity.dpapi")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-data")) || bytes.Contains(raw, p12) {
		t.Fatal("plaintext on disk")
	}
	bad := p
	bad.Password = "wrong-password"
	if err := Save(bad); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != p.Password || !bytes.Equal(got.P12, p.P12) {
		t.Fatal("roundtrip failed")
	}
	if err := Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("saved blob remains: %v", err)
	}
}

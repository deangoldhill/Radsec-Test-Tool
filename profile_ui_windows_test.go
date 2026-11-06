//go:build windows

package main

import (
	"os"
	"path/filepath"
	"radsec-windows-tester/testprofile"
	"testing"
)

func TestCollectFullProfileDelay(t *testing.T) {
	v := map[string]string{"host": "dummy.invalid", "port": "2083", "secret": "dummy-secret", "tls": "1.2", "credentials": "P12/PFX", "kind": "full", "delay": "375", "username": "dummy-user", "status": "Start", "sessiontime": "0", "requests": "1", "threads": "1", "timeout": "20"}
	p, err := collectProfile(v, &testprofile.Profile{Mode: "P12/PFX", P12: []byte("dummy P12")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != "full" || p.Delay != "375" {
		t.Fatal("full/delay omitted")
	}
}
func TestCollectProfileIncludesDummyCertificateFiles(t *testing.T) {
	d := t.TempDir()
	cert := filepath.Join(d, "dummy-cert.pem")
	key := filepath.Join(d, "dummy-key.pem")
	if err := os.WriteFile(cert, []byte("dummy cert only"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("dummy key only"), 0600); err != nil {
		t.Fatal(err)
	}
	v := map[string]string{"host": "dummy.invalid", "port": "2083", "secret": "dummy-secret", "tls": "1.2", "credentials": "Separate PEM", "cert": cert, "key": key, "kind": "auth", "username": "dummy-user", "password": "dummy-password", "status": "Start", "session": "dummy-session", "sessiontime": "0", "requests": "1", "threads": "1", "timeout": "20"}
	p, err := collectProfile(v, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Secret != v["secret"] || p.Password != v["password"] || string(p.Cert) != "dummy cert only" || string(p.Key) != "dummy key only" {
		t.Fatal("profile omitted fields or certificate contents")
	}
	got, err := testprofile.Encrypt(p, "dummy-passphrase-very-long")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("empty encrypted export")
	}
}

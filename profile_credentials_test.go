package main

import (
	"bytes"
	"radsec-windows-tester/testprofile"
	"testing"
)

func TestProfileCredentialsUseEmbeddedPEMMaterial(t *testing.T) {
	p := &testprofile.Profile{Mode: "Separate PEM", Cert: []byte("dummy cert"), Key: []byte("dummy key"), CA: []byte("dummy CA"), KeyPass: "dummy pass"}
	c, err := chooseProfileCredentials("Separate PEM", map[string]string{}, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.CertData, p.Cert) || !bytes.Equal(c.KeyData, p.Key) || !bytes.Equal(c.CA, p.CA) || c.KeyPass != p.KeyPass || c.CertPath != "" {
		t.Fatal("PEM profile not embedded")
	}
	cfg := guiTLSConfig("dummy.invalid", "2083", "", "dummy", c, 0x0303, 1)
	if !bytes.Equal(cfg.CertData, p.Cert) || !bytes.Equal(cfg.KeyData, p.Key) {
		t.Fatal("embedded cert bytes lost in config")
	}
}

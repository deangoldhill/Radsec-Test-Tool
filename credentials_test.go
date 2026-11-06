package main

import (
	"testing"
	"time"
)

func TestSeparatePEMSelection(t *testing.T) {
	in, err := chooseCredentials("Separate PEM", map[string]string{"ca": "trusted.pem", "cert": "client.pem", "key": "client.key", "keypass": "secret", "p12": "other.p12", "p12pass": "other"})
	if err != nil {
		t.Fatal(err)
	}
	if in.CAPath != "trusted.pem" || in.CertPath != "client.pem" || in.KeyPath != "client.key" || in.KeyPass != "secret" || in.P12Path != "" || in.P12Pass != "" {
		t.Fatalf("incorrect PEM selection: %+v", in)
	}
}
func TestP12Selection(t *testing.T) {
	in, err := chooseCredentials("P12/PFX", map[string]string{"ca": "trusted.pem", "cert": "stale.pem", "key": "stale.key", "keypass": "stale", "p12": "client.p12", "p12pass": "bundle-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if in.CAPath != "trusted.pem" || in.P12Path != "client.p12" || in.P12Pass != "bundle-secret" || in.CertPath != "" || in.KeyPath != "" || in.KeyPass != "" {
		t.Fatalf("incorrect P12 selection: %+v", in)
	}
}
func TestCredentialSelectionRejectsIncompleteAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		files map[string]string
	}{
		{"Separate PEM", map[string]string{"cert": "client.pem"}},
		{"P12/PFX", map[string]string{}},
		{"bogus", map[string]string{"p12": "client.p12"}},
	} {
		if _, err := chooseCredentials(tc.mode, tc.files); err == nil {
			t.Errorf("accepted %s %v", tc.mode, tc.files)
		}
	}
}

func TestGUIConfigDoesNotMatchHostnamesButRetainsTrustSettings(t *testing.T) {
	c := guiTLSConfig("192.0.2.10", "2083", "tenant-routing.example", "radius-secret", credentialInputs{CAPath: "trusted.pem", P12Path: "client.p12", P12Pass: "pass"}, 0x0303, 8*time.Second)
	if !c.SkipHostnameVerification || c.ServerName != "" || c.SNI != "tenant-routing.example" {
		t.Fatalf("GUI must use SNI for routing only, not require a matching SAN: %+v", c)
	}
	if c.Host != "192.0.2.10" || c.Port != "2083" || c.CAPath != "trusted.pem" || c.P12Path != "client.p12" || c.P12Pass != "pass" || c.Secret != "radius-secret" || c.MinTLS != 0x0303 || c.Timeout != 8*time.Second {
		t.Fatalf("lost connection, trust or credential setting: %+v", c)
	}
}

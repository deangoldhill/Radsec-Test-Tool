package main

import (
	"bytes"
	"radsec-windows-tester/identity"
	"testing"
)

func TestSavedIdentitySelectionDoesNotPersistOtherSecrets(t *testing.T) {
	p := &identity.Profile{P12: []byte{1, 2, 3}, Password: "p12-only", CA: []byte("ca")}
	c, e := chooseSavedCredentials("P12/PFX", map[string]string{"secret": "radius-secret", "password": "user-password"}, p)
	if e != nil {
		t.Fatal(e)
	}
	if c.P12Path != "" || !bytes.Equal(c.P12Data, p.P12) || c.P12Pass != "p12-only" || !bytes.Equal(c.CA, p.CA) {
		t.Fatal("saved credential not selected")
	}
	if c.P12Pass == "radius-secret" || c.P12Pass == "user-password" {
		t.Fatal("wrong secret forwarded")
	}
}
func TestExplicitPathOverridesSavedIdentity(t *testing.T) {
	c, e := chooseSavedCredentials("P12/PFX", map[string]string{"p12": "new.pfx", "p12pass": "new-pass", "ca": "new-ca.pem"}, &identity.Profile{P12: []byte{1}, Password: "old"})
	if e != nil || c.P12Path != "new.pfx" || len(c.P12Data) != 0 || c.CAPath != "new-ca.pem" {
		t.Fatalf("explicit path not selected: %+v %v", c, e)
	}
}

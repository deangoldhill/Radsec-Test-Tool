package main

import (
	"radsec-windows-tester/identity"
	"radsec-windows-tester/testprofile"
	"strings"
)

// An explicit file path wins over cached embedded credentials. A profile only
// supplies material when its own mode matches and neither file path was chosen.
func chooseProfileCredentials(mode string, values map[string]string, saved *testprofile.Profile, legacy *identity.Profile) (credentialInputs, error) {
	if saved != nil && saved.Mode == mode && strings.TrimSpace(values["p12"]) == "" && strings.TrimSpace(values["cert"]) == "" && strings.TrimSpace(values["key"]) == "" {
		c := credentialInputs{}
		if ca := strings.TrimSpace(values["ca"]); ca != "" {
			c.CAPath = ca
		} else {
			c.CA = append([]byte(nil), saved.CA...)
		}
		if mode == "P12/PFX" {
			c.P12Data = append([]byte(nil), saved.P12...)
			c.P12Pass = saved.P12Pass
		} else {
			c.CertData = append([]byte(nil), saved.Cert...)
			c.KeyData = append([]byte(nil), saved.Key...)
			c.KeyPass = saved.KeyPass
		}
		return c, nil
	}
	return chooseSavedCredentials(mode, values, legacy)
}

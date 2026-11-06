package main

import (
	"errors"
	"radsec-windows-tester/identity"
	"radsec-windows-tester/protocol"
	"strings"
	"time"
)

type credentialInputs struct {
	CAPath, CertPath, KeyPath, KeyPass, P12Path, P12Pass string
	P12Data, CA, CertData, KeyData                       []byte
}

func chooseSavedCredentials(mode string, values map[string]string, saved *identity.Profile) (credentialInputs, error) {
	if mode != "P12/PFX" || strings.TrimSpace(values["p12"]) != "" || saved == nil {
		return chooseCredentials(mode, values)
	}
	c := credentialInputs{P12Data: append([]byte(nil), saved.P12...), P12Pass: saved.Password}
	if ca := strings.TrimSpace(values["ca"]); ca != "" {
		c.CAPath = ca
	} else {
		c.CA = append([]byte(nil), saved.CA...)
	}
	return c, nil
}

// chooseCredentials keeps the trusted CA independent of the selected client format.
// Stale values in the other format are never forwarded to the TLS layer.
func chooseCredentials(mode string, values map[string]string) (credentialInputs, error) {
	get := func(key string) string { return strings.TrimSpace(values[key]) }
	out := credentialInputs{CAPath: get("ca")}
	switch mode {
	case "Separate PEM":
		out.CertPath, out.KeyPath, out.KeyPass = get("cert"), get("key"), values["keypass"]
		if out.CertPath == "" || out.KeyPath == "" {
			return credentialInputs{}, errors.New("select both the client certificate and private key PEM files")
		}
	case "P12/PFX":
		out.P12Path, out.P12Pass = get("p12"), values["p12pass"]
		if out.P12Path == "" {
			return credentialInputs{}, errors.New("select a P12/PFX bundle file")
		}
	default:
		return credentialInputs{}, errors.New("select a credential format")
	}
	return out, nil
}

// The GUI does not bind the peer identity to a hostname. SNI is routing-only;
// protocol.Exchange still verifies the server CA chain, dates, and server EKU.
func guiTLSConfig(host, port, sni, secret string, creds credentialInputs, minTLS uint16, timeout time.Duration) protocol.Config {
	return protocol.Config{
		Host: host, Port: port, SNI: sni, Secret: secret,
		CAPath: creds.CAPath, CertPath: creds.CertPath, KeyPath: creds.KeyPath,
		KeyPass: creds.KeyPass, P12Path: creds.P12Path, P12Pass: creds.P12Pass,
		P12Data: creds.P12Data, CA: creds.CA, CertData: creds.CertData, KeyData: creds.KeyData,
		MinTLS: minTLS, Timeout: timeout, SkipHostnameVerification: true,
	}
}

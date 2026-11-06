package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	MaxP12Bytes      = 4 << 20
	MaxCABytes       = 1 << 20
	MaxPasswordBytes = 4096
	MaxPlainBytes    = 8 << 20
)

type Profile struct {
	Version  int    `json:"version"`
	P12      []byte `json:"p12"`
	Password string `json:"password"`
	CA       []byte `json:"ca,omitempty"`
}

func bounds(p Profile) error {
	if len(p.P12) == 0 || len(p.P12) > MaxP12Bytes || len(p.Password) > MaxPasswordBytes || len(p.CA) > MaxCABytes {
		return errors.New("identity size out of bounds")
	}
	return nil
}

// Validate checks the actual client keypair and optional trusted CA before storage.
func Validate(p Profile) error {
	if err := bounds(p); err != nil {
		return err
	}
	key, leaf, _, err := pkcs12.DecodeChain(p.P12, p.Password)
	if err != nil || key == nil || leaf == nil {
		return errors.New("P12 bundle or password invalid")
	}
	if len(p.CA) > 0 {
		rest := p.CA
		found := false
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				if len(bytes.TrimSpace(rest)) > 0 {
					return errors.New("invalid CA PEM")
				}
				break
			}
			if block.Type != "CERTIFICATE" {
				return errors.New("invalid CA PEM")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return errors.New("invalid CA PEM")
			}
			found = true
			rest = next
		}
		if !found {
			return errors.New("invalid CA PEM")
		}
	}
	return nil
}
func Marshal(p Profile) ([]byte, error) {
	if err := bounds(p); err != nil {
		return nil, err
	}
	p.Version = 1
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPlainBytes {
		return nil, errors.New("identity size out of bounds")
	}
	return b, nil
}
func Unmarshal(raw []byte) (Profile, error) {
	var p Profile
	if len(raw) > MaxPlainBytes {
		return p, errors.New("identity size out of bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return Profile{}, errors.New("invalid identity data")
	}
	if p.Version != 1 {
		return Profile{}, errors.New("unsupported identity version")
	}
	if err := bounds(p); err != nil {
		return Profile{}, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Profile{}, errors.New("invalid identity data")
	}
	return p, nil
}

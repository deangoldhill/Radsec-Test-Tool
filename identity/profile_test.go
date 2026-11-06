package identity

import (
	"bytes"
	"strings"
	"testing"
)

func TestProfileRoundtrip(t *testing.T) {
	p := Profile{P12: []byte{0, 1, 2, 255}, Password: "sensitive-☃", CA: []byte("-----BEGIN CERTIFICATE-----\nabc\n")}
	raw, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("sensitive-☃")) {
		t.Fatal("serialization lost password before encryption")
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.P12, p.P12) || got.Password != p.Password || !bytes.Equal(got.CA, p.CA) {
		t.Fatal("roundtrip changed profile")
	}
}
func TestProfileBoundsAndShape(t *testing.T) {
	for _, p := range []Profile{{}, {P12: make([]byte, MaxP12Bytes+1)}, {P12: []byte{1}, Password: strings.Repeat("a", MaxPasswordBytes+1)}, {P12: []byte{1}, CA: make([]byte, MaxCABytes+1)}} {
		if _, err := Marshal(p); err == nil {
			t.Fatal("accepted invalid profile")
		}
	}
	for _, raw := range [][]byte{[]byte(`{"version":99,"p12":"AQ=="}`), []byte(`{"version":1,"p12":"AQ==","secret":"leak"}`), []byte(`{"version":1,"p12":"AQ=="} trailing`), bytes.Repeat([]byte("x"), MaxPlainBytes+1)} {
		if _, err := Unmarshal(raw); err == nil {
			t.Fatal("accepted invalid or oversized encoded profile")
		}
	}
}

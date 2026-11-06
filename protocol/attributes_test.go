package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestIANAScalarAttributes(t *testing.T) {
	cases := []struct {
		input string
		typ   byte
		want  []byte
	}{
		{"NAS-IP-Address = 192.0.2.1", 4, []byte{192, 0, 2, 1}},
		{"NAS-IPv6-Address = 2001:db8::1", 95, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"Acct-Input-Octets = 4294967295", 42, []byte{255, 255, 255, 255}},
		{"Acct-Output-Gigawords = 2", 53, []byte{0, 0, 0, 2}},
		{"Acct-Session-Time = 20", 46, []byte{0, 0, 0, 20}},
		{"Acct-Terminate-Cause = 1", 49, []byte{0, 0, 0, 1}},
		{"MIP6-Feature-Vector = 4294967296", 124, []byte{0, 0, 0, 1, 0, 0, 0, 0}},
		{"Event-Timestamp = 1700000000", 55, []byte{0x65, 0x53, 0xf1, 0}},
		{"DNS-Server-IPv6-Address = 2001:db8::1", 169, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"Framed-IPv6-Route = 2001:db8::/32", 99, []byte("2001:db8::/32")},
		{"Service-Type = 2", 6, []byte{0, 0, 0, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, e := ParseAttributes(tc.input)
			if e != nil {
				t.Fatal(e)
			}
			if len(got) != len(tc.want)+2 || got[0] != tc.typ || !bytes.Equal(got[2:], tc.want) {
				t.Fatalf("%x want %d:%x", got, tc.typ, tc.want)
			}
		})
	}
}
func TestAttributeRandomPerBuild(t *testing.T) {
	a, e := build(Request{Kind: "acct", Username: "alice", Status: "Start", SessionID: "x", Extra: "Acct-Input-Octets = random(10,20); NAS-Identifier = random(20)"}, "secret")
	if e != nil {
		t.Fatal(e)
	}
	b, e := build(Request{Kind: "acct", Username: "alice", Status: "Start", SessionID: "x", Extra: "Acct-Input-Octets = random(10,20); NAS-Identifier = random(20)"}, "secret")
	if e != nil {
		t.Fatal(e)
	}
	values := func(p []byte) (uint32, []byte) {
		var n uint32
		var s []byte
		for i := 20; i < len(p); i += int(p[i+1]) {
			if p[i] == 42 {
				n = binary.BigEndian.Uint32(p[i+2 : i+6])
			}
			if p[i] == 32 {
				s = p[i+2 : i+int(p[i+1])]
			}
		}
		return n, s
	}
	x, s := values(a)
	y, r := values(b)
	if x < 10 || x > 20 || y < 10 || y > 20 || len(s) != 20 || len(r) != 20 || bytes.Equal(s, r) {
		t.Fatalf("random values %d %d %q %q", x, y, s, r)
	}
}
func TestAttributeRejectsManagedAndComplex(t *testing.T) {
	for _, s := range []string{"User-Name = duplicate", "User-Password = secret", "Acct-Status-Type = 2", "Acct-Session-Id = x", "Message-Authenticator = x", "Vendor-Specific = x", "IPv6-6rd-Configuration = x", "Extended-Attribute-1 = x", "Framed-IPv6-Prefix = 2001:db8::/32", "Unassigned = x", "Acct-Input-Octets = -1", "NAS-IP-Address = 2001:db8::1", "Acct-Input-Octets = random(20,10)", "NAS-Identifier = random(0)", "NAS-Identifier = random(254)"} {
		if _, e := ParseAttributes(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestAccountingSessionTimeCannotDuplicateField(t *testing.T) {
	_, e := build(Request{Kind: "acct", Username: "alice", Status: "Start", SessionID: "x", SessionTime: 10, Extra: "Acct-Session-Time = 11"}, "secret")
	if e == nil || !strings.Contains(e.Error(), "duplicates") {
		t.Fatalf("expected duplicate rejection: %v", e)
	}
}
func TestIANARegistryCoverageIsExplicit(t *testing.T) {
	if len(ianaAttributes) != 192 {
		t.Fatalf("registry entries: %d", len(ianaAttributes))
	}
	for _, name := range []string{"User-Name", "Acct-Input-Gigawords", "Acct-Output-Gigawords", "Acct-Session-Time", "NAS-IP-Address", "IPv6-6rd-Configuration", "Vendor-Specific", "Extended-Attribute-1", "Extended-Attribute-6"} {
		if _, ok := ianaAttributes[name]; !ok {
			t.Errorf("missing registered %s", name)
		}
	}
}
func TestStaticAndRandomAttributesRespectLimits(t *testing.T) {
	for _, s := range []string{"NAS-Identifier = " + strings.Repeat("x", 254), "NAS-Identifier = random(254)"} {
		if _, e := ParseAttributes(s); e == nil {
			t.Errorf("accepted oversized attribute")
		}
	}
	a, e := ParseAttributes("NAS-Identifier = random(12)")
	if e != nil || len(a) != 14 {
		t.Fatalf("%x %v", a, e)
	}
}

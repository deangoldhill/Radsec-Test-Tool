package main
import (
 "strings"
 "testing"
 "radsec-windows-tester/protocol"
)
func TestAttributeEditorRoundTripAndRandomExpressions(t *testing.T) {
 rows, err := parseAttributeRows("NAS-Identifier = lab; Acct-Input-Octets = random(10,20)")
 if err != nil || len(rows) != 2 { t.Fatalf("rows: %v %v", rows, err) }
 got := renderAttributeRows(rows)
 if !strings.Contains(got, "Acct-Input-Octets = random(10,20)") { t.Fatal(got) }
 if _, err := protocol.ParseAttributes(got); err != nil { t.Fatal(err) }
}
func TestAttributeEditorValidation(t *testing.T) {
 for _, tc := range []struct{name, mode, value string}{
  {"NAS-Identifier", "Random length", "12"},
  {"Acct-Input-Octets", "Random range", "10,20"},
  {"Acct-Input-Octets", "Static", "42"},
  {"Framed-IP-Address", "Static", "192.0.2.1"},
 } { row, err := makeAttributeRow(tc.name, tc.mode, tc.value); if err != nil { t.Errorf("%v: %v",tc,err); continue }; if _,err:=protocol.ParseAttributes(renderAttributeRows([]attributeRow{row}));err!=nil { t.Errorf("%v: %v",tc,err) } }
 for _, tc := range []struct{name, mode, value string}{
  {"User-Password", "Static", "secret"}, {"NAS-Identifier", "Static", "a;b"},
  {"NAS-Identifier", "Random length", "254"}, {"Acct-Input-Octets", "Random range", "20,10"},
  {"Framed-IP-Address", "Random range", "1,2"},
 } { if _,err:=makeAttributeRow(tc.name,tc.mode,tc.value);err==nil { t.Errorf("accepted %v",tc) } }
}

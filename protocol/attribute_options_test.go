package protocol
import "testing"
func TestSelectableAttributesExcludeManagedAndComplex(t *testing.T) {
 options := SelectableAttributes()
 if len(options) < 80 { t.Fatalf("too few: %d", len(options)) }
 seen := map[string]string{}
 for _, option := range options { seen[option.Name] = option.Kind }
 if seen["NAS-Identifier"] != "text" || seen["Acct-Input-Octets"] != "integer" || seen["Framed-IP-Address"] != "ipv4addr" { t.Fatalf("missing options: %v", seen) }
 for _, name := range []string{"User-Password", "Acct-Status-Type", "Vendor-Specific", "Extended-Attribute-1", "Framed-IPv6-Prefix"} { if _, ok := seen[name]; ok { t.Errorf("offered %s", name) } }
 for i:=1; i<len(options); i++ { if options[i-1].Name >= options[i].Name { t.Fatal("unsorted or duplicate options") } }
}

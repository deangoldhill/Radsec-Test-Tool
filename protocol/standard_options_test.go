package protocol

import "testing"

func TestStandardDictionaryIncludesUnsupportedWithReason(t *testing.T) {
	all := StandardAttributes()
	if len(all) < 190 {
		t.Fatalf("only %d standard base attributes listed", len(all))
	}
	byName := map[string]AttributeOption{}
	for _, o := range all {
		byName[o.Name] = o
	}
	for _, name := range []string{"User-Password", "Vendor-Specific"} {
		if o, ok := byName[name]; !ok || o.Supported || o.Reason == "" {
			t.Fatalf("%s must be listed as protected/unsupported: %+v", name, o)
		}
	}
	for _, name := range []string{"NAS-IP-Address", "Acct-Output-Gigawords"} {
		if o, ok := byName[name]; !ok || !o.Supported {
			t.Fatalf("%s must be selectable: %+v", name, o)
		}
	}
}

//go:build windows

package main

import (
	"radsec-windows-tester/protocol"
	"strings"
	"testing"
)

func TestAttributeEditorPrefersCommonNASIPDefault(t *testing.T) {
	options := protocol.StandardAttributes()
	index := preferredAttributeIndex(options)
	if index < 0 || index >= len(options) || options[index].Name != "NAS-IP-Address" {
		t.Fatalf("default option index %d", index)
	}
}
func TestAttributeEditorLabelsUnavailableStandardAttributes(t *testing.T) {
	for _, o := range protocol.StandardAttributes() {
		label := attributeOptionLabel(o)
		if !o.Supported && !strings.Contains(label, "unavailable") {
			t.Fatalf("%s missing unavailable label: %q", o.Name, label)
		}
		if o.Supported && label != o.Name {
			t.Fatalf("supported %s relabeled %q", o.Name, label)
		}
	}
}

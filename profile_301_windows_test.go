//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestExportIncludesPendingAttributeEditorRows(t *testing.T) {
	row, err := makeAttributeRow("NAS-IP-Address", "Static", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	extra, err := profileExtraForSave("", []attributeRow{row}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(extra, "NAS-IP-Address") || !strings.Contains(extra, "192.0.2.8") {
		t.Fatalf("draft rows missing: %q", extra)
	}
	prior, err := profileExtraForSave("Filter-Id = abc", []attributeRow{row}, false)
	if err != nil {
		t.Fatal(err)
	}
	if prior != "Filter-Id = abc" {
		t.Fatalf("inactive editor changed Extra: %q", prior)
	}
}
func TestProfileComboRetainsDropdownListHeight(t *testing.T) {
	if profileNameListHeight() < 150 {
		t.Fatalf("saved-profile list is too short: %d", profileNameListHeight())
	}
}
func TestVersion301(t *testing.T) {
	if appVersion != "3.0.1" {
		t.Fatalf("wrong release version %s", appVersion)
	}
}

//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestClosingAttributeEditorCommitsQueuedRows(t *testing.T) {
	row, err := makeAttributeRow("NAS-IP-Address", "Static", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	got, err := editorExtraForClose("", []attributeRow{row}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "NAS-IP-Address = 192.0.2.8") {
		t.Fatalf("close lost queued row: %q", got)
	}
}
func TestDiscardAttributeEditorKeepsOldExtra(t *testing.T) {
	row, err := makeAttributeRow("NAS-IP-Address", "Static", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	got, err := editorExtraForClose("NAS-IP-Address = 198.51.100.1", []attributeRow{row}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "NAS-IP-Address = 198.51.100.1" {
		t.Fatalf("discard changed configured attributes: %q", got)
	}
}

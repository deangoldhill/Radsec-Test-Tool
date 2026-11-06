//go:build windows

package main

import "testing"

func TestAttributeCaptionLeavesRoomForEditorInFullMode(t *testing.T) {
	if got := extraAttributeCaption("full"); got != "Extra attributes" {
		t.Fatalf("full label = %q", got)
	}
	if got := extraAttributeCaption("auth"); got != "Extra attributes · Name = value; ..." {
		t.Fatalf("auth label = %q", got)
	}
}

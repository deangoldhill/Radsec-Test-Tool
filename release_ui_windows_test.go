//go:build windows

package main

import "testing"

func TestReleaseBrandAndProfileDialogGeometry(t *testing.T) {
	if appTitle != "RadSec Test Tool" {
		t.Fatalf("unexpected title %q", appTitle)
	}
	if appVersion != "3.0.1" {
		t.Fatalf("unexpected version %q", appVersion)
	}
	if profileDialogWidth < 740 || profileDialogHeight < 440 {
		t.Fatal("profile dialog too cramped")
	}
	if profileButtonX(4)+profileButtonWidth > profileDialogWidth-20 {
		t.Fatal("profile buttons clip right edge")
	}
	if profileStatusY+profileStatusHeight > profileDialogHeight-35 {
		t.Fatal("status clips bottom")
	}
}

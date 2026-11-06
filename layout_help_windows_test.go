//go:build windows

package main

import "testing"

func TestMainLayoutDoesNotCompressTextHeight(t *testing.T) {
	old := dpi
	dpi = 96
	defer func() { dpi = old }()
	if scaleY(100) != 100 {
		t.Fatalf("vertical compression remains: %d", scaleY(100))
	}
}
func TestProfileLayoutFitsAtDefaultAndAfterResize(t *testing.T) {
	for _, size := range [][2]int{{880, 520}, {1080, 720}, {760, 470}} {
		l := profileLayout(size[0], size[1])
		if l.name.Right > int32(size[0]-20) || l.name.Left < 20 {
			t.Fatalf("name does not fit %v: %+v", size, l.name)
		}
		if l.buttons[4].Right > int32(size[0]-20) || l.buttons[0].Left < 20 {
			t.Fatalf("buttons clipped %v", size)
		}
		if l.status.Bottom > int32(size[1]-10) || l.status.Top <= l.pass.Bottom {
			t.Fatalf("status clipped %v", size)
		}
		if l.portable.Bottom >= l.status.Top {
			t.Fatalf("portable section overlaps status %v", size)
		}
	}
}
func TestAttributeLayoutFitsAtDefaultAndAfterResize(t *testing.T) {
	for _, size := range [][2]int{{1020, 740}, {1260, 900}, {850, 620}} {
		l := attributeLayout(size[0], size[1])
		if l.list.Bottom <= l.list.Top+200 || l.list.Right > int32(size[0]-20) {
			t.Fatalf("list does not fit %v", size)
		}
		if l.apply.Bottom > int32(size[1]-20) || l.cancel.Right > int32(size[0]-20) {
			t.Fatalf("action buttons clipped %v", size)
		}
		if l.hint.Top <= l.value.Bottom || l.hint.Bottom >= l.apply.Top {
			t.Fatalf("controls overlap %v", size)
		}
	}
}
func TestHelpIndexCoversEveryMajorControl(t *testing.T) {
	for _, word := range []string{"Host", "TCP port", "Shared secret", "TLS SNI", "Minimum TLS", "Separate PEM", "P12/PFX", "Trusted CA", "Username", "Password", "Accounting status", "Session ID", "Session seconds", "Repeat requests", "Parallel workers", "Timeout", "Between acct stages", "Extra attributes", "Save P12", "Forget", "Profiles", "Save local", "Load local", "Delete local", "Export", "Import", "Browse", "Add / update", "Remove selected", "Apply to Extra", "Run RadSec", "Stop", "Client-side debug", "Clear", "Copy", "Save", "Pause", "Scroll", "Live statistics", "Details", "Events", "Help", "About"} {
		if !helpContains(word) {
			t.Errorf("help missing %q", word)
		}
	}
	if len(helpSections) < 8 {
		t.Fatal("help lacks index sections")
	}
}
func TestAboutIdentityAndLinks(t *testing.T) {
	for _, s := range []string{"Dean Goldhill", "3.0", "https://github.com/deangoldhill/Radsec-Test-Tool", "https://radsec.radius-stack.com", "https://radius-stack.com", "GPL-3.0-only"} {
		if !aboutContains(s) {
			t.Errorf("about missing %s", s)
		}
	}
}

//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestPortableCaptionsDescribeOptionalReadableExport(t *testing.T) {
	for _, s := range []string{mainProfileCaption, profilePortableDescription} {
		if !strings.Contains(strings.ToLower(s), "readable") || !strings.Contains(strings.ToLower(s), "encrypted") {
			t.Fatalf("caption should mention both formats: %q", s)
		}
	}
}

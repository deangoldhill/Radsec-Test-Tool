//go:build windows

package main

import "testing"

func TestHelpListNotifiesOnSelection(t *testing.T) {
	if helpListStyle&0x1 == 0 {
		t.Fatal("Help index listbox cannot send LBN_SELCHANGE")
	}
}

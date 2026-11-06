//go:build windows

package main

import (
	"fmt"
	"runtime"
	"testing"
)

const emGetLineCount = 0xBA

// Exercise the real Win32 EDIT control through the production append/post/drain path.
func TestLogScrollFollowsEachNewLineAndPreservesPositionWhenOff(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	parent, _, _ := create.Call(0, ptr("STATIC"), ptr("scroll regression"), WS_OVERLAPPEDWINDOW|WS_VISIBLE, 0, 0, 380, 160, 0, 0, 0, 0)
	if parent == 0 {
		t.Fatal("could not create parent window")
	}
	defer up("DestroyWindow").Call(parent)
	edit, _, _ := create.Call(0, ptr("EDIT"), ptr(""), WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, 0, 0, 340, 64, parent, 0, 0, 0)
	if edit == 0 {
		t.Fatal("could not create log edit")
	}
	oldHwnd, oldLog, oldEvents, oldDisplay, oldScroll, oldPending := hwnd, logHandle, events, lastDisplayed, autoScroll, pending
	defer func() {
		hwnd, logHandle, events, lastDisplayed, autoScroll, pending = oldHwnd, oldLog, oldEvents, oldDisplay, oldScroll, oldPending
	}()
	hwnd, logHandle, events, lastDisplayed, autoScroll, pending = parent, edit, newEventLog(500), "", true, nil
	appendAndDrain := func(i int) {
		appendLog(eventInfo, fmt.Sprintf("line %03d", i))
		// The posted WM_APP calls this same drain on the UI thread.
		wndproc(parent, WM_APP, 0, 0)
	}
	for i := 0; i < 60; i++ {
		appendAndDrain(i)
	}
	assertBottom := func(label string) {
		t.Helper()
		first, _, _ := send.Call(edit, EM_GETFIRSTVISIBLELINE, 0, 0)
		count, _, _ := send.Call(edit, emGetLineCount, 0, 0)
		if count > first+6 {
			t.Fatalf("%s: not following tail: first=%d lines=%d", label, first, count)
		}
	}
	assertBottom("initial")
	// A manual scroll upward must be overridden for every new line while on.
	send.Call(edit, EM_LINESCROLL, 0, ^uintptr(39))
	before, _, _ := send.Call(edit, EM_GETFIRSTVISIBLELINE, 0, 0)
	if before >= 20 {
		t.Fatalf("could not scroll upward: first=%d", before)
	}
	appendAndDrain(60)
	assertBottom("new line with Scroll on")
	wndproc(parent, WM_COMMAND, idScroll, 0)
	if autoScroll {
		t.Fatal("Scroll button did not turn follow off")
	}
	send.Call(edit, EM_LINESCROLL, 0, ^uintptr(19))
	before, _, _ = send.Call(edit, EM_GETFIRSTVISIBLELINE, 0, 0)
	if before == 0 || before >= 50 {
		t.Fatalf("could not scroll to a middle position while off: first=%d", before)
	}
	appendAndDrain(61)
	after, _, _ := send.Call(edit, EM_GETFIRSTVISIBLELINE, 0, 0)
	if after != before {
		t.Fatalf("Scroll off moved manual viewport: before=%d after=%d", before, after)
	}
	appendAndDrain(62)
	after, _, _ = send.Call(edit, EM_GETFIRSTVISIBLELINE, 0, 0)
	if after != before {
		t.Fatalf("Scroll off moved manual viewport on next line: before=%d after=%d", before, after)
	}
	wndproc(parent, WM_COMMAND, idScroll, 0)
	if !autoScroll {
		t.Fatal("Scroll button did not turn follow back on")
	}
	for i := 63; i < 66; i++ {
		send.Call(edit, EM_LINESCROLL, 0, ^uintptr(39))
		appendAndDrain(i)
		assertBottom(fmt.Sprintf("new line %d after re-enabling Scroll", i))
	}
}

//go:build windows

package main

import (
    "testing"
)

func TestEmbeddedRadiusStackIcon(t *testing.T) {
    instance, _, err := kernel32.NewProc("GetModuleHandleW").Call(0)
    if instance == 0 { t.Fatalf("module handle: %v", err) }
    // Resource ID 1 must resolve to a real RT_GROUP_ICON in this executable.
    icon, _, err := up("LoadImageW").Call(instance, 1, 1, 32, 32, 0)
    if icon == 0 { t.Fatalf("missing embedded RadiusStack RT_GROUP_ICON #1: %v", err) }
    defer up("DestroyIcon").Call(icon)
}

//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

type helpSection struct{ Title, Body string }

var helpSections = []helpSection{
	{"Start here", `RadSec Test Tool sends RADIUS requests over TLS to a RadSec server. Enter the connection details and credentials, then choose a request type and Run RadSec test. The tool permits public or private hosts. It checks the server certificate chain, validity dates and server-auth usage, but hostname matching is OFF by design: check the configured trust CA carefully.

Help opens this indexed guide. About shows the author, version, license and project links. This is a test client, not a RadSec server.`},
	{"Connection", `RadSec host / IP: DNS hostname, IPv4 or IPv6 endpoint. TCP port: 1..65535 (default 2083). Shared secret: RADIUS shared secret agreed with the server. TLS SNI hostname: optional TLS Server Name Indication, not hostname verification. Minimum TLS: 1.2 or 1.3. Trusted CA PEM: optional explicit CA; when omitted the system trust store is used. Browse next to a certificate path selects a local file. A reachable public IP is allowed; a valid TLS trust chain is still required.`},
	{"Client identity", `Client certificate format: Separate PEM or P12/PFX. For Separate PEM, choose Client certificate PEM and Client private key PEM; PEM key passphrase is used for encrypted keys. For P12/PFX, choose Combined P12/PFX bundle and enter its password. Trusted CA PEM is the trust anchor for the server, not a substitute for a client certificate.

Save P12 stores only the selected client identity under the current Windows user using DPAPI; it does not save RADIUS credentials. Forget removes that saved identity. The status line says whether a saved P12 is active. File-path fields and Browse buttons select certificate material for the current run.`},
	{"RADIUS request", `Request type: auth sends an Access-Request; acct sends an Accounting-Request; full runs authentication followed by accounting stages (Start, Interim-Update, Stop). Username identifies the test user. Password is the PAP password for auth/full. Accounting status chooses Start, Interim-Update or Stop for acct. Accounting session ID identifies an acct session; full generates an independent session ID for each repeated transaction. Accounting session seconds: 0..2147483647. Between acct stages: 0..3600000 milliseconds for full transactions.

Repeat requests: 1..10000. Parallel workers: 1..100. Timeout per request: 1..90 seconds. Extra attributes: supported Name = value pairs separated by semicolons; managed or unsupported attributes are rejected. Run RadSec test starts the run. Stop cancels active work; Stop (idle) indicates nothing is running.`},
	{"Attribute editor", `Edit attributes opens the resizable Advanced RADIUS attributes window. The top list contains queued rows; select a row to edit it. Attribute chooses a supported standard attribute (unavailable entries explain why they cannot be added). Value mode chooses Static, Random length for text, or Random range for eligible numbers. Value accepts the typed value; random length uses a count and random range uses min,max. Add / update adds a row or replaces the selected row. Remove selected removes it. Apply to Extra or closing the editor with X validates and copies queued rows into Extra attributes. Cancel discards changes. The hint line explains the selected type or a validation error.`},
	{"Profiles", `Profiles opens Secure profiles. Profile name: type 1..48 ASCII letters/digits/hyphen/underscore (start with a letter or digit), or select an existing name. Save local saves the current connection, credentials, request fields and certificate material with current-user Windows DPAPI; saving an existing name replaces it. Load local applies the selected saved profile. Delete local asks for confirmation; it removes the saved file but leaves current fields. The older single-slot profile appears as Default.

Export writes a new .radsecprofile file with all connection, credential, request and Extra attribute settings. Leave Export password blank for readable JSON (including secrets and certificate material), or set any password for an encrypted file; existing files are not overwritten. Import accepts either format and restores the attributes. Enter the password only for an encrypted file. Portable files may be transferred, while local DPAPI files are tied to the Windows account. The password field is cleared after an import/export attempt.`},
	{"Diagnostics", `Client-side debug toggles extra sanitized connection diagnostics for the next run; it is not a server/proxy debug setting. Severity filters All events, Success + warnings, Warnings + errors, or Errors only. Search events filters the local event view. Clear empties displayed local events. Copy copies diagnostics to the clipboard. Save writes a text diagnostics file. Pause/Resume freezes or resumes the displayed event view. Scroll on/off controls whether new entries auto-scroll. No credentials should be included in diagnostics.`},
	{"Statistics", `Live statistics shows observed counts and timings for the active or last run. Details (50+) shows expanded observed measurements. Events shows the local diagnostic log. Access-Accept, Access-Reject and Accounting-Response are distinct outcomes. Response validation errors are not counted as transport errors; unobserved phases are not invented. Stop may leave a partial run that is reported as such.`},
	{"Security and files", `Profiles and saved P12 identity use current-user Windows DPAPI. Portable exports with a blank password are readable JSON and expose all saved credentials/certificate material to anyone with the file; exports with a password are encrypted. Local data is in %APPDATA%\\RadSecConnectionLab. The EXE does not need companion application files, but you supply CA/client certificates and connection settings. This build is unsigned: Windows may show an unknown-publisher warning. Do not disable security checks to run it; obtain a signed release when available.`},
}

func helpContains(word string) bool {
	for _, section := range helpSections {
		if strings.Contains(strings.ToLower(section.Title+" "+section.Body), strings.ToLower(word)) {
			return true
		}
	}
	return false
}

const aboutText = `RadSec Test Tool · version 3.0.1
Author: Dean Goldhill

Free to use under the GNU General Public License version 3, GPL-3.0-only. Source and the full license text accompany this release; the GitHub repository must publish its LICENSE separately.

Project source: https://github.com/deangoldhill/Radsec-Test-Tool
Tool home: https://radsec.radius-stack.com
RadiusStack project: https://radius-stack.com`

func aboutContains(word string) bool { return strings.Contains(aboutText, word) }

const helpListStyle = WS_TABSTOP | WS_VSCROLL | 0x00800000 | 0x1 // LBS_NOTIFY is required for topic changes.
var helpWindow, helpList, helpBody, helpTitle, helpIntro uintptr
var aboutWindow, aboutBody, aboutTitle uintptr
var aboutLinks [3]uintptr
var helpClass = syscall.StringToUTF16Ptr("RadSecHelpWindow")
var aboutClass = syscall.StringToUTF16Ptr("RadSecAboutWindow")

func centerChildX(parent uintptr, width int) int {
	var r rect
	up("GetWindowRect").Call(parent, uintptr(unsafe.Pointer(&r)))
	x := int(r.Left) + (int(r.Right-r.Left)-width)/2
	if x < 0 {
		return 0
	}
	return x
}
func centerChildY(parent uintptr, height int) int {
	var r rect
	up("GetWindowRect").Call(parent, uintptr(unsafe.Pointer(&r)))
	y := int(r.Top) + (int(r.Bottom-r.Top)-height)/2
	if y < 0 {
		return 0
	}
	return y
}
func infoChild(parent uintptr, class, title string, style uintptr) uintptr {
	h, _, _ := create.Call(0, ptr(class), ptr(title), style|WS_CHILD|WS_VISIBLE, 0, 0, 10, 10, parent, 0, 0, 0)
	send.Call(h, WM_SETFONT, fonts[0], 1)
	return h
}
func paintInfo(h uintptr) {
	var ps paintStruct
	dc, _, _ := up("BeginPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
	var r rect
	up("GetClientRect").Call(h, uintptr(unsafe.Pointer(&r)))
	fill(dc, rect{0, 0, r.Right, r.Bottom}, canvas)
	up("EndPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
}
func infoColor(dc uintptr) uintptr {
	gp("SetTextColor").Call(dc, ink)
	gp("SetBkColor").Call(dc, raised)
	return brush(raised)
}
func selectedHelp() {
	n, _, _ := send.Call(helpList, LB_GETCURSEL, 0, 0)
	if int32(n) < 0 || int(n) >= len(helpSections) {
		return
	}
	text := helpSections[n].Title + "\r\n\r\n" + helpSections[n].Body
	setText.Call(helpBody, ptr(strings.ReplaceAll(text, "\n", "\r\n")))
}
func resizeHelp() {
	if helpWindow == 0 {
		return
	}
	var r rect
	up("GetClientRect").Call(helpWindow, uintptr(unsafe.Pointer(&r)))
	w, h := int(r.Right), int(r.Bottom)
	if w <= 0 || h <= 0 {
		return
	}
	m := scale(24)
	side := scale(250)
	top := scale(94)
	bottom := h - scale(24)
	moveRect(helpTitle, rect{int32(m), int32(scale(16)), int32(w - m), int32(scale(46))})
	moveRect(helpIntro, rect{int32(m), int32(scale(51)), int32(w - m), int32(scale(80))})
	moveRect(helpList, rect{int32(m), int32(top), int32(m + side), int32(bottom)})
	moveRect(helpBody, rect{int32(m + side + scale(16)), int32(top), int32(w - m), int32(bottom)})
	invalidate.Call(helpWindow, 0, 1)
}
func helpWndProc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case WM_COMMAND:
		if l == helpList && w>>16 == LBN_SELCHANGE {
			selectedHelp()
			return 0
		}
	case WM_SIZE:
		resizeHelp()
		return 0
	case WM_GETMINMAXINFO:
		p := (*minMax)(unsafe.Pointer(l))
		p.MinTrack = point{int32(scale(800)), int32(scale(580))}
		return 0
	case WM_PAINT:
		paintInfo(h)
		return 0
	case WM_ERASEBKGND:
		return 1
	case WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX:
		return infoColor(w)
	case WM_CLOSE:
		up("DestroyWindow").Call(h)
		return 0
	case WM_DESTROY:
		helpWindow = 0
		helpList = 0
		helpBody = 0
		return 0
	}
	ret, _, _ := up("DefWindowProcW").Call(h, uintptr(m), w, l)
	return ret
}
func openHelpWindow() {
	if helpWindow != 0 {
		up("SetForegroundWindow").Call(helpWindow)
		return
	}
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: syscall.NewCallback(helpWndProc), Instance: inst, Name: uintptr(unsafe.Pointer(helpClass)), Background: brush(canvas)}
	reg.Call(uintptr(unsafe.Pointer(&wc)))
	helpWindow, _, _ = create.Call(0, uintptr(unsafe.Pointer(helpClass)), ptr("RadSec Test Tool · Help"), WS_OVERLAPPEDWINDOW, uintptr(centerChildX(hwnd, scale(1080))), uintptr(centerChildY(hwnd, scale(760))), uintptr(scale(1080)), uintptr(scale(760)), hwnd, 0, inst, 0)
	if helpWindow == 0 {
		return
	}
	helpTitle = infoChild(helpWindow, "STATIC", "HELP  /  USER GUIDE", 0)
	helpIntro = infoChild(helpWindow, "STATIC", "Select a topic on the left. The guide explains every input and action.", 0)
	helpList = infoChild(helpWindow, "LISTBOX", "", helpListStyle)
	helpBody = infoChild(helpWindow, "EDIT", "", ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|0x00800000)
	for _, s := range helpSections {
		send.Call(helpList, LB_ADDSTRING, 0, ptr(s.Title))
	}
	send.Call(helpList, LB_SETCURSEL, 0, 0)
	selectedHelp()
	resizeHelp()
	show.Call(helpWindow, SW_SHOW)
	up("UpdateWindow").Call(helpWindow)
}
func resizeAbout() {
	if aboutWindow == 0 {
		return
	}
	var r rect
	up("GetClientRect").Call(aboutWindow, uintptr(unsafe.Pointer(&r)))
	w, h := int(r.Right), int(r.Bottom)
	if w <= 0 || h <= 0 {
		return
	}
	m := scale(24)
	moveRect(aboutTitle, rect{int32(m), int32(scale(18)), int32(w - m), int32(scale(54))})
	moveRect(aboutBody, rect{int32(m), int32(scale(68)), int32(w - m), int32(h - scale(100))})
	bw := (w - 2*m - 2*scale(12)) / 3
	for i, b := range aboutLinks {
		x := m + i*(bw+scale(12))
		moveRect(b, rect{int32(x), int32(h - scale(68)), int32(x + bw), int32(h - scale(28))})
	}
	invalidate.Call(aboutWindow, 0, 1)
}
func aboutWndProc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case WM_COMMAND:
		urls := []string{"https://github.com/deangoldhill/Radsec-Test-Tool", "https://radsec.radius-stack.com", "https://radius-stack.com"}
		for i, b := range aboutLinks {
			if l == b {
				syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(h, ptr("open"), ptr(urls[i]), 0, 0, 1)
				return 0
			}
		}
	case WM_SIZE:
		resizeAbout()
		return 0
	case WM_GETMINMAXINFO:
		p := (*minMax)(unsafe.Pointer(l))
		p.MinTrack = point{int32(scale(680)), int32(scale(450))}
		return 0
	case WM_DRAWITEM:
		item := (*drawItem)(unsafe.Pointer(l))
		roundedRect(item.DC, item.Rc, scale(10), raised, border)
		drawText(item.DC, text(item.Item), item.Rc, ink, fonts[0], 0x1|0x4|0x20)
		return 1
	case WM_PAINT:
		paintInfo(h)
		return 0
	case WM_ERASEBKGND:
		return 1
	case WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT:
		return infoColor(w)
	case WM_CLOSE:
		up("DestroyWindow").Call(h)
		return 0
	case WM_DESTROY:
		aboutWindow = 0
		aboutBody = 0
		return 0
	}
	ret, _, _ := up("DefWindowProcW").Call(h, uintptr(m), w, l)
	return ret
}
func openAboutWindow() {
	if aboutWindow != 0 {
		up("SetForegroundWindow").Call(aboutWindow)
		return
	}
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: syscall.NewCallback(aboutWndProc), Instance: inst, Name: uintptr(unsafe.Pointer(aboutClass)), Background: brush(canvas)}
	reg.Call(uintptr(unsafe.Pointer(&wc)))
	aboutWindow, _, _ = create.Call(0, uintptr(unsafe.Pointer(aboutClass)), ptr("About RadSec Test Tool"), WS_OVERLAPPEDWINDOW, uintptr(centerChildX(hwnd, scale(760))), uintptr(centerChildY(hwnd, scale(510))), uintptr(scale(760)), uintptr(scale(510)), hwnd, 0, inst, 0)
	if aboutWindow == 0 {
		return
	}
	aboutTitle = infoChild(aboutWindow, "STATIC", "ABOUT  /  RADSEC TEST TOOL", 0)
	aboutBody = infoChild(aboutWindow, "EDIT", strings.ReplaceAll(aboutText, "\n", "\r\n"), ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|0x00800000)
	for i, title := range []string{"GitHub repository", "Tool home page", "RadiusStack project"} {
		aboutLinks[i] = infoChild(aboutWindow, "BUTTON", title, WS_TABSTOP|BS_OWNERDRAW)
	}
	resizeAbout()
	show.Call(aboutWindow, SW_SHOW)
	up("UpdateWindow").Call(aboutWindow)
}

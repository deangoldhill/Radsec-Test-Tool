//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"radsec-windows-tester/identity"
	"radsec-windows-tester/protocol"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	appTitle               = "RadSec Test Tool"
	appVersion             = "3.0.1"
	mainProfileCaption     = "Profiles: Windows-protected local · readable or encrypted portable export"
	WS_OVERLAPPEDWINDOW    = 0x00cf0000
	WS_VISIBLE             = 0x10000000
	WS_CHILD               = 0x40000000
	WS_VSCROLL             = 0x00200000
	WS_TABSTOP             = 0x10000
	ES_MULTILINE           = 4
	ES_READONLY            = 0x800
	ES_AUTOVSCROLL         = 0x40
	ES_PASSWORD            = 0x20
	ES_AUTOHSCROLL         = 0x80
	CBS_DROPDOWNLIST       = 3
	CBS_OWNERDRAWFIXED     = 0x10
	CBS_HASSTRINGS         = 0x200
	BS_OWNERDRAW           = 0xb
	WM_COMMAND             = 0x111
	WM_DESTROY             = 2
	WM_APP                 = 0x8000
	WM_SIZE                = 5
	WM_PAINT               = 15
	WM_ERASEBKGND          = 20
	WM_DRAWITEM            = 0x2b
	WM_CTLCOLORSTATIC      = 0x138
	WM_CTLCOLOREDIT        = 0x133
	WM_CTLCOLORLISTBOX     = 0x134
	WM_GETMINMAXINFO       = 0x24
	WM_DPICHANGED          = 0x2e0
	EM_SETSEL              = 0xb1
	EM_REPLACESEL          = 0xc2
	EM_SCROLLCARET         = 0xb7
	EM_GETLINECOUNT        = 0xba
	EM_GETFIRSTVISIBLELINE = 0xce
	EM_LINESCROLL          = 0xb6
	EM_LIMITTEXT           = 0xc5
	CB_ADDSTRING           = 0x143
	CB_GETCURSEL           = 0x147
	CB_SETCURSEL           = 0x14e
	CBN_SELCHANGE          = 1
	EN_CHANGE              = 0x300
	SW_SHOW                = 5
	SW_HIDE                = 0
	WM_SETFONT             = 0x30
	COLOR_TRANSPARENT      = 1
	idRun                  = 101
	idStop                 = 102
	idStats                = 103
	idEvents               = 104
	idDetails              = 105
	idDebug                = 106
	idCA                   = 201
	idCert                 = 202
	idKey                  = 203
	idP12                  = 204
	idClear                = 301
	idCopy                 = 302
	idSave                 = 303
	idPause                = 304
	idScroll               = 305
	idSaveIdentity         = 306
	idForgetIdentity       = 307
	idProfiles             = 308
	idAttributes           = 309
	idHelp                 = 310
	idAbout                = 311
)

var user32 = syscall.NewLazyDLL("user32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var gdi = syscall.NewLazyDLL("gdi32.dll")
var dwm = syscall.NewLazyDLL("dwmapi.dll")
var ux = syscall.NewLazyDLL("uxtheme.dll")

func up(name string) *syscall.LazyProc { return user32.NewProc(name) }
func gp(name string) *syscall.LazyProc { return gdi.NewProc(name) }

var reg = up("RegisterClassExW")
var create = up("CreateWindowExW")
var send = up("SendMessageW")
var post = up("PostMessageW")
var setText = up("SetWindowTextW")
var getText = up("GetWindowTextW")
var move = up("MoveWindow")
var show = up("ShowWindow")
var invalidate = up("InvalidateRect")
var comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
var getOpenFileName = comdlg32.NewProc("GetOpenFileNameW")
var getSaveFileName = comdlg32.NewProc("GetSaveFileNameW")
var dialogError = comdlg32.NewProc("CommDlgExtendedError")

type point struct{ X, Y int32 }
type rect struct{ Left, Top, Right, Bottom int32 }
type msg struct {
	H       uintptr
	M       uint32
	W, L    uintptr
	T       uint32
	P       point
	Private uint32
}
type wndclass struct {
	Size, Style                                               uint32
	Proc                                                      uintptr
	ClsExtra, WndExtra                                        int32
	Instance, Icon, Cursor, Background, Menu, Name, IconSmall uintptr
}
type paintStruct struct {
	DC           uintptr
	Erase        int32
	Rc           rect
	Restore, Inc int32
	Reserved     [32]byte
}
type drawItem struct {
	CtlType, CtlID, ItemID, ItemAction, ItemState uint32
	Item, DC                                      uintptr
	Rc                                            rect
	Data                                          uintptr
}
type minMax struct{ Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack point }
type openFileName struct {
	Size                                                 uint32
	Owner, Instance, Filter, CustomFilter                uintptr
	MaxCustom, FilterIndex                               uint32
	File                                                 uintptr
	MaxFile                                              uint32
	FileTitle                                            uintptr
	MaxFileTitle                                         uint32
	InitialDir, Title                                    uintptr
	Flags                                                uint32
	FileOffset, FileExtension                            uint16
	DefaultExt, CustomData, Hook, TemplateName, Reserved uintptr
	ReservedFlags, FlagsEx                               uint32
}

var _ [152 - unsafe.Sizeof(openFileName{})]byte
var _ [unsafe.Sizeof(openFileName{}) - 152]byte

func ptr(s string) uintptr     { return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))) }
func rgb(r, g, b byte) uintptr { return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16 }

var canvas = rgb(8, 9, 10)
var panel = rgb(15, 16, 17)
var raised = rgb(25, 26, 27)
var border = rgb(35, 37, 42)
var ink = rgb(247, 248, 248)
var muted = rgb(138, 143, 152)
var accent = rgb(94, 106, 210)
var green = rgb(70, 179, 132)
var amber = rgb(219, 163, 76)
var danger = rgb(219, 107, 110)
var brushes = map[uintptr]uintptr{}
var fonts = [3]uintptr{}

func brush(c uintptr) uintptr {
	if brushes[c] == 0 {
		brushes[c], _, _ = gp("CreateSolidBrush").Call(c)
	}
	return brushes[c]
}
func font(size int, bold bool) uintptr {
	weight := uintptr(400)
	if bold {
		weight = 600
	}
	f, _, _ := gp("CreateFontW").Call(uintptr(int32(-scale(size))), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, ptr("Segoe UI"))
	return f
}

var hwnd, logHandle, statusHandle, searchHandle, filterHandle, runHandle, stopHandle, statsHandle uintptr
var activeRun *Run
var statsVisible bool
var detailsVisible bool
var fields = map[string]uintptr{}
var groups = map[string][]uintptr{}
var buttons = map[uintptr]int{}
var events = newEventLog(500)
var lastDisplayed string
var pending []logEntry
var mu sync.Mutex
var running = false
var clientDebug = false
var savedIdentity *identity.Profile
var identityState uintptr
var autoScroll = true
var dpi = 96
var clientW, clientH = 1200, 960

func scale(v int) int { return (v*dpi + 48) / 96 }

// Keep vertical dimensions in the same DPI space as the font: compressing only controls clipped descenders.
func scaleY(v int) int { return scale(v) }
func position(h uintptr, x, y, w, ht int) {
	move.Call(h, uintptr(scale(x)), uintptr(scaleY(y)), uintptr(scale(w)), uintptr(scaleY(ht)), 1)
}
func id(h uintptr, n int) { up("SetWindowLongPtrW").Call(h, ^uintptr(11), uintptr(n)) }
func control(class, text string, style uintptr) uintptr {
	h, _, _ := create.Call(0, ptr(class), ptr(text), style|WS_CHILD|WS_VISIBLE, 0, 0, 10, 10, hwnd, 0, 0, 0)
	send.Call(h, WM_SETFONT, fonts[0], 1)
	if class == "EDIT" || class == "COMBOBOX" {
		if theme := ux.NewProc("SetWindowTheme"); theme.Find() == nil {
			theme.Call(h, ptr("DarkMode_CFD"), 0)
		}
	}
	return h
}
func label(text string, bold bool) uintptr {
	h := control("STATIC", text, 0)
	if bold {
		send.Call(h, WM_SETFONT, fonts[1], 1)
	}
	return h
}
func field(key, caption, value string, secret bool) {
	l := label(caption, false)
	style := uintptr(WS_TABSTOP | ES_AUTOHSCROLL | 0x00800000)
	if secret {
		style |= ES_PASSWORD
	}
	h := control("EDIT", value, style)
	groups[key] = []uintptr{l, h}
	fields[key] = h
}
func fileField(key, caption string, n int) {
	l := label(caption, false)
	h := control("EDIT", "", WS_TABSTOP|ES_AUTOHSCROLL|0x00800000)
	b := button("Browse", n)
	groups[key] = []uintptr{l, h, b}
	fields[key] = h
}
func combo(key, caption string, options []string) {
	l := label(caption, false)
	h := control("COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST|CBS_OWNERDRAWFIXED|CBS_HASSTRINGS)
	for _, s := range options {
		send.Call(h, CB_ADDSTRING, 0, ptr(s))
	}
	send.Call(h, CB_SETCURSEL, 0, 0)
	groups[key] = []uintptr{l, h}
	fields[key] = h
}
func button(text string, n int) uintptr {
	h := control("BUTTON", text, WS_TABSTOP|BS_OWNERDRAW)
	id(h, n)
	buttons[h] = n
	return h
}
func place(key string, x, y, w int) {
	a := groups[key]
	position(a[0], x, y, w, 23)
	if len(a) == 3 {
		position(a[1], x, y+24, w-80, 29)
		position(a[2], x+w-74, y+24, 74, 29)
	} else {
		ht := 29
		if key == "credentials" || key == "kind" || key == "tls" || key == "status" {
			ht = 170
		}
		position(a[1], x, y+24, w, ht)
	}
}
func visible(key string, on bool) {
	for _, h := range groups[key] {
		how := uintptr(SW_HIDE)
		if on {
			how = SW_SHOW
		}
		show.Call(h, how)
	}
}
func text(h uintptr) string {
	if h == 0 {
		return ""
	}
	buf := make([]uint16, 4096)
	n, _, _ := getText.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf[:n])
}
func val(key string) string { return strings.TrimSpace(text(fields[key])) }
func selected(key string, options ...string) string {
	n, _, _ := send.Call(fields[key], CB_GETCURSEL, 0, 0)
	if int(n) >= len(options) {
		return ""
	}
	return options[n]
}
func appendLog(level severity, message string) {
	mu.Lock()
	if len(pending) >= 1000 {
		copy(pending, pending[1:])
		pending = pending[:999]
	}
	pending = append(pending, logEntry{level, message})
	mu.Unlock()
	post.Call(hwnd, WM_APP, 0, 0)
}
func redrawLog() {
	if logHandle == 0 {
		return
	}
	s := events.view()
	if s == lastDisplayed {
		return
	}
	firstLine, _, _ := send.Call(logHandle, EM_GETFIRSTVISIBLELINE, 0, 0)
	setText.Call(logHandle, ptr(s))
	lastDisplayed = s
	if autoScroll && !events.paused {
		send.Call(logHandle, EM_SETSEL, ^uintptr(0), ^uintptr(0))
		lineCount, _, _ := send.Call(logHandle, EM_GETLINECOUNT, 0, 0)
		send.Call(logHandle, EM_LINESCROLL, 0, lineCount)
	} else {
		send.Call(logHandle, EM_LINESCROLL, 0, firstLine)
	}
}
func drain() {
	mu.Lock()
	lines := pending
	pending = nil
	mu.Unlock()
	for _, e := range lines {
		events.add(e.level, e.message)
	}
	redrawLog()
}
func browseFile(key string) {
	filter := "PEM files (*.pem;*.crt;*.cer;*.key)\x00*.pem;*.crt;*.cer;*.key\x00All files (*.*)\x00*.*\x00\x00"
	if key == "p12" {
		filter = "PKCS#12 (*.p12;*.pfx)\x00*.p12;*.pfx\x00All files (*.*)\x00*.*\x00\x00"
	}
	wide := utf16.Encode([]rune(filter))
	file := make([]uint16, 32768)
	selected := text(fields[key])
	if len(selected) < len(file)-1 {
		copy(file, syscall.StringToUTF16(selected))
	}
	opts := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: hwnd, Filter: uintptr(unsafe.Pointer(&wide[0])), FilterIndex: 1, File: uintptr(unsafe.Pointer(&file[0])), MaxFile: uint32(len(file)), Flags: 0x80000 | 0x1000 | 0x800}
	if ok, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&opts))); ok != 0 {
		setText.Call(fields[key], ptr(syscall.UTF16ToString(file)))
		if key == "p12" {
			refreshIdentityState()
		}
	} else if code, _, _ := dialogError.Call(); code != 0 {
		appendLog(eventError, "File selection canceled by Windows dialog error")
	}
	runtime.KeepAlive(wide)
	runtime.KeepAlive(file)
}
func boundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > maxBytes {
		return nil, errors.New("file too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(b)) > maxBytes {
		return nil, errors.New("file too large")
	}
	return b, nil
}
func refreshIdentityState() {
	if identityState == 0 {
		return
	}
	s := "No saved P12 identity"
	if savedIdentity != nil {
		s = "Saved P12 available"
	}
	if selected("credentials", "Separate PEM", "P12/PFX") == "P12/PFX" {
		if val("p12") != "" {
			s = "Selected P12 file (not saved)"
		} else if savedIdentity != nil {
			s = "Saved P12 active"
		} else {
			s = "Select a P12 file"
		}
	}
	setText.Call(identityState, ptr(s))
}
func saveIdentity() {
	if selected("credentials", "Separate PEM", "P12/PFX") != "P12/PFX" || val("p12") == "" {
		appendLog(eventError, "Select a P12/PFX file before saving an identity")
		return
	}
	p12, err := boundedFile(val("p12"), identity.MaxP12Bytes)
	if err != nil {
		appendLog(eventError, "Cannot read P12/PFX file or it exceeds the size limit")
		return
	}
	p := identity.Profile{P12: p12, Password: text(fields["p12pass"])}
	if ca := val("ca"); ca != "" {
		p.CA, err = boundedFile(ca, identity.MaxCABytes)
		if err != nil {
			appendLog(eventError, "Cannot read trusted CA PEM or it exceeds the size limit")
			return
		}
	}
	if err = identity.Validate(p); err != nil {
		appendLog(eventError, "P12/password or optional CA PEM is invalid")
		return
	}
	if err = identity.Save(p); err != nil {
		appendLog(eventError, "Could not save protected identity; prior saved identity remains unchanged")
		return
	}
	savedIdentity = &p
	setText.Call(fields["p12"], ptr(""))
	setText.Call(fields["p12pass"], ptr(""))
	setText.Call(fields["ca"], ptr(""))
	refreshIdentityState()
	appendLog(eventSuccess, "P12 identity saved with Windows user protection (RADIUS credentials not saved)")
}
func forgetIdentity() {
	if err := identity.Forget(); err != nil {
		appendLog(eventError, "Could not remove saved identity")
		return
	}
	savedIdentity = nil
	refreshIdentityState()
	appendLog(eventInfo, "Saved P12 identity forgotten")
}
func saveLog() {
	filter := utf16.Encode([]rune("Text files (*.txt)\x00*.txt\x00All files (*.*)\x00*.*\x00\x00"))
	file := make([]uint16, 32768)
	copy(file, syscall.StringToUTF16("radsec-diagnostics.txt"))
	opts := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: hwnd, Filter: uintptr(unsafe.Pointer(&filter[0])), FilterIndex: 1, File: uintptr(unsafe.Pointer(&file[0])), MaxFile: uint32(len(file)), Flags: 0x80000 | 0x2, DefaultExt: ptr("txt")}
	if ok, _, _ := getSaveFileName.Call(uintptr(unsafe.Pointer(&opts))); ok != 0 {
		if err := os.WriteFile(syscall.UTF16ToString(file), []byte(events.view()), 0600); err != nil {
			appendLog(eventError, "Could not save diagnostics")
		} else {
			appendLog(eventSuccess, "Diagnostics saved (no credentials included)")
		}
	}
	runtime.KeepAlive(filter)
	runtime.KeepAlive(file)
}
func copyLog() {
	content := syscall.StringToUTF16(events.view())
	if ok, _, _ := up("OpenClipboard").Call(hwnd); ok == 0 {
		return
	}
	defer up("CloseClipboard").Call()
	up("EmptyClipboard").Call()
	mem, _, _ := kernel32.NewProc("GlobalAlloc").Call(2, uintptr(len(content)*2))
	if mem == 0 {
		return
	}
	p, _, _ := kernel32.NewProc("GlobalLock").Call(mem)
	if p == 0 {
		kernel32.NewProc("GlobalFree").Call(mem)
		return
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(content)), content)
	kernel32.NewProc("GlobalUnlock").Call(mem)
	if ok, _, _ := up("SetClipboardData").Call(13, mem); ok == 0 {
		kernel32.NewProc("GlobalFree").Call(mem)
	}
}
func refreshModes() {
	mode := selected("credentials", "Separate PEM", "P12/PFX")
	vis := visibleCredentialFields(mode)
	for _, k := range []string{"ca", "cert", "key", "keypass", "p12", "p12pass"} {
		visible(k, vis[k])
	}
	acctFields := visibleAccountingFields(selected("kind", "auth", "acct", "full"))
	for _, k := range []string{"status", "session", "sessiontime", "password", "delay"} {
		visible(k, acctFields[k])
	}
	layout()
	refreshIdentityState()
}
func parseInt(k string, min, max int) (int, error) {
	v, e := strconv.Atoi(val(k))
	if e != nil || v < min || v > max {
		return 0, fmt.Errorf("%s must be %d..%d", k, min, max)
	}
	return v, nil
}
func runTests() {
	if running {
		return
	}
	port, e := parseInt("port", 1, 65535)
	if e != nil {
		appendLog(eventError, e.Error())
		return
	}
	count, e := parseInt("requests", 1, 10000)
	if e != nil {
		appendLog(eventError, e.Error())
		return
	}
	workers, e := parseInt("threads", 1, 100)
	if e != nil {
		appendLog(eventError, e.Error())
		return
	}
	seconds, e := parseInt("timeout", 1, 90)
	if e != nil {
		appendLog(eventError, e.Error())
		return
	}
	delayMS := 0
	if selected("kind", "auth", "acct", "full") == "full" {
		delayMS, e = parseInt("delay", 0, 3600000)
		if e != nil {
			appendLog(eventError, e.Error())
			return
		}
	}
	session := 0
	if selected("kind", "auth", "acct", "full") == "acct" {
		session, e = parseInt("sessiontime", 0, 2147483647)
		if e != nil {
			appendLog(eventError, e.Error())
			return
		}
	}
	kind := selected("kind", "auth", "acct", "full")
	status := selected("status", "Start", "Interim-Update", "Stop")
	tlsMin := selected("tls", "1.2", "1.3")
	var version uint16 = 0x0303
	if tlsMin == "1.3" {
		version = 0x0304
	}
	mode := selected("credentials", "Separate PEM", "P12/PFX")
	creds, e := chooseProfileCredentials(mode, map[string]string{"ca": val("ca"), "cert": val("cert"), "key": val("key"), "keypass": text(fields["keypass"]), "p12": val("p12"), "p12pass": text(fields["p12pass"])}, loadedProfile, savedIdentity)
	if e != nil {
		appendLog(eventError, e.Error())
		return
	}
	c := guiTLSConfig(val("host"), strconv.Itoa(port), val("sni"), val("secret"), creds, version, time.Duration(seconds)*time.Second)
	q := protocol.Request{Kind: kind, Username: val("username"), Password: text(fields["password"]), Status: status, SessionID: val("session"), SessionTime: uint32(session), Extra: val("extra")}
	if c.Host == "" || c.Secret == "" || q.Username == "" {
		appendLog(eventError, "Host, shared secret and username are required")
		return
	}
	if kind == "full" && q.Password == "" {
		appendLog(eventError, "Authentication password required for full transaction")
		return
	}
	if _, e := protocol.ParseAttributes(q.Extra); e != nil {
		appendLog(eventError, "Invalid extra attributes; check supported names and values")
		return
	}
	running = true
	debugEnabled := clientDebug
	if debugEnabled {
		appendLog(eventInfo, "Client-side debug enabled for first 10 requests only; not a proxy debug mode. Values and peer text hidden.")
	}
	setText.Call(runHandle, ptr("Running…"))
	setText.Call(statusHandle, ptr("Running · server hostname not checked"))
	appendLog(eventInfo, fmt.Sprintf("Starting %d %s requests with %d workers", count, kind, workers))
	statsVisible = true
	showStatsPage()
	var index int64
	activeRun = startRun(context.Background(), count, workers, func(ctx context.Context) (protocol.Result, error) {
		n := atomic.AddInt64(&index, 1)
		requestConfig := c
		if debugEnabled && n <= 10 {
			requestIndex := n
			requestConfig.Trace = func(line string) { appendLog(eventInfo, fmt.Sprintf("#%d %s", requestIndex, line)) }
		}
		var r protocol.Result
		var err error
		if kind == "full" {
			r, err = runFullTransactionContext(ctx, requestConfig, q, time.Duration(delayMS)*time.Millisecond, int(n))
		} else {
			r, err = protocol.ExchangeContext(ctx, requestConfig, q)
		}
		if err == nil {
			appendLog(classifyResponse(r.Name, nil), fmt.Sprintf("#%d %s · %d ms · TLS %s", n, r.Name, r.Duration.Milliseconds(), tlsName(r.TLSVersion)))
		} else if !errors.Is(err, context.Canceled) {
			appendLog(eventError, fmt.Sprintf("#%d %s", n, safeExchangeError(err)))
		}
		return r, err
	}, func() { post.Call(hwnd, WM_APP, 2, 0) })

}
func showStatsPage() {
	if statsHandle == 0 {
		return
	}
	if statsVisible {
		show.Call(statsHandle, SW_SHOW)
		show.Call(logHandle, SW_HIDE)
	} else {
		show.Call(statsHandle, SW_HIDE)
		show.Call(logHandle, SW_SHOW)
	}
}
func refreshStats() {
	if activeRun == nil {
		return
	}
	snap := activeRun.Snapshot()
	if detailsVisible {
		setText.Call(statsHandle, ptr(snap.Detailed()))
	} else {
		setText.Call(statsHandle, ptr(snap.String()))
	}
	if snap.Finished && running {
		running = false
		if snap.Stopped {
			appendLog(eventWarn, fmt.Sprintf("Cancelled: %d/%d completed; %d not started", snap.Completed, snap.Planned, snap.Planned-snap.Completed))
			setText.Call(statusHandle, ptr("Cancelled · final statistics available"))
		} else {
			appendLog(eventInfo, fmt.Sprintf("Finished: %d/%d requests", snap.Completed, snap.Planned))
			setText.Call(statusHandle, ptr("Ready · Last run complete · hostname unchecked"))
		}
		setText.Call(runHandle, ptr("Run RadSec test  →"))
		setText.Call(stopHandle, ptr("Stop (idle)"))
	}
}
func tlsName(v uint16) string {
	if v == 0x0304 {
		return "1.3"
	}
	if v == 0x0303 {
		return "1.2"
	}
	return "unknown"
}
func extraAttributeCaption(kind string) string {
	if kind == "full" {
		return "Extra attributes"
	}
	return "Extra attributes · Name = value; ..."
}
func layout() {
	if hwnd == 0 || fonts[0] == 0 {
		return
	}
	w := clientW * 96 / dpi
	h := clientH * 96 / dpi
	left := max(560, (w*55)/100)
	if left > w-350 {
		left = w - 350
	}
	half := (left - 68) / 2
	rightX := left + 20
	rightW := w - rightX - 20
	geometry := credentialLayout(selected("credentials", "Separate PEM", "P12/PFX"))
	requestTop := geometry["requestTop"].Y
	kind := selected("kind", "auth", "acct", "full")
	accounting := kind == "acct"
	setText.Call(groups["extra"][0], ptr(extraAttributeCaption(kind)))
	place("host", 38, 105, half)
	place("port", 50+half, 105, half)
	place("secret", 38, 161, half)
	place("sni", 50+half, 161, half)
	place("tls", 38, 217, half)
	place("credentials", 38, 319, half)
	place("ca", 50+half, 319, half)
	place("cert", 38, 375, half)
	place("key", 50+half, 375, half)
	place("keypass", 38, 431, half)
	place("p12", 38, 375, half)
	place("p12pass", 50+half, 375, half)
	position(identityState, 38, 301, max(140, left-265), 19)
	for b, n := range buttons {
		if n == idHelp {
			position(b, max(500, w-302), 19, 82, 30)
		}
		if n == idAbout {
			position(b, max(590, w-208), 19, 82, 30)
		}
		if n == idProfiles {
			position(b, left-126, 83, 105, 27)
		}
		if n == idSaveIdentity {
			position(b, left-225, 284, 105, 27)
		}
		if n == idForgetIdentity {
			position(b, left-112, 284, 94, 27)
		}
	}
	place("kind", 38, requestTop+28, half)
	place("username", 50+half, requestTop+28, half)
	place("password", 38, requestTop+84, half)
	place("status", 50+half, requestTop+84, half)
	place("session", 38, requestTop+140, half)
	place("sessiontime", 50+half, requestTop+140, half)
	place("delay", 50+half, requestTop+84, half)
	row := requestTop + 196
	if !accounting && selected("kind", "auth", "acct", "full") != "full" {
		place("password", 38, requestTop+84, half)
		place("requests", 50+half, requestTop+84, half)
		place("threads", 38, requestTop+140, half)
		place("timeout", 50+half, requestTop+140, half)
		place("extra", 38, requestTop+196, left-56)
		position(attributeButton, left-169, requestTop+196, 113, 19)
		position(runHandle, 38, requestTop+265, (left-64)/2, 43)
	} else if selected("kind", "auth", "acct", "full") == "full" {
		place("password", 38, requestTop+84, half)
		place("delay", 50+half, requestTop+84, half)
		place("requests", 38, requestTop+140, half)
		place("threads", 50+half, requestTop+140, half)
		place("timeout", 38, requestTop+196, half)
		place("extra", 50+half, requestTop+196, half)
		position(attributeButton, left-169, requestTop+196, 113, 19)
		position(runHandle, 38, requestTop+265, (left-64)/2, 43)
	} else {
		place("status", 38, requestTop+84, half)
		place("session", 50+half, requestTop+84, half)
		place("sessiontime", 38, requestTop+140, half)
		place("requests", 50+half, requestTop+140, half)
		place("threads", 38, row, half)
		place("timeout", 50+half, row, half)
		place("extra", 38, row+56, left-56)
		position(attributeButton, left-169, row+56, 113, 19)
		position(runHandle, 38, row+129, (left-64)/2, 43)
	}
	position(filterHandle, rightX+18, 153, 142, 170)
	position(searchHandle, rightX+170, 153, max(80, rightW-188), 30)
	for handle, n := range buttons {
		if n == idDebug {
			position(handle, rightX+18, 195, rightW-36, 30)
		} else if n == idClear || n == idCopy || n == idSave || n == idPause || n == idScroll {
			idx := map[int]int{idClear: 0, idCopy: 1, idSave: 2, idPause: 3, idScroll: 4}[n]
			bw := (rightW - 36 - 4*8) / 5
			position(handle, rightX+18+idx*(bw+8), 229, bw, 30)
		}
	}
	position(logHandle, rightX+18, 302, rightW-36, max(130, h-405))
	position(statsHandle, rightX+18, 302, rightW-36, max(130, h-405))
	position(stopHandle, 44+(left-64)/2, requestTop+265, (left-64)/2, 43)
	if accounting {
		position(stopHandle, 44+(left-64)/2, row+129, (left-64)/2, 43)
	}
	for handle, n := range buttons {
		if n == idStats {
			position(handle, rightX+18, 266, (rightW-52)/3, 29)
		}
		if n == idDetails {
			position(handle, rightX+26+(rightW-52)/3, 266, (rightW-52)/3, 29)
		}
		if n == idEvents {
			position(handle, rightX+34+2*(rightW-52)/3, 266, (rightW-52)/3, 29)
		}
	}
	position(statusHandle, rightX+18, max(370, h-80), rightW-36, 40)
	invalidate.Call(hwnd, 0, 1)
}
func fill(dc uintptr, r rect, color uintptr) {
	up("FillRect").Call(dc, uintptr(unsafe.Pointer(&r)), brush(color))
}
func box(dc uintptr, x, y, w, h int, color uintptr) {
	fill(dc, rect{int32(scale(x)), int32(scaleY(y)), int32(scale(x + w)), int32(scaleY(y + h))}, color)
}

// roundedRect paints a filled, bordered GDI card in physical pixels.
func roundedRect(dc uintptr, r rect, radius int, background, outline uintptr) {
	pen, _, _ := gp("CreatePen").Call(0, 1, outline)
	oldPen, _, _ := gp("SelectObject").Call(dc, pen)
	oldBrush, _, _ := gp("SelectObject").Call(dc, brush(background))
	gp("RoundRect").Call(dc, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom), uintptr(radius), uintptr(radius))
	gp("SelectObject").Call(dc, oldBrush)
	gp("SelectObject").Call(dc, oldPen)
	gp("DeleteObject").Call(pen)
}
func card(dc uintptr, x, y, width, height int) {
	roundedRect(dc, rect{int32(scale(x)), int32(scaleY(y)), int32(scale(x + width)), int32(scaleY(y + height))}, scale(14), panel, border)
}
func drawText(dc uintptr, s string, r rect, color uintptr, fontHandle uintptr, flags uintptr) {
	gp("SetBkMode").Call(dc, COLOR_TRANSPARENT)
	gp("SetTextColor").Call(dc, color)
	old, _, _ := gp("SelectObject").Call(dc, fontHandle)
	up("DrawTextW").Call(dc, ptr(s), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
	gp("SelectObject").Call(dc, old)
}
func caption(dc uintptr, s string, x, y, w, h int, color uintptr, bold bool) {
	f := fonts[0]
	if bold {
		f = fonts[1]
	}
	drawText(dc, s, rect{int32(scale(x)), int32(scaleY(y)), int32(scale(x + w)), int32(scaleY(y + h))}, color, f, 0x20|0x4|0x800)
}
func paint() {
	var ps paintStruct
	dc, _, _ := up("BeginPaint").Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer up("EndPaint").Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	w := clientW * 96 / dpi
	h := clientH * 96 / dpi
	left := max(560, w*55/100)
	if left > w-350 {
		left = w - 350
	}
	half := (left - 68) / 2
	rx := left + 20
	rw := w - rx - 20
	geometry := credentialLayout(selected("credentials", "Separate PEM", "P12/PFX"))
	requestTop := geometry["requestTop"].Y
	accounting := selected("kind", "auth", "acct", "full") == "acct"
	requestHeight := 311
	if !accounting {
		requestHeight = 311
	}
	if selected("kind", "auth", "acct", "full") == "full" {
		requestHeight = 318
	}
	box(dc, 0, 0, w, h, canvas)
	caption(dc, appTitle, 22, 19, 480, 23, ink, true)
	caption(dc, "v"+appVersion, max(500, w-85), 19, 64, 23, muted, false)
	caption(dc, "Mutual TLS · RADIUS over TCP", 22, 44, 520, 22, muted, false)
	card(dc, 20, 76, left-2, 196)
	card(dc, 20, 280, left-2, geometry["sectionBottom"].Y-280)
	card(dc, 20, requestTop, left-2, requestHeight)
	caption(dc, "01   CONNECTION", 38, 85, 360, 19, accent, true)
	caption(dc, "HOSTNAME CHECK OFF", 50+half, 225, half, 18, amber, true)
	caption(dc, "CA chain + dates still checked", 50+half, 248, half, 19, muted, false)
	caption(dc, "02   CLIENT IDENTITY", 38, 282, 360, 18, accent, true)
	caption(dc, "03   RADIUS REQUEST", 38, requestTop+9, 360, 19, accent, true)
	caption(dc, mainProfileCaption, 38, requestTop+requestHeight+65, left-56, 22, muted, false)
	card(dc, rx, 76, rw, max(370, h-96))
	caption(dc, "DIAGNOSTICS", rx+18, 91, 220, 23, ink, true)
	caption(dc, "LOCAL EVENTS  ·  NO SECRETS", rx+18, 114, rw-36, 18, muted, false)
	caption(dc, "SEVERITY", rx+18, 137, 142, 17, muted, false)
	caption(dc, "SEARCH EVENTS", rx+170, 137, rw-188, 17, muted, false)
}
func drawControl(d *drawItem) {
	r := d.Rc
	dc := d.DC
	if d.CtlType == 3 {
		bg := raised
		fg := ink
		if d.ItemState&1 != 0 {
			bg = accent
		}
		fill(dc, r, bg)
		if d.ItemID != ^uint32(0) {
			options := map[uintptr][]string{fields["credentials"]: {"Separate PEM", "P12/PFX"}, fields["tls"]: {"1.2", "1.3"}, fields["kind"]: {"auth", "acct", "full"}, fields["status"]: {"Start", "Interim-Update", "Stop"}, filterHandle: {"All events", "Success + warnings", "Warnings + errors", "Errors only"}}
			for handle, opts := range attributeComboOptions {
				options[handle] = opts
			}
			s := ""
			if opts, ok := options[d.Item]; ok && int(d.ItemID) < len(opts) {
				s = opts[d.ItemID]
			}
			r.Left += int32(scale(10))
			drawText(dc, s, r, fg, fonts[0], 0x20|0x4)
		}
		return
	}
	n := buttons[d.Item]
	bg := raised
	if n == idRun {
		bg = accent
	}
	if d.ItemState&1 != 0 {
		bg = border
	}
	roundedRect(dc, r, scale(9), bg, border)
	name := text(d.Item)
	drawText(dc, name, r, ink, fonts[0], 0x1|0x4|0x20)
	if d.ItemState&0x10 != 0 {
		up("DrawFocusRect").Call(dc, uintptr(unsafe.Pointer(&r)))
	}
}
func setColor(dc, child uintptr) uintptr {
	bg := panel
	fg := muted
	if child == logHandle || child == statsHandle || child == searchHandle || child == filterHandle {
		bg = raised
	}
	for _, h := range fields {
		if h == child {
			bg = raised
			fg = ink
			break
		}
	}
	if child == statusHandle {
		fg = amber
	}
	gp("SetTextColor").Call(dc, fg)
	gp("SetBkColor").Call(dc, bg)
	return brush(bg)
}
func wndproc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case WM_SIZE:
		clientW = int(uint16(l))
		clientH = int(uint16(l >> 16))
		layout()
		return 0
	case WM_GETMINMAXINFO:
		p := (*minMax)(unsafe.Pointer(l))
		p.MinTrack = point{int32(scale(1060)), int32(scale(1000))}
		return 0
	case WM_DPICHANGED:
		dpi = int(uint16(w))
		if dpi < 96 {
			dpi = 96
		}
		for i, f := range fonts {
			gp("DeleteObject").Call(f)
			fonts[i] = 0
		}
		fonts[0] = font(14, false)
		fonts[1] = font(15, true)
		fonts[2] = font(13, false)
		for _, a := range groups {
			for _, child := range a {
				send.Call(child, WM_SETFONT, fonts[0], 1)
			}
		}
		for b := range buttons {
			send.Call(b, WM_SETFONT, fonts[0], 1)
		}
		send.Call(logHandle, WM_SETFONT, fonts[2], 1)
		r := (*rect)(unsafe.Pointer(l))
		up("SetWindowPos").Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 4)
		layout()
		return 0
	case WM_ERASEBKGND:
		return 1
	case WM_PAINT:
		paint()
		return 0
	case WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_CTLCOLORLISTBOX:
		return setColor(w, l)
	case WM_DRAWITEM:
		drawControl((*drawItem)(unsafe.Pointer(l)))
		return 1
	case WM_COMMAND:
		n := int(w & 0xffff)
		notification := w >> 16
		if notification == CBN_SELCHANGE && (l == fields["credentials"] || l == fields["kind"]) {
			if l == fields["credentials"] {
				active := visibleCredentialFields(selected("credentials", "Separate PEM", "P12/PFX"))
				for _, key := range []string{"cert", "key", "keypass", "p12", "p12pass"} {
					if !active[key] {
						setText.Call(fields[key], ptr(""))
					}
				}
			}
			if l == fields["kind"] && selected("kind", "auth", "acct", "full") == "acct" {
				setText.Call(fields["password"], ptr(""))
			}
			refreshModes()
			return 0
		}
		if l == filterHandle && notification == CBN_SELCHANGE {
			idx, _, _ := send.Call(filterHandle, CB_GETCURSEL, 0, 0)
			level := eventInfo
			if idx == 1 {
				level = eventSuccess
			} else if idx == 2 {
				level = eventWarn
			} else if idx == 3 {
				level = eventError
			}
			events.setFilter(level, text(searchHandle))
			redrawLog()
			return 0
		}
		if l == fields["p12"] && notification == EN_CHANGE {
			refreshIdentityState()
			return 0
		}
		if l == searchHandle && notification == EN_CHANGE {
			events.setFilter(events.minLevel, text(searchHandle))
			redrawLog()
			return 0
		}
		switch n {
		case idAttributes:
			openAttributeEditor()
		case idRun:
			runTests()
		case idStop:
			if activeRun != nil && running {
				activeRun.Stop()
				setText.Call(stopHandle, ptr("Stopping…"))
				setText.Call(statusHandle, ptr("Stopping · waiting for in-flight requests"))
			}
		case idStats:
			detailsVisible = false
			statsVisible = true
			showStatsPage()
			refreshStats()
		case idDetails:
			detailsVisible = true
			statsVisible = true
			showStatsPage()
			refreshStats()
		case idEvents:
			statsVisible = false
			showStatsPage()
		case idDebug:
			clientDebug = !clientDebug
			for b, buttonID := range buttons {
				if buttonID == idDebug {
					if clientDebug {
						setText.Call(b, ptr("Client-side debug: ON"))
					} else {
						setText.Call(b, ptr("Client-side debug: OFF"))
					}
				}
			}
			if clientDebug {
				appendLog(eventInfo, "Client-side debug enabled (next Run only); this is not a proxy debug mode")
			} else {
				appendLog(eventInfo, "Client-side debug disabled")
			}
		case idCA:
			browseFile("ca")
		case idCert:
			browseFile("cert")
		case idKey:
			browseFile("key")
		case idP12:
			browseFile("p12")
		case idSaveIdentity:
			saveIdentity()
		case idHelp:
			openHelpWindow()
		case idAbout:
			openAboutWindow()
		case idProfiles:
			openProfileDialog()
		case idForgetIdentity:
			forgetIdentity()
		case idClear:
			events.clear()
			redrawLog()
		case idCopy:
			copyLog()
		case idSave:
			saveLog()
		case idPause:
			events.setPaused(!events.paused)
			for b, id := range buttons {
				if id == idPause {
					v := "Pause"
					if events.paused {
						v = "Resume"
					}
					setText.Call(b, ptr(v))
					invalidate.Call(b, 0, 1)
				}
			}
			redrawLog()
		case idScroll:
			autoScroll = !autoScroll
			for b, id := range buttons {
				if id == idScroll {
					v := "Scroll on"
					if !autoScroll {
						v = "Scroll off"
					}
					setText.Call(b, ptr(v))
					invalidate.Call(b, 0, 1)
				}
			}
		}
		return 0
	case WM_APP:
		drain()
		if w == 2 {
			refreshStats()
		}
		return 0
	case WM_DESTROY:
		if activeRun != nil && running {
			activeRun.Stop()
		}
		for _, b := range brushes {
			gp("DeleteObject").Call(b)
		}
		for _, f := range fonts {
			gp("DeleteObject").Call(f)
		}
		up("PostQuitMessage").Call(0)
		return 0
	}
	r, _, _ := up("DefWindowProcW").Call(h, uintptr(m), w, l)
	return r
}
func main() {
	runtime.LockOSThread()
	dpiReady := uintptr(0)
	if aware := up("SetProcessDpiAwarenessContext"); aware.Find() == nil {
		dpiReady, _, _ = aware.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	}
	if dpiReady == 0 {
		if legacy := up("SetProcessDPIAware"); legacy.Find() == nil {
			legacy.Call()
		}
	}
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	name := syscall.StringToUTF16Ptr("RadSecConnectionLab")
	// Use the embedded RadiusStack shield in the title bar, taskbar and Alt-Tab.
	largeIcon, _, _ := up("LoadImageW").Call(inst, 1, 1, 32, 32, 0)
	smallIcon, _, _ := up("LoadImageW").Call(inst, 1, 1, 16, 16, 0)
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: syscall.NewCallback(wndproc), Instance: inst, Name: uintptr(unsafe.Pointer(name)), Icon: largeIcon, IconSmall: smallIcon, Cursor: func() uintptr { c, _, _ := up("LoadCursorW").Call(0, 32512); return c }(), Background: brush(canvas)}
	if n, _, err := reg.Call(uintptr(unsafe.Pointer(&wc))); n == 0 {
		panic(err)
	}
	hwnd, _, _ = create.Call(0, uintptr(unsafe.Pointer(name)), ptr(appTitle+"  ·  "+appVersion), WS_OVERLAPPEDWINDOW, 100, 35, 1280, 1060, 0, 0, inst, 0)
	if hwnd == 0 {
		panic("CreateWindowExW failed")
	}
	if p := up("GetDpiForWindow"); p.Find() == nil {
		v, _, _ := p.Call(hwnd)
		if v >= 96 {
			dpi = int(v)
		}
	}
	dark := int32(1)
	if theme := dwm.NewProc("DwmSetWindowAttribute"); theme.Find() == nil {
		theme.Call(hwnd, 20, uintptr(unsafe.Pointer(&dark)), 4)
	}
	fonts[0] = font(14, false)
	fonts[1] = font(15, true)
	fonts[2] = font(13, false)
	field("host", "RadSec host / IP", "", false)
	field("port", "TCP port", "2083", false)
	field("secret", "Shared secret", "", true)
	field("sni", "TLS SNI hostname · optional", "", false)
	combo("tls", "Minimum TLS", []string{"1.2", "1.3"})
	combo("credentials", "Client certificate format", []string{"Separate PEM", "P12/PFX"})
	fileField("ca", "Trusted CA PEM · optional", idCA)
	fileField("cert", "Client certificate PEM", idCert)
	fileField("key", "Client private key PEM", idKey)
	field("keypass", "PEM key passphrase", "", true)
	fileField("p12", "Combined P12 / PFX bundle", idP12)
	field("p12pass", "P12 / PFX password", "", true)
	identityState = label("No saved P12 identity", false)
	button("Save P12", idSaveIdentity)
	button("Profiles...", idProfiles)
	button("Help", idHelp)
	button("About", idAbout)
	button("Forget", idForgetIdentity)
	combo("kind", "Request type", []string{"auth", "acct", "full"})
	field("username", "Username", "", false)
	field("password", "Password", "", true)
	combo("status", "Accounting status", []string{"Start", "Interim-Update", "Stop"})
	field("session", "Accounting session ID", "radsec-win-test", false)
	field("sessiontime", "Accounting session seconds", "0", false)
	field("delay", "Between acct stages · ms (0–3600000)", "0", false)
	field("requests", "Repeat requests", "1", false)
	field("threads", "Parallel workers", "1", false)
	field("timeout", "Timeout per request · seconds", "20", false)
	field("extra", "Extra attributes · Name = value; ...", "", false)
	attributeButton = button("Edit attributes…", idAttributes)
	runHandle = button("Run RadSec test  →", idRun)
	stopHandle = button("Stop (idle)", idStop)
	filterHandle = control("COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST|CBS_OWNERDRAWFIXED|CBS_HASSTRINGS)
	for _, s := range []string{"All events", "Success + warnings", "Warnings + errors", "Errors only"} {
		send.Call(filterHandle, CB_ADDSTRING, 0, ptr(s))
	}
	send.Call(filterHandle, CB_SETCURSEL, 0, 0)
	searchHandle = control("EDIT", "", WS_TABSTOP|ES_AUTOHSCROLL|0x00800000)
	for _, v := range []struct {
		s string
		n int
	}{{"Clear", idClear}, {"Copy", idCopy}, {"Save", idSave}, {"Pause", idPause}, {"Scroll on", idScroll}, {"Client-side debug: OFF", idDebug}} {
		button(v.s, v.n)
	}
	logHandle = control("EDIT", "", ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL|0x00800000)
	button("Live statistics", idStats)
	button("Details (50+)", idDetails)
	button("Events", idEvents)
	statsHandle = control("EDIT", "No run yet. Live statistics appear when a run starts.", ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL|0x00800000)
	send.Call(statsHandle, WM_SETFONT, fonts[2], 1)
	send.Call(logHandle, EM_LIMITTEXT, 500000, 0)
	send.Call(logHandle, WM_SETFONT, fonts[2], 1)
	statusHandle = label("Ready · CA trust required · hostname unchecked", false)
	r := rect{}
	up("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&r)))
	clientW = int(r.Right)
	clientH = int(r.Bottom)
	layout()
	showStatsPage()
	refreshModes()
	if p, err := identity.Load(); err == nil {
		savedIdentity = &p
		events.add(eventInfo, "Saved P12 identity loaded into memory")
	} else if !os.IsNotExist(err) {
		events.add(eventWarn, "Saved P12 identity unavailable or invalid; select a P12 file")
	}
	refreshIdentityState()
	events.add(eventInfo, "Hostname matching OFF: trust chain, certificate dates and server-auth usage remain checked")
	redrawLog()
	show.Call(hwnd, SW_SHOW)
	up("UpdateWindow").Call(hwnd)
	var message msg
	for {
		n, _, _ := up("GetMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(n) <= 0 {
			break
		}
		if handled, _, _ := up("IsDialogMessageW").Call(hwnd, uintptr(unsafe.Pointer(&message))); handled != 0 {
			continue
		}
		up("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
		up("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
	}
}

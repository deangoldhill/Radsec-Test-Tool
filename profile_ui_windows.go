//go:build windows

package main

import (
	"errors"
	"radsec-windows-tester/identity"
	"radsec-windows-tester/protocol"
	"radsec-windows-tester/testprofile"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var loadedProfile *testprofile.Profile
var profileWindow, profileStatus, profilePass, profileName uintptr

const (
	profileDialogWidth  = 900 // initial outer window, in 96-DPI units
	profileDialogHeight = 560
	profileButtonWidth  = 128 // minimum reference width; actual buttons share available space
	profileStatusY      = 415
	profileStatusHeight = 34
)

func profileButtonX(i int) int { return 28 + i*138 }

type profileGeometry struct {
	name, pass, status, local, portable rect
	buttons                             [5]rect
}

var profileButtons [5]uintptr

func profileLayout(width, height int) profileGeometry {
	u := scale
	margin := u(28)
	name := rect{int32(margin), int32(u(157)), int32(width - margin), int32(u(191))}
	pass := rect{int32(margin), int32(u(354)), int32(width - margin), int32(u(388))}
	statusTop := height - u(54)
	status := rect{int32(margin), int32(statusTop), int32(width - margin), int32(statusTop + u(34))}
	local := rect{int32(u(16)), int32(u(86)), int32(width - u(16)), int32(u(278))}
	portable := rect{int32(u(16)), int32(u(285)), int32(width - u(16)), int32(statusTop - u(16))}
	var buttons [5]rect
	gap := u(10)
	available := width - 2*margin - 4*gap
	bw := available / 5
	for i := range buttons {
		x := margin + i*(bw+gap)
		buttons[i] = rect{int32(x), int32(u(207)), int32(x + bw), int32(u(246))}
	}
	return profileGeometry{name, pass, status, local, portable, buttons}
}
func moveRect(h uintptr, r rect) {
	if h != 0 {
		move.Call(h, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 1)
	}
}
func profileExtraForSave(current string, rows []attributeRow, editorOpen bool) (string, error) {
	if !editorOpen {
		return current, nil
	}
	extra := renderAttributeRows(rows)
	if _, err := protocol.ParseAttributes(extra); err != nil {
		return "", err
	}
	return extra, nil
}
func profileNameListHeight() int { return scale(220) }
func resizeProfile() {
	if profileWindow == 0 {
		return
	}
	var client rect
	up("GetClientRect").Call(profileWindow, uintptr(unsafe.Pointer(&client)))
	if client.Right <= 0 || client.Bottom <= 0 {
		return
	}
	g := profileLayout(int(client.Right), int(client.Bottom))
	move.Call(profileName, uintptr(g.name.Left), uintptr(g.name.Top), uintptr(g.name.Right-g.name.Left), uintptr(profileNameListHeight()), 1)
	moveRect(profilePass, g.pass)
	moveRect(profileStatus, g.status)
	for i, h := range profileButtons {
		moveRect(h, g.buttons[i])
	}
	invalidate.Call(profileWindow, 0, 1)
}

const (
	profileSave   = 401
	profileLoad   = 402
	profileExport = 403
	profileImport = 404
	profileForget = 405
)

var profileClassName = syscall.StringToUTF16Ptr("RadSecProfileDialog")

func profileValues() map[string]string {
	v := map[string]string{}
	for _, key := range []string{"host", "port", "secret", "sni", "ca", "cert", "key", "keypass", "p12", "p12pass", "username", "password", "session", "sessiontime", "requests", "threads", "timeout", "delay", "extra"} {
		v[key] = text(fields[key])
	}
	for _, c := range []struct {
		key     string
		options []string
	}{{"tls", []string{"1.2", "1.3"}}, {"credentials", []string{"Separate PEM", "P12/PFX"}}, {"kind", []string{"auth", "acct", "full"}}, {"status", []string{"Start", "Interim-Update", "Stop"}}} {
		v[c.key] = selected(c.key, c.options...)
	}
	return v
}
func collectProfile(v map[string]string, saved *testprofile.Profile, legacy *identity.Profile) (testprofile.Profile, error) {
	p := testprofile.Profile{Host: strings.TrimSpace(v["host"]), Port: strings.TrimSpace(v["port"]), Secret: v["secret"], SNI: strings.TrimSpace(v["sni"]), TLS: v["tls"], Mode: v["credentials"], KeyPass: v["keypass"], P12Pass: v["p12pass"], Kind: v["kind"], Delay: v["delay"], Username: v["username"], Password: v["password"], Status: v["status"], Session: v["session"], SessionTime: v["sessiontime"], Requests: v["requests"], Threads: v["threads"], Timeout: v["timeout"], Extra: v["extra"]}
	var err error
	extra, err := profileExtraForSave(v["extra"], attributeRows, attributeWindow != 0)
	if err != nil {
		return testprofile.Profile{}, errors.New("invalid pending attributes")
	}
	p.Extra = extra
	if path := strings.TrimSpace(v["ca"]); path != "" {
		p.CA, err = boundedFile(path, testprofile.MaxCertificateBytes)
		if err != nil {
			return testprofile.Profile{}, errors.New("cannot read selected CA")
		}
	} else if saved != nil {
		p.CA = append([]byte(nil), saved.CA...)
	} else if legacy != nil && p.Mode == "P12/PFX" {
		p.CA = append([]byte(nil), legacy.CA...)
	}
	if p.Mode == "Separate PEM" {
		if path := strings.TrimSpace(v["cert"]); path != "" {
			p.Cert, err = boundedFile(path, testprofile.MaxCertificateBytes)
			if err != nil {
				return testprofile.Profile{}, errors.New("cannot read selected certificate")
			}
		} else if saved != nil && saved.Mode == p.Mode {
			p.Cert = append([]byte(nil), saved.Cert...)
		}
		if path := strings.TrimSpace(v["key"]); path != "" {
			p.Key, err = boundedFile(path, testprofile.MaxCertificateBytes)
			if err != nil {
				return testprofile.Profile{}, errors.New("cannot read selected private key")
			}
		} else if saved != nil && saved.Mode == p.Mode {
			p.Key = append([]byte(nil), saved.Key...)
		}
		if p.KeyPass == "" && saved != nil && saved.Mode == p.Mode {
			p.KeyPass = saved.KeyPass
		}
	} else if p.Mode == "P12/PFX" {
		if path := strings.TrimSpace(v["p12"]); path != "" {
			p.P12, err = boundedFile(path, testprofile.MaxCertificateBytes)
			if err != nil {
				return testprofile.Profile{}, errors.New("cannot read selected P12")
			}
		} else if saved != nil && saved.Mode == p.Mode {
			p.P12 = append([]byte(nil), saved.P12...)
		} else if legacy != nil {
			p.P12 = append([]byte(nil), legacy.P12...)
		}
		if p.P12Pass == "" {
			if saved != nil && saved.Mode == p.Mode {
				p.P12Pass = saved.P12Pass
			} else if legacy != nil {
				p.P12Pass = legacy.Password
			}
		}
	}
	if p.Delay == "" {
		p.Delay = "0"
	}
	if err = testprofile.Validate(p); err != nil {
		return testprofile.Profile{}, err
	}
	if _, err = protocol.ParseAttributes(p.Extra); err != nil {
		return testprofile.Profile{}, errors.New("invalid extra attributes")
	}
	return p, nil
}
func setCombo(key string, options []string, value string) {
	for i, v := range options {
		if v == value {
			send.Call(fields[key], CB_SETCURSEL, uintptr(i), 0)
			return
		}
	}
}
func applyProfile(p testprofile.Profile) {
	for key, value := range map[string]string{"host": p.Host, "port": p.Port, "secret": p.Secret, "sni": p.SNI, "username": p.Username, "password": p.Password, "session": p.Session, "sessiontime": p.SessionTime, "requests": p.Requests, "threads": p.Threads, "timeout": p.Timeout, "delay": p.Delay, "extra": p.Extra} {
		setText.Call(fields[key], ptr(value))
	}
	for _, key := range []string{"ca", "cert", "key", "keypass", "p12", "p12pass"} {
		setText.Call(fields[key], ptr(""))
	}
	setCombo("tls", []string{"1.2", "1.3"}, p.TLS)
	setCombo("credentials", []string{"Separate PEM", "P12/PFX"}, p.Mode)
	setCombo("kind", []string{"auth", "acct", "full"}, p.Kind)
	setCombo("status", []string{"Start", "Interim-Update", "Stop"}, p.Status)
	loadedProfile = &p
	if attributeWindow != 0 {
		if rows, err := parseAttributeRows(p.Extra); err == nil {
			attributeRows = rows
			resetEditorList(-1)
		}
	}
	refreshModes()
}
func profileFile(save bool) (string, bool) {
	filter := utf16.Encode([]rune("RadSec profile (*.radsecprofile)\x00*.radsecprofile\x00\x00"))
	file := make([]uint16, 32768)
	if save {
		copy(file, syscall.StringToUTF16("radsec-test.radsecprofile"))
	}
	opts := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: profileWindow, Filter: uintptr(unsafe.Pointer(&filter[0])), FilterIndex: 1, File: uintptr(unsafe.Pointer(&file[0])), MaxFile: uint32(len(file)), Flags: 0x80000 | 0x8, DefaultExt: ptr("radsecprofile")}
	api := getOpenFileName
	if save {
		api = getSaveFileName
		opts.Flags = 0x80000 | 0x2
	}
	ok, _, _ := api.Call(uintptr(unsafe.Pointer(&opts)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(file)
	if ok == 0 {
		return "", false
	}
	return syscall.UTF16ToString(file), true
}
func profileMessage(s string) { setText.Call(profileStatus, ptr(s)) }
func refreshProfileNames(preferred string) {
	names, err := testprofile.ListNamed()
	if err != nil {
		profileMessage("Could not list local profiles")
		return
	}
	send.Call(profileName, 0x14b, 0, 0) // CB_RESETCONTENT
	for i, name := range names {
		send.Call(profileName, CB_ADDSTRING, 0, ptr(name))
		if name == preferred {
			send.Call(profileName, CB_SETCURSEL, uintptr(i), 0)
		}
	}
	if preferred == "" {
		setText.Call(profileName, ptr(""))
	}
}
func chosenProfileName() (string, bool) {
	name := text(profileName)
	if testprofile.ValidateName(name) != nil {
		profileMessage("Name: 1-48 ASCII letters, digits, - or _ (start with a letter/digit)")
		return "", false
	}
	return name, true
}
func profileAction(n int) {
	switch n {
	case profileLoad:
		name, ok := chosenProfileName()
		if !ok {
			return
		}
		p, err := testprofile.LoadNamed(name)
		if err != nil {
			profileMessage("No readable protected profile with that name")
			return
		}
		applyProfile(p)
		profileMessage("Windows-protected profile loaded: " + name)
	case profileForget:
		name, ok := chosenProfileName()
		if !ok {
			return
		}
		// Explicitly confirm deletion; live fields are intentionally unchanged.
		confirm, _, _ := up("MessageBoxW").Call(profileWindow, ptr("Delete local profile "+name+"?"), ptr("Confirm profile deletion"), 0x24)
		if confirm != 6 {
			return
		}
		if err := testprofile.DeleteNamed(name); err != nil {
			profileMessage("Could not remove local profile")
			return
		}
		refreshProfileNames("")
		profileMessage("Deleted " + name + " (current fields remain)")
	case profileSave, profileExport:
		p, err := collectProfile(profileValues(), loadedProfile, savedIdentity)
		if err != nil {
			profileMessage("Profile incomplete: check settings and certificate files")
			return
		}
		if n == profileSave {
			name, ok := chosenProfileName()
			if !ok {
				return
			}
			if err = testprofile.SaveNamed(name, p); err != nil {
				profileMessage("Could not save Windows-protected profile")
				return
			}
			loadedProfile = &p
			refreshProfileNames(name)
			profileMessage("Saved " + name + " with Windows user protection")
			return
		}
		pass := text(profilePass)
		path, ok := profileFile(true)
		if !ok {
			return
		}
		err = testprofile.ExportFile(path, p, pass)
		setText.Call(profilePass, ptr(""))
		if err != nil {
			profileMessage("Export failed; choose a NEW file")
			return
		}
		if pass == "" {
			profileMessage("Readable profile exported (includes credentials and attributes)")
		} else {
			profileMessage("Encrypted profile exported (includes credentials and attributes)")
		}
	case profileImport:
		pass := text(profilePass)
		path, ok := profileFile(false)
		if !ok {
			return
		}
		p, err := testprofile.ImportFile(path, pass)
		setText.Call(profilePass, ptr(""))
		if err != nil {
			profileMessage("Import failed: invalid file or wrong password")
			return
		}
		applyProfile(p)
		profileMessage("Profile imported into current fields (including attributes)")
	}
}
func profileWndProc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case WM_COMMAND:
		switch int(w & 0xffff) {
		case profileSave, profileLoad, profileExport, profileImport, profileForget:
			profileAction(int(w & 0xffff))
			return 0
		}
	case WM_SIZE:
		resizeProfile()
		return 0
	case WM_GETMINMAXINFO:
		min := (*minMax)(unsafe.Pointer(l))
		min.MinTrack = point{int32(scale(790)), int32(scale(500))}
		return 0
	case WM_PAINT:
		var ps paintStruct
		dc, _, _ := up("BeginPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
		r := rect{}
		up("GetClientRect").Call(h, uintptr(unsafe.Pointer(&r)))
		fill(dc, rect{0, 0, r.Right, r.Bottom}, canvas)
		g := profileLayout(int(r.Right), int(r.Bottom))
		roundedRect(dc, g.local, scale(16), panel, border)
		roundedRect(dc, g.portable, scale(16), panel, border)
		profileCaption(dc, "SECURE PROFILES", 28, 18, int(r.Right)-scale(56), 28, ink, true)
		profileCaption(dc, profilePortableDescription, 28, 51, int(r.Right)-scale(56), 27, muted, false)
		profileCaption(dc, "LOCAL PROFILES", 28, 99, int(r.Right)-scale(56), 27, accent, true)
		profileCaption(dc, "Profile name — choose saved or type a new name", 28, 126, int(r.Right)-scale(56), 27, muted, false)
		profileCaption(dc, "Saving an existing name replaces that local profile.", 28, 249, int(r.Right)-scale(56), 25, muted, false)
		profileCaption(dc, "PORTABLE PROFILE", 28, 296, int(r.Right)-scale(56), 27, accent, true)
		profileCaption(dc, "Export password · optional (blank makes a readable file)", 28, 324, int(r.Right)-scale(56), 27, muted, false)
		up("EndPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
		return 0
	case WM_ERASEBKGND:
		return 1
	case WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX:
		gp("SetTextColor").Call(w, ink)
		gp("SetBkColor").Call(w, raised)
		return brush(raised)
	case WM_DRAWITEM:
		item := (*drawItem)(unsafe.Pointer(l))
		bg := raised
		if item.ItemState&1 != 0 {
			bg = accent
		}
		roundedRect(item.DC, item.Rc, 12, bg, border)
		drawText(item.DC, text(item.Item), item.Rc, ink, fonts[0], 0x1|0x4|0x20)
		return 1
	case 0x10: // WM_CLOSE
		up("DestroyWindow").Call(h)
		return 0
	case WM_DESTROY:
		profileWindow = 0
		return 0
	}
	r, _, _ := up("DefWindowProcW").Call(h, uintptr(m), w, l)
	return r
}

const profilePortableDescription = "Windows-protected local profiles  ·  readable or encrypted portable files"

func profileCaption(dc uintptr, s string, x, y, w, h int, color uintptr, bold bool) {
	f := fonts[0]
	if bold {
		f = fonts[1]
	}
	drawText(dc, s, rect{int32(scale(x)), int32(scale(y)), int32(scale(x) + w), int32(scale(y + h))}, color, f, 0x20|0x4|0x800)
}
func openProfileDialog() {
	if profileWindow != 0 {
		return
	}
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: syscall.NewCallback(profileWndProc), Instance: inst, Name: uintptr(unsafe.Pointer(profileClassName)), Cursor: func() uintptr { c, _, _ := up("LoadCursorW").Call(0, 32512); return c }(), Background: brush(panel)}
	reg.Call(uintptr(unsafe.Pointer(&wc)))
	profileWindow, _, _ = create.Call(0, uintptr(unsafe.Pointer(profileClassName)), ptr("Secure profiles  ·  v"+appVersion), WS_OVERLAPPEDWINDOW, uintptr(centerChildX(hwnd, scale(profileDialogWidth))), uintptr(centerChildY(hwnd, scale(profileDialogHeight))), uintptr(scale(profileDialogWidth)), uintptr(scale(profileDialogHeight)), hwnd, 0, inst, 0)
	if profileWindow == 0 {
		return
	}
	child := func(class, name string, style uintptr, x, y, width, height int) uintptr {
		h, _, _ := create.Call(0, ptr(class), ptr(name), style|WS_CHILD|WS_VISIBLE, uintptr(x), uintptr(y), uintptr(width), uintptr(height), profileWindow, 0, inst, 0)
		send.Call(h, WM_SETFONT, fonts[0], 1)
		return h
	}
	profileName = child("COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|0x2|CBS_HASSTRINGS, 0, 0, 10, scale(175)) // CBS_DROPDOWN
	refreshProfileNames("")
	for i, b := range []struct {
		name string
		id   int
	}{{"Save local", profileSave}, {"Load local", profileLoad}, {"Export...", profileExport}, {"Import...", profileImport}, {"Delete local", profileForget}} {
		h := child("BUTTON", b.name, WS_TABSTOP|BS_OWNERDRAW, 0, 0, 10, 10)
		profileButtons[i] = h
		id(h, b.id)
	}
	profilePass = child("EDIT", "", WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL|0x00800000, 0, 0, 10, 10)
	profileStatus = child("STATIC", "Existing file exports are never overwritten.", 0, 0, 0, 10, 10)
	resizeProfile()
	up("EnableWindow").Call(hwnd, 0)
	show.Call(profileWindow, SW_SHOW)
	up("UpdateWindow").Call(profileWindow)
	var message msg
	for profileWindow != 0 {
		n, _, _ := up("GetMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(n) <= 0 {
			break
		}
		if handled, _, _ := up("IsDialogMessageW").Call(profileWindow, uintptr(unsafe.Pointer(&message))); handled != 0 {
			continue
		}
		up("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
		up("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
	}
	up("EnableWindow").Call(hwnd, 1)
}

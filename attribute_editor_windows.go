//go:build windows

package main

import (
	"radsec-windows-tester/protocol"
	"strings"
	"syscall"
	"unsafe"
)

const (
	attributeAddID    = 401
	WM_CLOSE          = 0x10
	attributeRemoveID = 402
	attributeApplyID  = 403
	attributeCloseID  = 404
	LB_ADDSTRING      = 0x180
	LB_RESETCONTENT   = 0x184
	LB_GETCURSEL      = 0x188
	LB_SETCURSEL      = 0x186
	LBN_SELCHANGE     = 1
	CB_RESETCONTENT   = 0x14b
)

var attributeButton uintptr
var attributeWindow uintptr
var attributeList, attributeName, attributeMode, attributeValue, attributeHint uintptr
var attributeRows []attributeRow
var attributeNames []string
var standardAttributeOptions []protocol.AttributeOption
var attributeAddButton, attributeRemoveButton, attributeApplyButton, attributeCloseButton uintptr
var attributeTitle, attributeNameLabel, attributeModeLabel, attributeValueLabel uintptr

const attributeWindowWidth = 1020
const attributeWindowHeight = 760

type attributeGeometry struct{ list, name, mode, value, hint, apply, cancel, add, remove, title, nameLabel, modeLabel, valueLabel rect }

func attributeLayout(width, height int) attributeGeometry {
	u := scale
	margin := u(24)
	gap := u(16)
	side := u(190)
	list := rect{int32(margin), int32(u(64)), int32(width - margin), int32(height - u(306))}
	contentTop := int(list.Bottom) + u(16)
	colW := width - 2*margin - side - u(190) - 2*gap
	if colW < u(280) {
		colW = u(280)
	}
	modeX := margin + colW + gap
	actionX := width - margin - side
	name := rect{int32(margin), int32(contentTop + u(27)), int32(margin + colW), int32(contentTop + u(197))}
	mode := rect{int32(modeX), int32(contentTop + u(27)), int32(modeX + u(176)), int32(contentTop + u(197))}
	value := rect{int32(margin), int32(contentTop + u(94)), int32(actionX - gap), int32(contentTop + u(127))}
	hint := rect{int32(margin), int32(contentTop + u(142)), int32(width - margin), int32(contentTop + u(174))}
	buttonsY := height - u(62)
	return attributeGeometry{list, name, mode, value, hint,
		rect{int32(width - margin - u(382)), int32(buttonsY), int32(width - margin - u(198)), int32(buttonsY + u(38))},
		rect{int32(width - margin - u(190)), int32(buttonsY), int32(width - margin), int32(buttonsY + u(38))},
		rect{int32(actionX), int32(contentTop + u(27)), int32(width - margin), int32(contentTop + u(65))},
		rect{int32(actionX), int32(contentTop + u(94)), int32(width - margin), int32(contentTop + u(132))},
		rect{int32(margin), int32(u(19)), int32(width - margin), int32(u(49))},
		rect{int32(margin), int32(contentTop), int32(margin + colW), int32(contentTop + u(27))},
		rect{int32(modeX), int32(contentTop), int32(actionX - gap), int32(contentTop + u(27))},
		rect{int32(margin), int32(contentTop + u(67)), int32(actionX - gap), int32(contentTop + u(94))}}
}
func resizeAttributeEditor() {
	if attributeWindow == 0 {
		return
	}
	var r rect
	up("GetClientRect").Call(attributeWindow, uintptr(unsafe.Pointer(&r)))
	if r.Right <= 0 || r.Bottom <= 0 {
		return
	}
	g := attributeLayout(int(r.Right), int(r.Bottom))
	for _, item := range []struct {
		h uintptr
		r rect
	}{{attributeList, g.list}, {attributeName, g.name}, {attributeMode, g.mode}, {attributeValue, g.value}, {attributeHint, g.hint}, {attributeApplyButton, g.apply}, {attributeCloseButton, g.cancel}, {attributeAddButton, g.add}, {attributeRemoveButton, g.remove}, {attributeTitle, g.title}, {attributeNameLabel, g.nameLabel}, {attributeModeLabel, g.modeLabel}, {attributeValueLabel, g.valueLabel}} {
		moveRect(item.h, item.r)
	}
	invalidate.Call(attributeWindow, 0, 1)
}

func preferredAttributeIndex(options []protocol.AttributeOption) int {
	for i, option := range options {
		if option.Name == "NAS-IP-Address" && option.Supported {
			return i
		}
	}
	for i, option := range options {
		if option.Supported {
			return i
		}
	}
	return -1
}
func attributeOptionLabel(o protocol.AttributeOption) string {
	if !o.Supported {
		return o.Name + " (unavailable)"
	}
	return o.Name
}

var attributeComboOptions = map[uintptr][]string{}
var attributeButtons = map[uintptr]int{}

func editorControl(class, title string, style uintptr, x, y, w, h int) uintptr {
	handle, _, _ := create.Call(0, ptr(class), ptr(title), style|WS_CHILD|WS_VISIBLE, uintptr(scale(x)), uintptr(scale(y)), uintptr(scale(w)), uintptr(scale(h)), attributeWindow, 0, 0, 0)
	send.Call(handle, WM_SETFONT, fonts[0], 1)
	return handle
}
func editorButton(title string, id int, x, y, w int) uintptr {
	h := editorControl("BUTTON", title, WS_TABSTOP|BS_OWNERDRAW, x, y, w, 32)
	buttons[h] = id
	attributeButtons[h] = id
	up("SetWindowLongPtrW").Call(h, ^uintptr(11), uintptr(id))
	return h
}
func editorCombo(options []string, x, y, w int) uintptr {
	h := editorControl("COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST|CBS_OWNERDRAWFIXED|CBS_HASSTRINGS, x, y, w, 175)
	attributeComboOptions[h] = options
	for _, s := range options {
		send.Call(h, CB_ADDSTRING, 0, ptr(s))
	}
	send.Call(h, CB_SETCURSEL, 0, 0)
	return h
}
func editorSelection(h uintptr) int {
	n, _, _ := send.Call(h, CB_GETCURSEL, 0, 0)
	if int32(n) < 0 {
		return -1
	}
	return int(n)
}
func editorStatus(s string) { setText.Call(attributeHint, ptr(s)) }
func resetEditorList(selectIndex int) {
	send.Call(attributeList, LB_RESETCONTENT, 0, 0)
	for _, row := range attributeRows {
		send.Call(attributeList, LB_ADDSTRING, 0, ptr(row.Name+"  =  "+row.Expression))
	}
	if selectIndex >= 0 && selectIndex < len(attributeRows) {
		send.Call(attributeList, LB_SETCURSEL, uintptr(selectIndex), 0)
	}
}
func boolPtr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
func editorModes() {
	i := editorSelection(attributeName)
	if i < 0 || i >= len(attributeNames) {
		return
	}
	option := standardAttributeOptions[i]
	up("EnableWindow").Call(attributeAddButton, boolPtr(option.Supported))
	if !option.Supported {
		attributeComboOptions[attributeMode] = []string{"Unavailable"}
		send.Call(attributeMode, CB_RESETCONTENT, 0, 0)
		send.Call(attributeMode, CB_ADDSTRING, 0, ptr("Unavailable"))
		send.Call(attributeMode, CB_SETCURSEL, 0, 0)
		editorStatus(option.Reason)
		return
	}
	kind := option.Kind
	modes := []string{"Static"}
	hint := "Enter a value"
	switch kind {
	case "text", "string":
		modes = append(modes, "Random length")
		hint = "Text: static value or random length 1..253"
	case "integer", "integer64", "enum", "time":
		modes = append(modes, "Random range")
		hint = "Number: static unsigned value or random min,max"
	case "ipv4addr", "ipv6addr":
		hint = "IP address: static value only"
	}
	attributeComboOptions[attributeMode] = modes
	send.Call(attributeMode, CB_RESETCONTENT, 0, 0)
	for _, mode := range modes {
		send.Call(attributeMode, CB_ADDSTRING, 0, ptr(mode))
	}
	send.Call(attributeMode, CB_SETCURSEL, 0, 0)
	editorStatus(hint)
}
func editorLoadRow() {
	index, _, _ := send.Call(attributeList, LB_GETCURSEL, 0, 0)
	if int32(index) < 0 || int(index) >= len(attributeRows) {
		return
	}
	row := attributeRows[index]
	for i, name := range attributeNames {
		if row.Name == name {
			send.Call(attributeName, CB_SETCURSEL, uintptr(i), 0)
			break
		}
	}
	editorModes()
	value := row.Expression
	if strings.HasPrefix(value, "random(") && strings.HasSuffix(value, ")") {
		value = value[len("random(") : len(value)-1]
		send.Call(attributeMode, CB_SETCURSEL, 1, 0)
	}
	setText.Call(attributeValue, ptr(value))
}
func editorExtraForClose(current string, rows []attributeRow, commit bool) (string, error) {
	return profileExtraForSave(current, rows, commit)
}
func commitAttributeEditor() {
	extra, err := editorExtraForClose(text(fields["extra"]), attributeRows, true)
	if err != nil {
		editorStatus("Invalid attributes: " + err.Error())
		return
	}
	setText.Call(fields["extra"], ptr(extra))
	closeAttributeEditor()
}
func editorSaveRow() {
	index := editorSelection(attributeName)
	modeIndex := editorSelection(attributeMode)
	if index < 0 || index >= len(attributeNames) || modeIndex < 0 || modeIndex >= len(attributeComboOptions[attributeMode]) {
		editorStatus("Select an attribute and value mode")
		return
	}
	if !standardAttributeOptions[index].Supported {
		editorStatus(standardAttributeOptions[index].Reason)
		return
	}
	row, err := makeAttributeRow(attributeNames[index], attributeComboOptions[attributeMode][modeIndex], text(attributeValue))
	if err != nil {
		editorStatus("Invalid value: " + err.Error())
		return
	}
	selected, _, _ := send.Call(attributeList, LB_GETCURSEL, 0, 0)
	if int32(selected) >= 0 && int(selected) < len(attributeRows) {
		attributeRows[selected] = row
		resetEditorList(int(selected))
	} else {
		attributeRows = append(attributeRows, row)
		resetEditorList(len(attributeRows) - 1)
	}
	editorStatus("Row saved. Apply to export expressions to Extra.")
}
func closeAttributeEditor() {
	if attributeWindow != 0 {
		up("DestroyWindow").Call(attributeWindow)
	}
}
func attributeWndproc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case WM_COMMAND:
		notification := w >> 16
		if l == attributeName && notification == CBN_SELCHANGE {
			editorModes()
			return 0
		}
		if l == attributeList && notification == LBN_SELCHANGE {
			editorLoadRow()
			return 0
		}
		switch int(w & 0xffff) {
		case attributeAddID:
			editorSaveRow()
			return 0
		case attributeRemoveID:
			n, _, _ := send.Call(attributeList, LB_GETCURSEL, 0, 0)
			if int32(n) >= 0 && int(n) < len(attributeRows) {
				attributeRows = append(attributeRows[:n], attributeRows[n+1:]...)
				resetEditorList(-1)
				editorStatus("Row removed; Apply to export.")
			}
			return 0
		case attributeApplyID:
			commitAttributeEditor()
			return 0
		case attributeCloseID:
			closeAttributeEditor()
			return 0
		}
	case WM_SIZE:
		resizeAttributeEditor()
		return 0
	case WM_GETMINMAXINFO:
		min := (*minMax)(unsafe.Pointer(l))
		min.MinTrack = point{int32(scale(870)), int32(scale(670))}
		return 0
	case WM_DRAWITEM:
		drawControl((*drawItem)(unsafe.Pointer(l)))
		return 1
	case WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX:
		gp("SetTextColor").Call(w, ink)
		gp("SetBkColor").Call(w, panel)
		return brush(panel)
	case WM_ERASEBKGND:
		return 1
	case WM_PAINT:
		var ps paintStruct
		dc, _, _ := up("BeginPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
		var client rect
		up("GetClientRect").Call(h, uintptr(unsafe.Pointer(&client)))
		fill(dc, rect{0, 0, client.Right, client.Bottom}, canvas)
		up("EndPaint").Call(h, uintptr(unsafe.Pointer(&ps)))
		return 0
	case WM_CLOSE:
		commitAttributeEditor()
		return 0
	case WM_DESTROY:
		for handle := range attributeButtons {
			delete(buttons, handle)
		}
		attributeButtons = map[uintptr]int{}
		for handle := range attributeComboOptions {
			delete(attributeComboOptions, handle)
		}
		attributeWindow = 0
		return 0
	}
	result, _, _ := up("DefWindowProcW").Call(h, uintptr(m), w, l)
	return result
}
func openAttributeEditor() {
	if attributeWindow != 0 {
		up("SetForegroundWindow").Call(attributeWindow)
		return
	}
	rows, err := parseAttributeRows(val("extra"))
	if err != nil {
		appendLog(eventError, "Cannot open attribute editor: Extra contains an invalid or unsupported attribute; edit Extra manually first")
		return
	}
	attributeRows = rows
	class := syscall.StringToUTF16Ptr("RadSecAttributeEditor")
	instance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: syscall.NewCallback(attributeWndproc), Instance: instance, Name: uintptr(unsafe.Pointer(class)), Background: brush(canvas)}
	reg.Call(uintptr(unsafe.Pointer(&wc)))
	attributeWindow, _, _ = create.Call(0, uintptr(unsafe.Pointer(class)), ptr("Advanced RADIUS attributes"), WS_OVERLAPPEDWINDOW, uintptr(centerChildX(hwnd, scale(attributeWindowWidth))), uintptr(centerChildY(hwnd, scale(attributeWindowHeight))), uintptr(scale(attributeWindowWidth)), uintptr(scale(attributeWindowHeight)), hwnd, 0, instance, 0)
	if attributeWindow == 0 {
		appendLog(eventError, "Cannot open attribute editor window")
		return
	}
	attributeTitle = editorControl("STATIC", "STANDARD ATTRIBUTES  ·  Edit a row, then Apply to Extra", 0, 0, 0, 10, 10)
	attributeList = editorControl("LISTBOX", "", WS_TABSTOP|WS_VSCROLL|0x1|0x00800000, 0, 0, 10, 10)
	attributeNameLabel = editorControl("STATIC", "Attribute", 0, 0, 0, 10, 10)
	attributeModeLabel = editorControl("STATIC", "Value mode", 0, 0, 0, 10, 10)
	attributeNames = nil
	standardAttributeOptions = protocol.StandardAttributes()
	labels := make([]string, 0, len(standardAttributeOptions))
	for _, option := range standardAttributeOptions {
		attributeNames = append(attributeNames, option.Name)
		labels = append(labels, attributeOptionLabel(option))
	}
	attributeName = editorCombo(labels, 0, 0, 10)
	if index := preferredAttributeIndex(standardAttributeOptions); index >= 0 {
		send.Call(attributeName, CB_SETCURSEL, uintptr(index), 0)
	}
	attributeMode = editorCombo([]string{"Static"}, 0, 0, 10)
	attributeValueLabel = editorControl("STATIC", "Value / random length / min,max", 0, 0, 0, 10, 10)
	attributeValue = editorControl("EDIT", "", WS_TABSTOP|ES_AUTOHSCROLL|0x00800000, 0, 0, 10, 10)
	attributeAddButton = editorButton("Add / update", attributeAddID, 0, 0, 10)
	attributeRemoveButton = editorButton("Remove selected", attributeRemoveID, 0, 0, 10)
	attributeHint = editorControl("STATIC", "", 0, 0, 0, 10, 10)
	attributeApplyButton = editorButton("Apply to Extra", attributeApplyID, 0, 0, 10)
	attributeCloseButton = editorButton("Cancel", attributeCloseID, 0, 0, 10)
	resizeAttributeEditor()
	resetEditorList(-1)
	editorModes()
	show.Call(attributeWindow, SW_SHOW)
	up("UpdateWindow").Call(attributeWindow)
}

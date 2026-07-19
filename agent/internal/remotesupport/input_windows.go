//go:build windows

package remotesupport

import (
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsInputSink applies remote-control input on Windows via the Win32
// SendInput / SetCursorPos APIs. It only acts while control is active (the
// admin's control_state gate), scaling the admin's 0..1000 normalized
// coordinates to the primary display's real pixel size.
type windowsInputSink struct {
	controlActive atomic.Bool
	screenW       int32
	screenH       int32

	user32       *windows.LazyDLL
	pSendInput   *windows.LazyProc
	pSetCursor   *windows.LazyProc
	pGetSystemM  *windows.LazyProc
}

// NewWindowsInputSink builds the OS input injector. It is wired into the agent
// on Windows so remote control actually moves the mouse / types.
func NewWindowsInputSink() InputSink {
	u := windows.NewLazySystemDLL("user32.dll")
	s := &windowsInputSink{
		user32:      u,
		pSendInput:  u.NewProc("SendInput"),
		pSetCursor:  u.NewProc("SetCursorPos"),
		pGetSystemM: u.NewProc("GetSystemMetrics"),
	}
	s.screenW = int32(s.metric(0)) // SM_CXSCREEN
	s.screenH = int32(s.metric(1)) // SM_CYSCREEN
	if s.screenW == 0 {
		s.screenW = 1920
	}
	if s.screenH == 0 {
		s.screenH = 1080
	}
	return s
}

func (s *windowsInputSink) metric(idx int) int {
	r, _, _ := s.pGetSystemM.Call(uintptr(idx))
	return int(r)
}

func (s *windowsInputSink) SetControlActive(active bool) { s.controlActive.Store(active) }

func (s *windowsInputSink) Apply(ev InputEvent) {
	if !s.controlActive.Load() {
		return // admin does not currently hold control
	}
	switch ev.Event {
	case "tap":
		s.moveTo(ev.X, ev.Y)
		s.click()
	case "swipe":
		s.moveTo(ev.X, ev.Y)
		s.mouseDown()
		steps := 10
		for i := 1; i <= steps; i++ {
			t := float64(i) / float64(steps)
			s.moveTo(ev.X+(ev.X2-ev.X)*t, ev.Y+(ev.Y2-ev.Y)*t)
			time.Sleep(10 * time.Millisecond)
		}
		s.mouseUp()
	case "text":
		s.typeText(ev.Text)
	case "clipboard":
		s.typeText(ev.Text)
	case "key":
		s.pressKey(ev)
	case "global_action":
		s.globalAction(ev.Action)
	}
}

// moveTo scales 0..1000 normalized coords to screen pixels and positions the
// cursor.
func (s *windowsInputSink) moveTo(x, y float64) {
	px := int32(x / 1000.0 * float64(s.screenW))
	py := int32(y / 1000.0 * float64(s.screenH))
	if px < 0 {
		px = 0
	}
	if py < 0 {
		py = 0
	}
	s.pSetCursor.Call(uintptr(px), uintptr(py))
}

// --- SendInput plumbing -----------------------------------------------------

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseEventLeftDown = 0x0002
	mouseEventLeftUp   = 0x0004

	keyEventKeyUp   = 0x0002
	keyEventUnicode = 0x0004
)

// mouseInput / keybdInput mirror the Win32 INPUT union (mouse/keyboard). The
// union is 32 bytes on amd64; we allocate the larger and cast.
type inputUnion struct {
	typ uint32
	_   uint32 // padding to align the union on 8 bytes (amd64)
	mi  mouseInput
}

type mouseInput struct {
	dx, dy      int32
	mouseData   uint32
	dwFlags     uint32
	time        uint32
	dwExtraInfo uintptr
}

type keybdInputRec struct {
	typ uint32
	_   uint32
	wVk         uint16
	wScan       uint16
	dwFlags     uint32
	time        uint32
	dwExtraInfo uintptr
	_pad        [8]byte
}

func (s *windowsInputSink) sendMouse(flags uint32) {
	in := inputUnion{typ: inputMouse}
	in.mi.dwFlags = flags
	s.pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
}

func (s *windowsInputSink) mouseDown() { s.sendMouse(mouseEventLeftDown) }
func (s *windowsInputSink) mouseUp()   { s.sendMouse(mouseEventLeftUp) }
func (s *windowsInputSink) click() {
	s.mouseDown()
	time.Sleep(20 * time.Millisecond)
	s.mouseUp()
}

// typeText sends each rune as a Unicode key event (works regardless of layout).
func (s *windowsInputSink) typeText(text string) {
	for _, r := range text {
		for _, u := range utf16.Encode([]rune{r}) {
			s.sendUnicode(u, false)
			s.sendUnicode(u, true)
		}
	}
}

func (s *windowsInputSink) sendUnicode(scan uint16, keyUp bool) {
	rec := keybdInputRec{typ: inputKeyboard, wScan: scan, dwFlags: keyEventUnicode}
	if keyUp {
		rec.dwFlags |= keyEventKeyUp
	}
	s.pSendInput.Call(1, uintptr(unsafe.Pointer(&rec)), unsafe.Sizeof(inputUnion{}))
}

// pressKey handles named editing/navigation keys via their virtual-key code.
func (s *windowsInputSink) pressKey(ev InputEvent) {
	vk := vkForKeyName(ev.KeyName)
	if vk == 0 {
		return
	}
	s.sendVK(vk, false)
	s.sendVK(vk, true)
}

func (s *windowsInputSink) sendVK(vk uint16, keyUp bool) {
	rec := keybdInputRec{typ: inputKeyboard, wVk: vk}
	if keyUp {
		rec.dwFlags |= keyEventKeyUp
	}
	s.pSendInput.Call(1, uintptr(unsafe.Pointer(&rec)), unsafe.Sizeof(inputUnion{}))
}

// globalAction maps the admin's Android-style actions to sensible desktop keys.
func (s *windowsInputSink) globalAction(action string) {
	switch strings.ToLower(action) {
	case "back":
		s.sendVK(0x1B, false) // VK_ESCAPE
		s.sendVK(0x1B, true)
	case "home":
		s.sendVK(0x5B, false) // VK_LWIN
		s.sendVK(0x5B, true)
	case "recents":
		// Win+Tab (task view). LWIN down, TAB, LWIN up.
		s.sendVK(0x5B, false)
		s.sendVK(0x09, false)
		s.sendVK(0x09, true)
		s.sendVK(0x5B, true)
	}
}

// vkForKeyName maps the admin viewer's key_name to a Windows virtual-key code.
func vkForKeyName(name string) uint16 {
	switch strings.ToLower(name) {
	case "enter", "return":
		return 0x0D
	case "backspace":
		return 0x08
	case "tab":
		return 0x09
	case "delete", "del":
		return 0x2E
	case "escape", "esc":
		return 0x1B
	case "up":
		return 0x26
	case "down":
		return 0x28
	case "left":
		return 0x25
	case "right":
		return 0x27
	case "home":
		return 0x24
	case "end":
		return 0x23
	case "pageup":
		return 0x21
	case "pagedown":
		return 0x22
	}
	return 0
}

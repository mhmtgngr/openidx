//go:build windows

package remotesupport

import (
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/kbinani/screenshot"
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
	originX       int32 // top-left of the captured display (multi-monitor)
	originY       int32
	// Virtual-desktop extent (bounding box of all monitors), for absolute
	// SendInput coordinates (0..65535) that are DPI-independent.
	virtLeft   int32
	virtTop    int32
	virtWidth  int32
	virtHeight int32

	user32      *windows.LazyDLL
	pSendInput  *windows.LazyProc
	pSetCursor  *windows.LazyProc
	pGetSystemM *windows.LazyProc
}

// NewWindowsInputSink builds the OS input injector. It is wired into the agent
// on Windows so remote control actually moves the mouse / types.
func NewWindowsInputSink() InputSink {
	// Make the process per-monitor DPI aware so GetDisplayBounds / capture and
	// input coordinates all speak PHYSICAL pixels. Without this, a scaled
	// display (e.g. 150%) reports logical pixels and injected clicks drift from
	// where the admin aims. Best-effort: ignore failures on older Windows.
	setProcessDPIAware()

	u := windows.NewLazySystemDLL("user32.dll")
	s := &windowsInputSink{
		user32:      u,
		pSendInput:  u.NewProc("SendInput"),
		pSetCursor:  u.NewProc("SetCursorPos"),
		pGetSystemM: u.NewProc("GetSystemMetrics"),
	}
	// Match the captured display (kbinani/screenshot GetDisplayBounds(0)) so
	// normalized click coordinates map to the SAME rectangle the admin sees.
	// On a single monitor this equals the primary metrics; on multi-monitor it
	// carries the display's origin offset so clicks don't land on the wrong
	// screen. Falls back to SM_CXSCREEN/SM_CYSCREEN if bounds are unavailable.
	if b := screenshot.GetDisplayBounds(0); b.Dx() > 0 && b.Dy() > 0 {
		s.screenW = int32(b.Dx())
		s.screenH = int32(b.Dy())
		s.originX = int32(b.Min.X)
		s.originY = int32(b.Min.Y)
	} else {
		s.screenW = int32(s.metric(0)) // SM_CXSCREEN
		s.screenH = int32(s.metric(1)) // SM_CYSCREEN
	}
	if s.screenW == 0 {
		s.screenW = 1920
	}
	if s.screenH == 0 {
		s.screenH = 1080
	}
	// Virtual-desktop bounding box (all monitors): SM_XVIRTUALSCREEN=76,
	// SM_YVIRTUALSCREEN=77, SM_CXVIRTUALSCREEN=78, SM_CYVIRTUALSCREEN=79.
	s.virtLeft = int32(s.metric(76))
	s.virtTop = int32(s.metric(77))
	s.virtWidth = int32(s.metric(78))
	s.virtHeight = int32(s.metric(79))
	return s
}

// setProcessDPIAware marks the process per-monitor DPI aware (best effort).
func setProcessDPIAware() {
	// Prefer the modern per-monitor-v2 context; fall back to the legacy call.
	if u := windows.NewLazySystemDLL("user32.dll"); u != nil {
		if p := u.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
			// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (HANDLE)-4
			if r, _, _ := p.Call(uintptr(^uintptr(3))); r != 0 {
				return
			}
		}
		if p := u.NewProc("SetProcessDPIAware"); p.Find() == nil {
			p.Call()
		}
	}
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

// moveTo positions the cursor from 0..1000 normalized coordinates (relative to
// the captured display) using SendInput with ABSOLUTE + VIRTUALDESK flags. The
// absolute range is a fixed 0..65535 mapped across the whole virtual desktop by
// Windows regardless of per-monitor DPI scaling — so this lands accurately even
// when the process/display is DPI-scaled (SetCursorPos took logical pixels,
// which drifted on scaled displays). We convert the captured-display pixel
// target into virtual-desktop-normalized coordinates.
func (s *windowsInputSink) moveTo(x, y float64) {
	// Target pixel on the captured display (its own origin + scaled offset).
	px := float64(s.originX) + x/1000.0*float64(s.screenW)
	py := float64(s.originY) + y/1000.0*float64(s.screenH)

	// Virtual desktop extent (all monitors). Fall back to the captured display.
	vx, vy := float64(s.virtLeft), float64(s.virtTop)
	vw, vh := float64(s.virtWidth), float64(s.virtHeight)
	if vw <= 0 || vh <= 0 {
		vx, vy, vw, vh = float64(s.originX), float64(s.originY), float64(s.screenW), float64(s.screenH)
	}

	// Normalize to 0..65535 across the virtual desktop.
	nx := (px - vx) / vw * 65535.0
	ny := (py - vy) / vh * 65535.0
	clamp := func(v float64) int32 {
		if v < 0 {
			return 0
		}
		if v > 65535 {
			return 65535
		}
		return int32(v)
	}

	in := inputUnion{typ: inputMouse}
	in.mi.dx = clamp(nx)
	in.mi.dy = clamp(ny)
	in.mi.dwFlags = mouseEventMove | mouseEventAbsolute | mouseEventVirtualDesk
	s.pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
}

// --- SendInput plumbing -----------------------------------------------------

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseEventLeftDown    = 0x0002
	mouseEventLeftUp      = 0x0004
	mouseEventMove        = 0x0001
	mouseEventAbsolute    = 0x8000
	mouseEventVirtualDesk = 0x4000

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
	typ         uint32
	_           uint32
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

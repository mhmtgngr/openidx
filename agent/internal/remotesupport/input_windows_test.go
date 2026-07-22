//go:build windows

package remotesupport

import (
	"testing"
	"unsafe"
)

// The Win32 INPUT struct is exactly 40 bytes on amd64 (4 type + 4 pad + 32
// union). If either struct drifts from 40, SendInput silently no-ops, so guard
// the layout at build time.
func TestSendInputStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(inputUnion{}); got != 40 {
		t.Errorf("inputUnion size = %d, want 40 (Win32 INPUT on amd64)", got)
	}
	if got := unsafe.Sizeof(keybdInputRec{}); got != 40 {
		t.Errorf("keybdInputRec size = %d, want 40", got)
	}
}

func TestVKForKeyName(t *testing.T) {
	cases := map[string]uint16{"enter": 0x0D, "ESC": 0x1B, "up": 0x26, "unknown": 0}
	for name, want := range cases {
		if got := vkForKeyName(name); got != want {
			t.Errorf("vkForKeyName(%q) = %#x, want %#x", name, got, want)
		}
	}
}

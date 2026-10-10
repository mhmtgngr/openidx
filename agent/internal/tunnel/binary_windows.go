//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// wintunDLL is the driver DLL ziti-edge-tunnel loads from its own folder. It
// is held and checked like the binary: a DLL planted beside the tunneler
// would run as SYSTEM inside it.
const wintunDLL = "wintun.dll"

// volumeNameDOS is VOLUME_NAME_DOS (0), which x/sys/windows does not name.
const volumeNameDOS = 0x0

// openBinary opens the tunneler and wintun.dll beside it WITHOUT
// FILE_SHARE_WRITE or FILE_SHARE_DELETE, so while the supervisor holds them
// nobody can write, delete or rename either file (nor, therefore, rename a
// folder above them out from under the path). Only then are they checked: no
// reparse point, the handle's final path is the path that was checked, and
// verifyBinary's owner/DACL check passes for each and every folder up to
// Program Files. The checked path is executed; it cannot be changed while the
// handles are held. The handles are kept for as long as the supervisor uses
// this binary, which is the life of every child it starts from it.
func openBinary(path string) (*heldBinary, error) {
	real, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	exe, err := openLocked(real)
	if err != nil {
		return nil, err
	}
	h := &heldBinary{path: real, execPath: real, file: exe}
	dll, err := openLocked(filepath.Join(filepath.Dir(real), wintunDLL))
	if err != nil {
		h.close()
		return nil, fmt.Errorf("%w (the tunneler needs %s beside it, and a missing one could be "+
			"loaded from a less protected folder)", err, wintunDLL)
	}
	h.extra = append(h.extra, dll)
	for _, f := range append([]*os.File{exe}, h.extra...) {
		if err := verifyBinary(f.Name()); err != nil {
			h.close()
			return nil, err
		}
	}
	return finishOpen(h)
}

// openLocked opens path for reading, sharing read access only, refuses a
// reparse point or a non-file, and checks that the handle's final path is
// path.
func openLocked(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	hdl, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %v", ErrUntrustedBinary, path, err)
	}
	f := os.NewFile(uintptr(hdl), path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(hdl, &info); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s is a link or a directory", ErrUntrustedBinary, path)
	}
	final, err := finalPath(hdl)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	if !strings.EqualFold(final, filepath.Clean(path)) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s resolves to %s", ErrUntrustedBinary, path, final)
	}
	return f, nil
}

// finalPath is the handle's path with the \\?\ prefix removed.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
	if err != nil {
		return "", err
	}
	if int(n) > len(buf) {
		return "", fmt.Errorf("final path too long")
	}
	s := windows.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(s, `\\?\UNC\`):
		s = `\\` + s[len(`\\?\UNC\`):]
	case strings.HasPrefix(s, `\\?\`):
		s = s[len(`\\?\`):]
	}
	return s, nil
}

// stillCurrent is true while the handles are held: the files cannot change.
func (h *heldBinary) stillCurrent() bool { return true }

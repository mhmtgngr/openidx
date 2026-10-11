//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// wintunDLL is the driver DLL ziti-edge-tunnel loads from its own folder. It
// is held and checked like the binary: a DLL planted beside the tunneler
// would run as SYSTEM inside it.
const wintunDLL = "wintun.dll"

// openBinary opens the tunneler and wintun.dll beside it WITHOUT
// FILE_SHARE_WRITE or FILE_SHARE_DELETE, so while the supervisor holds them
// nobody can write, delete or rename either file (nor, therefore, rename a
// folder above them out from under the path). Only then are they checked: no
// reparse point, the checked path still names the held file (volume serial and
// file index, compared through a second open), and
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
// reparse point or a non-file, and checks that path names the held file.
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
	// The path CreateProcess will open must name the file this handle holds.
	// That is a question of file identity, not of spelling: the same file is
	// reached through 8.3 short names (C:\Users\RUNNER~1), other letter case
	// or a mount point, and comparing path strings refused a path that was
	// the held file. So the path is opened again, the way the loader opens it
	// (following any links), and the two handles' volume serial number and
	// file index are compared.
	if err := sameFile(info, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// sameFile opens path afresh with no data access and reports an error unless
// it is the file whose information is held.
func sameFile(held windows.ByHandleFileInformation, path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("%w: reopening %s: %v", ErrUntrustedBinary, path, err)
	}
	defer windows.CloseHandle(h)
	var now windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &now); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	if now.VolumeSerialNumber != held.VolumeSerialNumber ||
		now.FileIndexHigh != held.FileIndexHigh || now.FileIndexLow != held.FileIndexLow {
		return fmt.Errorf("%w: %s does not name the file that was opened and checked", ErrUntrustedBinary, path)
	}
	return nil
}

// stillCurrent is true while the handles are held: the files cannot change.
func (h *heldBinary) stillCurrent() bool { return true }

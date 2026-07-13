//go:build !windows

package ipc

import (
	"context"
	"errors"
)

// ErrWindowsOnly is returned by the IPC transport on non-Windows platforms.
var ErrWindowsOnly = errors.New("service/tray IPC is only supported on Windows")

// Serve is a no-op stub on non-Windows platforms.
func Serve(_ context.Context, _ func() Status) error { return ErrWindowsOnly }

// Query is a no-op stub on non-Windows platforms.
func Query() (*Status, error) { return nil, ErrWindowsOnly }

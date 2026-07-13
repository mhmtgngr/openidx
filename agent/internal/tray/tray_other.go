//go:build !windows

// Package tray: non-Windows stub. The tray UI is Windows-only for now.
package tray

import (
	"errors"

	"go.uber.org/zap"
)

// ErrWindowsOnly is returned on non-Windows platforms.
var ErrWindowsOnly = errors.New("the tray app is only supported on Windows")

// Run is a no-op stub on non-Windows platforms.
func Run(_ *zap.Logger, _ string, _ string) error { return ErrWindowsOnly }

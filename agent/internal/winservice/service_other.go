//go:build !windows

// Package winservice: non-Windows stubs so the `service` subcommand compiles
// everywhere but only functions on Windows.
package winservice

import (
	"errors"

	"go.uber.org/zap"
)

// ErrWindowsOnly is returned by every entry point on non-Windows platforms.
var ErrWindowsOnly = errors.New("the Windows service is only supported on Windows")

const (
	ServiceName = "OpenIDXAgent"
	DisplayName = "OpenIDX Agent"
)

func IsWindowsService() (bool, error)      { return false, nil }
func Run(_ *zap.Logger, _, _ string) error { return ErrWindowsOnly }
func Install(_ string, _ string) error     { return ErrWindowsOnly }
func Uninstall() error                     { return ErrWindowsOnly }

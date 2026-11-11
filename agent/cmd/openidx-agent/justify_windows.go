//go:build windows

package main

import (
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/tray"
)

// runJustifyLink serves openidx://justify in the user's own process.
func runJustifyLink(link string) {
	tray.RunJustifyLink(zap.NewNop(), defaultConfigDir(), "", link)
}

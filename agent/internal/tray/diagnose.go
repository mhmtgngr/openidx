package tray

import (
	"context"
	"strings"
	"time"

	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
)

// diagnoseBudget bounds the check behind the "Why can't I connect?" item.
const diagnoseBudget = 40 * time.Second

// trayLang is the doctor's language for the tray's own.
func trayLang() doctor.Lang {
	if T == &trStrings {
		return doctor.LangTR
	}
	return doctor.LangEN
}

// diagnosis runs the doctor and words the result for a dialog. The tray is
// not elevated, so it never repairs: it says what is wrong, what to do, and
// gives the support code to read to IT.
func diagnosis(ctx context.Context, d collect.Deps, configDir string) (text string, healthy bool) {
	ctx, cancel := context.WithTimeout(ctx, diagnoseBudget)
	defer cancel()
	b := collect.Run(ctx, d, configDir, Version, false)
	var sb strings.Builder
	doctor.Summary(&sb, b, trayLang())
	return strings.TrimSpace(sb.String()), b.Healthy()
}

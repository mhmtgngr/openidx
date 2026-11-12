//go:build !windows

package main

import (
	"fmt"
	"os"
)

// runJustifyLink: the written-justification prompt is the Windows tray's;
// elsewhere the reason is given in the portal.
func runJustifyLink(string) {
	fmt.Fprintln(os.Stderr, "openidx://justify is handled by the Windows tray; give your reason in the OpenIDX portal.")
}

//go:build !windows

package main

import (
	"fmt"
	"os"
)

// elevateForDeepLink never hands off outside Windows: a link is enrolled in
// this process, with whatever rights it has.
func elevateForDeepLink(string) (bool, error) { return false, nil }

// notifyDeepLink prints the outcome: there is a terminal, or a log, to read.
func notifyDeepLink(msg string) { fmt.Fprintln(os.Stderr, msg) }

//go:build !windows

package tunnel

import "errors"

// ErrNamesUnsupported is what a platform without a name-resolution hook says.
var ErrNamesUnsupported = errors.New("name resolution by the agent is implemented for Windows only")

type unsupportedRules struct{}

func newNameRules() nameRules { return unsupportedRules{} }

func (unsupportedRules) Supported() error             { return ErrNamesUnsupported }
func (unsupportedRules) Apply([]string, string) error { return ErrNamesUnsupported }
func (unsupportedRules) Clear(restore []string) error { return nil }

//go:build !linux && !windows

package doctor

import "context"

type osActions struct{}

func (osActions) FlushDNS(context.Context) error       { return ErrUnsupported }
func (osActions) RestartService(context.Context) error { return ErrUnsupported }

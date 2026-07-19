//go:build !windows

package remotesupport

// NewWindowsInputSink returns nil off Windows: there is no OS input injector,
// so remote-support sessions on non-Windows agents are view-only (the peer
// still negotiates and streams; input is simply not applied). The agent falls
// back to the no-op sink when this is nil.
func NewWindowsInputSink() InputSink { return nil }

package credentials

import "context"

// generateOnlyRotator rotates the vault value but applies nothing to a target — for
// secrets consumed somewhere the engine can't reach (e.g. a shared API key). The engine
// promotes immediately and fires an "apply manually" notification.
type generateOnlyRotator struct{}

// NewGenerateOnlyRotator returns a Rotator that generates a new credential value and
// promotes it in the vault without pushing the change to any target system.
// Exported so cmd/admin-api can construct the rotator slice without importing the
// unexported type directly.
func NewGenerateOnlyRotator() Rotator { return generateOnlyRotator{} }

func (generateOnlyRotator) Type() string { return "generate_only" }
func (generateOnlyRotator) Apply(_ context.Context, _ map[string]any, _ []byte) error {
	return nil
}
func (generateOnlyRotator) Verify(_ context.Context, _ map[string]any, _ []byte) error {
	return ErrVerifyUnsupported
}

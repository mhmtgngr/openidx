package credentials

import "context"

// generateOnlyRotator rotates the vault value but applies nothing to a target — for
// secrets consumed somewhere the engine can't reach (e.g. a shared API key). The engine
// promotes immediately and fires an "apply manually" notification.
type generateOnlyRotator struct{}

func (generateOnlyRotator) Type() string { return "generate_only" }
func (generateOnlyRotator) Apply(_ context.Context, _ map[string]any, _ []byte) error {
	return nil
}
func (generateOnlyRotator) Verify(_ context.Context, _ map[string]any, _ []byte) error {
	return ErrVerifyUnsupported
}

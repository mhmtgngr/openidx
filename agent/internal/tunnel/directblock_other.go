//go:build !linux

package tunnel

import (
	"fmt"
	"runtime"
)

// DirectBlockSupport: no firewall hook on this platform yet (directblock.go
// says what each would need). The agent reports the gap.
func DirectBlockSupport() error {
	return fmt.Errorf("%w: no firewall hook on %s yet", ErrDirectBlockUnsupported, runtime.GOOS)
}

func runNft(string) error { return DirectBlockSupport() }

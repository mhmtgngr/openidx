//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// nftCandidates are where nft is looked for. PATH is never searched, for the
// reason the tunneler's binary is not (locate.go): this runs as root.
var nftCandidates = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"}

// findNft returns the first nft that exists and passes the trust check the
// tunneler binary passes (root-owned, not group/other-writable, all the way
// up).
func findNft() (string, error) {
	for _, p := range nftCandidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := verifyTrustedBinary(p, ""); err != nil {
			return "", err
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: nft (nftables) is not installed in %s", ErrDirectBlockUnsupported,
		strings.Join(nftCandidates, ", "))
}

// DirectBlockSupport says whether this process can install the block: it
// needs root and nft.
func DirectBlockSupport() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: the agent does not run as root (CAP_NET_ADMIN is needed to load an nftables table)",
			ErrDirectBlockUnsupported)
	}
	_, err := findNft()
	return err
}

// runNft loads script with `nft -f -`.
func runNft(script string) error {
	nft, err := findNft()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nft, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

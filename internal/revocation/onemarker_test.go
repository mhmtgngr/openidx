package revocation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The divergence this package exists to prevent is a STATIC property: two
// packages spelling the same Redis key differently. No runtime test can catch
// it, because each half is internally consistent -- governance wrote
// auth:user_revoked:<uid> and was right about its own contract, oauth reads
// oauth:user_tokens_revoked_at:<uid> and is right about its own, and only
// holding them side by side shows that a revocation never reached a check.
//
// So the guard is a census: nothing outside this package may spell a revocation
// key itself. A caller that wants the marker calls UserTokensRevokedAtKey, and
// there is no second spelling for the next one to drift from.

// keyFragments are the shapes a hand-written revocation marker takes. The first
// is the key this package owns; the second is the one internal/auth's
// unreachable TokenService owned, which governance copied.
var keyFragments = []string{"user_tokens_revoked_at", "user_revoked"}

func TestNothingOutsideThisPackageSpellsTheRevocationKey(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This package is where the spelling lives, and this file names the
		// fragments in order to look for them.
		if strings.Contains(filepath.ToSlash(path), "internal/revocation/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(src)
		for _, frag := range keyFragments {
			// A quoted occurrence is a hand-written key. The same words in a
			// comment or an identifier (userTokensRevokedAtKey) are fine: it is
			// the string literal that reaches Redis.
			for _, quoted := range []string{`"` + frag, frag + `:"`, `"` + frag + `:`} {
				if strings.Contains(text, quoted) {
					t.Errorf("%s spells a revocation key itself (%q). Call revocation.UserTokensRevokedAtKey instead: "+
						"a second spelling is how an access review's revocation came to be written where no check reads it.",
						path, frag)
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

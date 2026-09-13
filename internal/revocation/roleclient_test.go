package revocation

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A revocation marker written to the wrong Redis instance is a marker that can
// be evicted. The rate-limit role runs allkeys-lru on purpose (counters are
// disposable); a revoke-all marker or a revoked_session:* key that lands there
// disappears under memory pressure and the revoked token answers again. So the
// rule is static, like the key-spelling census next door: every line that
// touches a revocation marker must obtain its client through
// (*database.RedisClient).RevocationDB(), never through .Client. The accessor
// aliases the primary when no dedicated instance is configured, so a
// single-Redis install loses nothing; what it buys is that when an operator DOES
// configure REDIS_REVOCATION_URL, every marker actually goes there.
//
// markerFragments are the substrings that identify a revocation write or read.
var markerFragments = []string{
	`"revoked_session:`,
	`UserTokensRevokedAtKey(`,
	`userTokensRevokedAtKey(`,
	`RevokeUserTokens(`,
	`accessTokenBlacklistKey(`,
}

func TestRevocationMarkersNeverGoThroughThePrimaryClient(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "docs", "agent", "agent-android":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// This package defines the helpers; the database package defines the
		// accessor. Neither writes a marker.
		slash := filepath.ToSlash(path)
		if strings.Contains(slash, "internal/revocation/") || strings.Contains(slash, "internal/common/database/") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			text := sc.Text()
			trimmed := strings.TrimSpace(text)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			touches := false
			for _, frag := range markerFragments {
				if strings.Contains(text, frag) {
					touches = true
					break
				}
			}
			if !touches {
				continue
			}
			// The function declarations themselves are fine; a call that
			// reaches Redis through .Client. is not.
			if strings.HasPrefix(trimmed, "func ") {
				continue
			}
			if strings.Contains(text, ".Client.") || strings.Contains(text, ".Client,") {
				offenders = append(offenders, slash+":"+itoa(line)+": "+trimmed)
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offenders {
		t.Errorf("%s\n    writes or reads a revocation marker through the primary Redis client; use RevocationDB() so a dedicated (noeviction) revocation instance actually receives it", o)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

package identity

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// A bypass code is read off one screen and typed on another, by someone who
// is locked out and stressed. The old form was 16 characters of URL-safe
// base64: mixed case with l/I/1 and O/0, which a phone keyboard
// auto-capitalises and autocorrects. A code could fail on a glance.
//
// Codes now come from Crockford's base32 alphabet: digits and upper-case
// letters without I, L, O or U, so no two symbols look alike. 16 symbols of 32
// is 80 bits, more than the 72 the old form carried. Verification normalises
// what was typed the way Crockford decoding does — upper-case, and the
// look-alikes folded (I, L → 1; O → 0) — and ignores spaces and hyphens, so a
// code read out in groups still matches.

const bypassCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const bypassCodeLength = 16

func generateBypassCode() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(bypassCodeAlphabet)))
	for i := 0; i < bypassCodeLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(bypassCodeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// normalizeBypassCode folds what a person typed into the form a code was
// issued in. A code issued before this alphabet (mixed-case base64) still
// verifies as typed: the fold only changes characters the new alphabet lacks,
// and bcrypt sees the original on the first comparison when it differs.
func normalizeBypassCode(typed string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(typed)) {
		switch r {
		case ' ', '-':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		b.WriteRune(r)
	}
	return b.String()
}

//go:build !windows

package doctor

import (
	"os"
	"strings"
)

// DetectLang follows LC_ALL, then LC_MESSAGES, then LANG: Turkish when the
// first one set starts with "tr", English otherwise.
func DetectLang() Lang {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			if strings.HasPrefix(v, "tr") {
				return LangTR
			}
			return LangEN
		}
	}
	return LangEN
}

//go:build !windows

package doctor

import "testing"

func TestDetectLangFromEnv(t *testing.T) {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, "")
	}
	if DetectLang() != LangEN {
		t.Error("no locale must mean English")
	}
	t.Setenv("LANG", "tr_TR.UTF-8")
	if DetectLang() != LangTR {
		t.Error("LANG=tr_TR must mean Turkish")
	}
	t.Setenv("LC_ALL", "en_US.UTF-8")
	if DetectLang() != LangEN {
		t.Error("LC_ALL outranks LANG")
	}
}

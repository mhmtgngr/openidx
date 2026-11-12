package tray

import (
	"reflect"
	"testing"
)

func TestStringsFor(t *testing.T) {
	cases := map[uint16]string{
		0x041f: "tr", // tr-TR
		0x001f: "tr", // neutral Turkish
		0x0409: "en", // en-US
		0x0407: "en", // de-DE
		0:      "en",
	}
	for id, want := range cases {
		if got := stringsFor(id).Lang; got != want {
			t.Errorf("stringsFor(%#04x) = %s, want %s", id, got, want)
		}
	}
	if T.Lang != "en" && uiLanguage() == 0 {
		t.Errorf("default table = %s, want en", T.Lang)
	}
}

// Every field is filled in both languages, so no label falls back to blank.
func TestStringTablesComplete(t *testing.T) {
	for _, tab := range []strs{enStrings, trStrings} {
		v := reflect.ValueOf(tab)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).String() == "" {
				t.Errorf("%s: %s is empty", tab.Lang, v.Type().Field(i).Name)
			}
		}
	}
	if trStrings.SignIn == enStrings.SignIn || trStrings.Network == enStrings.Network {
		t.Error("tr table is not translated")
	}
}

func TestMyAppsURL(t *testing.T) {
	if got := myAppsURL(" https://idx.example/ "); got != "https://idx.example/my-network" {
		t.Errorf("myAppsURL = %q", got)
	}
	if myAppsURL("") != "" {
		t.Error("no server should give no URL")
	}
}

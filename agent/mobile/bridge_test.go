package mobile

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// Every binding in this package is written down four times.
//
//	agent/mobile/mobile.go                      func RegisterPushDevice(...)
//	client/plugins/openidx_engine/lib/…dart     invokeMethod('registerPushDevice')
//	…/android/…/OpenidxEnginePlugin.kt          "registerPushDevice" -> Mobile.…
//	…/ios/Classes/OpenidxEnginePlugin.swift     case "registerPushDevice":
//
// Three of those are hand-maintained lists in three different languages, and
// nothing has ever checked that they agree. They do today. The failure they
// permit is quiet and one-sided: add an eighteenth binding, wire it into Dart
// and Kotlin, forget Swift, and the Android build is fine while iOS answers
// MissingPluginException at runtime -- on a screen that looks finished, in a
// release that compiled, from a Flutter analyze that passed.
//
// Neither the Go compiler, `flutter analyze`, `gomobile bind`, nor any test in
// this repository can see across that boundary. This census can: it derives the
// Go side from the package source and requires each platform to answer for it,
// in both directions.
//
// It is a Go test reaching into client/ deliberately. The bindings are this
// package's export surface; the three bridges exist only to expose it; and the
// only way for four lists to agree by construction is for one of them to be
// checked against the others.
var bridges = []struct {
	name string
	path string
	// pattern must capture the channel method name in group 1.
	pattern *regexp.Regexp
}{
	{
		name:    "Dart plugin",
		path:    "../../client/plugins/openidx_engine/lib/openidx_engine.dart",
		pattern: regexp.MustCompile(`(?:invokeMethod<[^>]*>|_invokeString)\(\s*'([a-zA-Z]+)'`),
	},
	{
		name:    "Kotlin plugin",
		path:    "../../client/plugins/openidx_engine/android/src/main/kotlin/org/openidx/engine/OpenidxEnginePlugin.kt",
		pattern: regexp.MustCompile(`"([a-zA-Z]+)"\s*->`),
	},
	{
		name:    "Swift plugin",
		path:    "../../client/plugins/openidx_engine/ios/Classes/OpenidxEnginePlugin.swift",
		pattern: regexp.MustCompile(`case\s+"([a-zA-Z]+)"\s*:`),
	},
}

// channelName is the Dart/Kotlin/Swift spelling of a Go binding: the exported
// Go name with its first letter lowered. Start -> start, PamList -> pamList.
func channelName(goName string) string {
	if goName == "" {
		return ""
	}
	r := []rune(goName)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

func TestEveryBindingIsWiredOnEveryPlatform(t *testing.T) {
	goBindings := exportedBindings(t)

	want := map[string]string{} // channel name -> Go name
	for name := range goBindings {
		want[channelName(name)] = name
	}

	for _, b := range bridges {
		src, err := os.ReadFile(b.path)
		if err != nil {
			t.Fatalf("%s: %v.\nThis census is the only thing checking that the "+
				"platform bridges expose every binding; if the file moved, point it "+
				"at the new path rather than deleting the case.", b.name, err)
		}

		found := map[string]bool{}
		for _, m := range b.pattern.FindAllStringSubmatch(string(src), -1) {
			found[m[1]] = true
		}
		if len(found) == 0 {
			t.Errorf("%s (%s): the pattern matched no channel method at all. Either the "+
				"file's shape changed or the bridge is empty; both are findings, and a "+
				"census that matches nothing passes vacuously.", b.name, b.path)
			continue
		}

		var missing []string
		for channel, goName := range want {
			if !found[channel] {
				missing = append(missing, fmt.Sprintf("%s (Go: %s)", channel, goName))
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s does not handle %d binding(s) this package exports:\n  %s\n"+
				"A binding missing from one platform is not a build error anywhere -- "+
				"it is a MissingPluginException on a device, at the moment a user taps "+
				"the button. Wire it in %s.",
				b.name, len(missing), strings.Join(missing, "\n  "), b.path)
		}

		var extra []string
		for channel := range found {
			if _, ok := want[channel]; !ok {
				extra = append(extra, channel)
			}
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			t.Errorf("%s handles %d channel method(s) this package does not export:\n  %s\n"+
				"Either the binding was renamed or removed on the Go side and this arm is "+
				"now unreachable, or the arm is a typo that will never be called.",
				b.name, len(extra), strings.Join(extra, "\n  "))
		}
	}
}

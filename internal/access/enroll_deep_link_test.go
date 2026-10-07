package access

import (
	"net/url"
	"testing"
)

// The "Open in app" button on Windows hands the link straight to the agent's
// URL handler, which has no server field of its own: a link without `server`
// enrolled against the agent's built-in https://openidx.example.com. The
// link must name the server, and both values must survive the round trip
// through the same url.Parse the agent uses.
func TestEnrollDeepLinkNamesTheServer(t *testing.T) {
	link := enrollDeepLink("ABCDEFGHJKMN", "https://openidx.tdv.org")

	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	if u.Scheme != "openidx" || u.Host != "enroll" {
		t.Fatalf("link %q is not an openidx://enroll link", link)
	}
	if got := u.Query().Get("code"); got != "ABCDEFGHJKMN" {
		t.Errorf("code = %q, want ABCDEFGHJKMN", got)
	}
	if got := u.Query().Get("server"); got != "https://openidx.tdv.org" {
		t.Errorf("server = %q, want https://openidx.tdv.org", got)
	}
}

func TestEnrollDeepLinkWithoutServerCarriesTheCodeOnly(t *testing.T) {
	link := enrollDeepLink("ABCDEFGHJKMN", "")
	if link != "openidx://enroll?code=ABCDEFGHJKMN" {
		t.Errorf("link = %q, want the code alone", link)
	}
}

package oauth

import (
	"context"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/botgate"
)

// WHAT THE REFUSAL TELLS THE PERSON IT REFUSED.
//
// The bot gate's 403 is the only thing the login page has to work with, and
// until now it said the same sentence in two situations that are not the same:
// one where the page can render a challenge and one where it cannot. The
// second is a soft lockout, and telling someone to complete a verification
// that is nowhere on the screen is not a smaller version of telling them to
// wait -- it is an instruction they cannot follow, which reads as a broken
// login and is answered by retrying into the same counter.
//
// This package's suite is deliberately kept out of the database: these are
// assertions about a response body, and a seeded PostgreSQL would say nothing
// extra about them.

type okVerifier struct{}

func (okVerifier) Verify(context.Context, string, string) (bool, error) { return true, nil }

func TestARefusalThePageCanActOnCarriesTheSiteKey(t *testing.T) {
	g := botgate.New(nil, botgate.Config{Mode: botgate.ModeEnforce, SiteKey: "1x00000000000000000000AA"}, okVerifier{})

	body := challengeRefusal(g, botgate.ReasonFailures)

	if body["site_key"] != "1x00000000000000000000AA" {
		t.Errorf("site_key = %v, want the configured key. Without it the page cannot render the widget, "+
			"whatever the description says", body["site_key"])
	}
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "Complete the verification challenge") {
		t.Errorf("error_description = %q; with a renderable challenge the instruction should be to complete it", desc)
	}
	if body["error"] != "challenge_required" || body["challenge"] != "edge" {
		t.Errorf("the refusal changed shape: %+v; the login page matches on these two", body)
	}
	if body["reason"] != string(botgate.ReasonFailures) {
		t.Errorf("reason = %v, want %q", body["reason"], botgate.ReasonFailures)
	}
}

func TestARefusalThePageCannotActOnSaysWaitInstead(t *testing.T) {
	// The deployment shape that shipped: a verifier and no site key. The page
	// has nothing to render, so the refusal must not ask it to.
	g := botgate.New(nil, botgate.Config{Mode: botgate.ModeEnforce}, okVerifier{})

	body := challengeRefusal(g, botgate.ReasonFailures)

	if _, present := body["site_key"]; present {
		t.Errorf("site_key is present with no key configured: %v", body["site_key"])
	}
	desc, _ := body["error_description"].(string)
	if strings.Contains(desc, "Complete the verification challenge") {
		t.Errorf("error_description = %q.\nThere is no challenge to complete here -- this is a lockout until "+
			"the window passes, and the sentence has to say that or the person retries into the same counter", desc)
	}
	if !strings.Contains(desc, "Wait") {
		t.Errorf("error_description = %q; say what the person should actually do", desc)
	}
}

// And the combination that looks configured and is not: a site key with no
// verifier. The page must still be told to wait, because a widget it renders
// here can never be accepted.
func TestASiteKeyWithNoVerifierIsNotOffered(t *testing.T) {
	g := botgate.New(nil, botgate.Config{Mode: botgate.ModeEnforce, SiteKey: "1x00000000000000000000AA"}, nil)

	body := challengeRefusal(g, botgate.ReasonEdgeBotScore)

	if _, present := body["site_key"]; present {
		t.Errorf("site_key offered with no verifier: the person would solve a widget whose answer is ignored")
	}
	if desc, _ := body["error_description"].(string); strings.Contains(desc, "Complete the verification challenge") {
		t.Errorf("error_description = %q; the challenge cannot be checked, so it must not be asked for", desc)
	}
}

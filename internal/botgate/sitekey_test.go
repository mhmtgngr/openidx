package botgate

import (
	"context"
	"testing"
)

// A gate that can render a challenge is a gate that can check one.
//
// The two halves of Turnstile are separate settings and each alone is a dead
// end, so ChallengeSiteKey answers for both at once. These cases are the four
// combinations, and two of them are the ones that shipped or nearly shipped.

type alwaysGood struct{}

func (alwaysGood) Verify(context.Context, string, string) (bool, error) { return true, nil }

func TestASiteKeyIsOnlyOfferedWhenAnAnswerCanBeChecked(t *testing.T) {
	cases := []struct {
		name     string
		siteKey  string
		verifier ChallengeVerifier
		want     string
		why      string
	}{
		{
			name: "both configured", siteKey: "1x00000000000000000000AA", verifier: alwaysGood{}, want: "1x00000000000000000000AA",
			why: "the only combination where a person can be asked to prove they are human and be believed",
		},
		{
			name: "verifier but no site key", siteKey: "", verifier: alwaysGood{}, want: "",
			why: "what this deployment had: the server could check a token the page had no way to obtain, " +
				"so the refusal asked for a challenge that did not exist",
		},
		{
			name: "site key but no verifier", siteKey: "1x00000000000000000000AA", verifier: nil, want: "",
			why: "the worse half: the widget renders, the person solves it, and Check ignores the token " +
				"and falls through to the counter that refused them -- a loop with no exit",
		},
		{
			name: "neither", siteKey: "", verifier: nil, want: "",
			why: "the default: a soft lockout until the window passes, and the refusal must say so",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := New(nil, Config{Mode: ModeEnforce, SiteKey: tc.siteKey}, tc.verifier)
			if got := g.ChallengeSiteKey(); got != tc.want {
				t.Errorf("ChallengeSiteKey() = %q, want %q.\n%s", got, tc.want, tc.why)
			}
		})
	}
}

// And the fact the third case rests on, measured rather than assumed: with no
// verifier, a token is not rejected -- it is ignored, and the decision is made
// by the counter as though the person had solved nothing.
func TestWithNoVerifierASolvedChallengeChangesNothing(t *testing.T) {
	g := New(nil, Config{Mode: ModeEnforce, SiteKey: "1x00000000000000000000AA"}, nil)

	withToken := g.Check(context.Background(), "org", "someone", "1", "a-solved-token", "")
	withoutToken := g.Check(context.Background(), "org", "someone", "1", "", "")

	if withToken.Challenge != withoutToken.Challenge || withToken.Reason != withoutToken.Reason {
		t.Fatalf("a token changed the decision with no verifier configured: with=%+v without=%+v.\n"+
			"If that ever becomes true, ChallengeSiteKey may offer a site key without one.", withToken, withoutToken)
	}
	if !withToken.Challenge {
		t.Fatalf("the edge score of 1 should have been a challenge either way; this case is measuring nothing")
	}
}

package oauth

import "testing"

// responseTypeAllowedForClient is the one rule both authorize handlers use.
// /authorize/v2 enforced it through AuthorizeHandler.validateResponseType while
// the primary /authorize — the handler every browser client actually reaches —
// enforced nothing, so the value of these cases is that they now describe both.
func TestResponseTypeAllowedForClient(t *testing.T) {
	cases := []struct {
		name         string
		client       *OAuthClient
		responseType string
		want         bool
		why          string
	}{
		{
			name:         "registered type is allowed",
			client:       &OAuthClient{ResponseTypes: []string{"code"}},
			responseType: "code",
			want:         true,
		},
		{
			// The defect: a client registered for the authorization-code flow
			// asking for a token in the fragment was carried to a login screen.
			name:         "an unregistered type is refused",
			client:       &OAuthClient{ResponseTypes: []string{"code"}},
			responseType: "token",
			want:         false,
			why:          "a code-only client must not be able to ask for an implicit token",
		},
		{
			name:         "one of several registered types is allowed",
			client:       &OAuthClient{ResponseTypes: []string{"code", "id_token"}},
			responseType: "id_token",
			want:         true,
		},
		{
			// oauth_clients.response_types is JSONB with no column default, so a
			// row written by anything that does not set it reads back empty.
			// Refusing those would turn a missing value into an outage for that
			// client; RFC 7591 §2 makes the default ["code"], which is also what
			// dcr.go already applies at registration.
			name:         "an unset response_types defaults to code",
			client:       &OAuthClient{},
			responseType: "code",
			want:         true,
			why:          "a client row with no response_types must still be able to sign users in",
		},
		{
			name:         "the default is only code, not everything",
			client:       &OAuthClient{},
			responseType: "token",
			want:         false,
			why:          "defaulting must not become a way to skip the check",
		},
		{
			name:         "an empty request response_type is refused",
			client:       &OAuthClient{ResponseTypes: []string{"code"}},
			responseType: "",
			want:         false,
			why:          "response_type is required (RFC 6749 §4.1.1); no client registers \"\"",
		},
		{
			name:         "a nil client is refused",
			client:       nil,
			responseType: "code",
			want:         false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseTypeAllowedForClient(tc.client, tc.responseType); got != tc.want {
				t.Fatalf("responseTypeAllowedForClient = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

// The two handlers must not be able to drift into two opinions again.
func TestBothAuthorizeHandlersShareTheResponseTypeRule(t *testing.T) {
	h := &AuthorizeHandler{}
	client := &OAuthClient{ResponseTypes: []string{"code"}}
	for _, rt := range []string{"code", "token", "id_token", ""} {
		if h.validateResponseType(client, rt) != responseTypeAllowedForClient(client, rt) {
			t.Fatalf("validateResponseType and responseTypeAllowedForClient disagree on %q", rt)
		}
	}
}

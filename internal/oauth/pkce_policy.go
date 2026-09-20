package oauth

import (
	"encoding/base64"
	"fmt"
)

// PKCE (RFC 7636) policy, in one place.
//
// It lives in its own file because the rule was previously spelled out in
// exactly one of the five request paths that accept a client-supplied
// code_challenge — AuthorizeHandler.validatePKCEParameters, on
// /oauth/authorize/v2 — while /oauth/authorize, the route every browser
// client actually reaches (service.go, handleAuthorize), enforced no part of
// it: a public client could omit code_challenge entirely and be carried to a
// login page, and the code minted at the end of that flow carried an empty
// challenge, which makes handleTokenRequest's `if authCode.CodeChallenge != ""`
// guard vacuous. That is the same omission scope and response_type each had on
// this handler, found and fixed one at a time; this is the third.
//
// pkce_required is the second half. It is stored on the client
// (oauth_client_store.go), served by the admin API and editable in the
// console's Applications editor — and nothing read it. An operator who ticked
// the box was told the client now required PKCE and it required nothing.

// pkceRequired reports whether this client must present a code_challenge.
//
// Public clients: RFC 7636 §1 — they cannot authenticate at the token
// endpoint, so an intercepted code is redeemable by whoever holds it. This is
// why dcr.go registers every public client with PKCERequired = true.
//
// Confidential clients: only when the operator asked for it. PKCE is sound for
// a confidential client too (OAuth 2.1 requires it of everyone), but turning it
// on for every existing confidential registration would reject the next request
// from clients that work today. The switch is how an operator opts in, per
// client, and it is now the thing that decides.
func pkceRequired(client *OAuthClient) bool {
	if client == nil {
		return false
	}
	return client.Type == "public" || client.PKCERequired
}

// validatePKCERequest applies the whole rule to one authorization request:
// whether a challenge is required at all, whether the method is one this
// server implements, and whether the challenge itself is well formed.
//
// production suppresses "plain" (RFC 7636 §7.2 — it offers no protection
// against interception, and discovery advertises only S256). The token
// endpoint keeps its own "plain" guard for defence in depth.
//
// A nil error means the request may proceed. The text of a non-nil error is
// reported to the client as an invalid_request error_description, so it says
// what the client got wrong and nothing about the server.
func validatePKCERequest(client *OAuthClient, challenge, method string, production bool) error {
	if challenge == "" {
		if pkceRequired(client) {
			return fmt.Errorf("code_challenge is required for this client")
		}
		// No challenge and none required: there is nothing to validate. A
		// code_challenge_method on its own is meaningless, and ignoring it
		// matches what both handlers did before.
		return nil
	}

	if method != "" {
		if method != "S256" && method != "plain" {
			return fmt.Errorf("unsupported code_challenge_method: %s", method)
		}
		if method == "plain" && production {
			return fmt.Errorf("code_challenge_method 'plain' is not allowed; use S256")
		}
	}

	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		return fmt.Errorf("invalid code_challenge format: must be base64url-encoded")
	}
	// RFC 7636 §4.1: 43..128 characters of the encoded challenge.
	if len(challenge) < 43 || len(challenge) > 128 {
		return fmt.Errorf("code_challenge length must be between 43 and 128 characters")
	}
	return nil
}

// isProduction reports whether this service is running with a production
// config, for the "plain" rule above. The config is nil in several test
// fixtures, and a missing config is not production.
func (s *Service) isProduction() bool {
	return s.config != nil && s.config.IsProduction()
}

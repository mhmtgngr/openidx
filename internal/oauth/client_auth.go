package oauth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// Client authentication at the token endpoint.
//
// Discovery advertises both client_secret_post and client_secret_basic
// (token_endpoint_auth_methods_supported), but nothing ever parsed an
// Authorization: Basic header — every handler read client_id/client_secret from
// the form body only. A client following the advertised capability, or simply
// following RFC 6749 §2.3.1's "the authorization server MUST support the HTTP
// Basic authentication scheme", was rejected with invalid_client. That is the
// exact failure mode the codebase's own rule ("advertised = working") exists to
// prevent.

// clientCredentials extracts the client id and secret from a token-endpoint
// request, preferring the Authorization: Basic header over the form body.
//
// The second return value reports whether the request is well-formed. It is
// false only when the client used both mechanisms at once, which RFC 6749
// §2.3.1 forbids ("The client MUST NOT use more than one authentication method
// in each request") and which would otherwise leave the server silently
// choosing between two different credentials.
func clientCredentials(c *gin.Context) (id, secret string, ok bool) {
	basicID, basicSecret, hasBasic := basicClientAuth(c)
	formID, formSecret := c.PostForm("client_id"), c.PostForm("client_secret")

	if hasBasic {
		// A form client_id that merely repeats the Basic one is harmless and
		// common; a second *secret*, or a conflicting id, is the ambiguity the
		// RFC forbids.
		if formSecret != "" || (formID != "" && formID != basicID) {
			return "", "", false
		}
		return basicID, basicSecret, true
	}
	return formID, formSecret, true
}

// basicClientAuth decodes an Authorization: Basic header per RFC 6749 §2.3.1.
//
// The id and secret are form-urlencoded before base64 encoding, so they must be
// decoded on the way back out — a secret containing '+' or '%' is otherwise
// silently mangled into a mismatch that looks like a wrong password.
func basicClientAuth(c *gin.Context) (id, secret string, ok bool) {
	header := c.GetHeader("Authorization")
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}

	name, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}

	decodedName, err := url.QueryUnescape(name)
	if err != nil {
		return "", "", false
	}
	decodedPass, err := url.QueryUnescape(pass)
	if err != nil {
		return "", "", false
	}
	if decodedName == "" {
		return "", "", false
	}
	return decodedName, decodedPass, true
}

// errTwoClientAuthMethods and errClientNotAuthenticated are the two ways
// authenticateConfidentialClient refuses a caller; writeClientAuthError maps
// them to their RFC 6749 §5.2 answers. Any other error is a lookup that could
// not be made.
var (
	errTwoClientAuthMethods   = errors.New("use only one client authentication method")
	errClientNotAuthenticated = errors.New("client authentication failed")
)

// isConfidential reports whether this client can authenticate at the token
// endpoint (RFC 6749 §2.1): it holds a secret, and it was not registered as a
// client that cannot keep one. Dynamic registration and the seeds name such a
// client "public"; the console's application types are web, native and
// service, and it describes native -- a mobile or desktop application -- as a
// public client with PKCE, although the management API mints it a secret like
// the others. A secret shipped inside an application proves nothing about who
// is calling.
func (c *OAuthClient) isConfidential() bool {
	if c == nil || c.ClientSecret == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.Type)) {
	case "public", "native":
		return false
	}
	return true
}

// authenticateConfidentialClient authenticates the caller of a grant that only
// a confidential client may use: token exchange, which mints a user's token
// for an audience. The caller must name a confidential client of the
// request's organization and present its secret by exactly one method.
//
// The exchange used to check the secret of a client whose type was the
// literal "confidential" and nothing else, so a public client, whose
// client_id is no secret, was authenticated by naming it, and every client the
// console registers without its secret.
func (s *Service) authenticateConfidentialClient(c *gin.Context) (*OAuthClient, error) {
	id, secret, ok := clientCredentials(c)
	if !ok {
		return nil, errTwoClientAuthMethods
	}
	if id == "" || secret == "" {
		return nil, errClientNotAuthenticated
	}
	client, err := s.GetClient(c.Request.Context(), id)
	if errors.Is(err, ErrOAuthClientNotFound) {
		return nil, errClientNotAuthenticated
	}
	if err != nil {
		return nil, err
	}
	if !client.isConfidential() || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(secret)) != 1 {
		return nil, errClientNotAuthenticated
	}
	return client, nil
}

// writeClientAuthError answers a caller authenticateConfidentialClient refused.
func writeClientAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errTwoClientAuthMethods):
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrorInvalidRequest, "error_description": err.Error()})
	case errors.Is(err, errClientNotAuthenticated):
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrorInvalidClient, "error_description": err.Error()})
	default:
		writeServerOrUnavailable(c, err)
	}
}

// Package sso implements the desktop OAuth Authorization-Code + PKCE flow over
// an RFC 8252 loopback redirect. The user authenticates (incl. MFA) in their
// default browser; the client captures the code on 127.0.0.1 and exchanges it
// for tokens. Mirrors the mobile app's oauth flow.
package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DesktopClientID is the public/PKCE client seeded by migration v85.
	DesktopClientID = "openidx-desktop"
	// LoopbackAddr / RedirectURI must match a registered redirect on the client.
	LoopbackAddr = "127.0.0.1:47600"
	RedirectURI  = "http://127.0.0.1:47600/callback"
)

// DefaultScopes requested at login.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// Tokens is the result of a login or refresh.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"` // unix seconds
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// Login runs the interactive PKCE-loopback flow against serverURL (e.g.
// https://openidx.tdv.org) and returns tokens. Blocks until the browser
// redirect is captured, the context is cancelled, or the timeout elapses.
func Login(ctx context.Context, serverURL string) (*Tokens, error) {
	serverURL = strings.TrimRight(serverURL, "/")

	pk, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", LoopbackAddr)
	if err != nil {
		return nil, fmt.Errorf("binding loopback %s: %w", LoopbackAddr, err)
	}

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "sign-in failed: "+e, http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("authorization error: %s", e)}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("state mismatch")}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("no authorization code")}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">` +
			`<h2>Signed in to OpenIDX</h2><p>You can close this tab and return to the app.</p></body></html>`))
		resCh <- result{code: code}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	authURL := serverURL + "/oauth/authorize/v2?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {DesktopClientID},
		"redirect_uri":          {RedirectURI},
		"scope":                 {strings.Join(DefaultScopes, " ")},
		"state":                 {state},
		"code_challenge":        {pk.challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	if err := openBrowser(authURL); err != nil {
		// Non-fatal: print the URL so the user can open it manually.
		fmt.Printf("Open this URL to sign in:\n  %s\n", authURL)
	}

	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout.C:
		return nil, fmt.Errorf("sign-in timed out")
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		return exchange(ctx, serverURL, url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {DesktopClientID},
			"code":          {res.code},
			"redirect_uri":  {RedirectURI},
			"code_verifier": {pk.verifier},
		})
	}
}

// Refresh exchanges a refresh token for a fresh access token.
func Refresh(ctx context.Context, serverURL, refreshToken string) (*Tokens, error) {
	return exchange(ctx, strings.TrimRight(serverURL, "/"), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {DesktopClientID},
		"refresh_token": {refreshToken},
	})
}

func exchange(ctx context.Context, serverURL string, form url.Values) (*Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		serverURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	exp := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	if tr.ExpiresIn == 0 {
		exp = time.Now().Add(time.Hour).Unix()
	}
	return &Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresAt:    exp,
	}, nil
}

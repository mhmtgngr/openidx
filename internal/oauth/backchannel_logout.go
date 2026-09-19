// Package oauth - OpenID Connect Back-Channel Logout 1.0.
//
// The discovery document has advertised backchannel_logout_supported and
// backchannel_logout_session_supported for as long as it has existed, the
// oauth_clients table has carried back_channel_logout_uri since v63, and
// nothing read that column or sent a single logout token. A relying party
// that registered a URI and trusted the advertisement kept its own session
// open after the user signed out here — the one thing back-channel logout is
// for, and the exact inverse of what single sign-on (browser_session.go) now
// makes cheap: one login opens every application, so one logout has to be
// able to close them.
//
// Shape (Back-Channel Logout 1.0 §2):
//
//   - A logout token is a JWT signed with the ID-token key: iss, sub (the
//     same subject the RP saw in its ID token, pairwise or public), aud (the
//     client), iat, exp (short), jti, the events claim naming
//     http://schemas.openid.net/event/backchannel-logout, and sid — the
//     session id the RP saw as the ID token's sid. No nonce, ever (§2.4:
//     "MUST NOT contain a nonce"). typ is logout+jwt.
//   - It is POSTed as application/x-www-form-urlencoded logout_token=... to
//     the client's back_channel_logout_uri. 200 means the RP acted; anything
//     else is a failure it reports (§2.8).
//   - Who is told: every relying party the session reached — the client the
//     session was created for, and every client holding a refresh token bound
//     to it (that is how an SSO code issued from the session shows up here) —
//     restricted to clients whose registration carries a URI, in the
//     session's own tenant.
//   - When: from the one place a session stops being live, revokeSessionWithRedis
//     (session_policy.go). That covers /oauth/logout with a cookie, an
//     id_token_hint or a bearer, /oauth/logout-all, an SSF receiver acting on
//     an upstream signal, a concurrent-session eviction, a force-login
//     termination, and the inactivity and absolute-timeout sweeps. A session
//     the identity service ends on its own (its session admin pages) is not
//     this process's revocation and is not covered here; that is written in
//     the plan, not hidden.
//
// Delivery is best-effort and asynchronous: the logout that caused it has
// already happened, the caller's response is never held for a relying
// party's endpoint, and the spec says the OP MAY retry — this one does not
// (a failure is logged and audited). It is a notification, not the
// revocation: the tokens the session backed are cut by the revocation marker
// whether or not the RP heard.
package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	// backchannelLogoutEvent is the events-claim member name (§2.4).
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	// logoutTokenTTL bounds how long a logout token is acceptable. It is a
	// notification consumed on receipt, so two minutes is generous.
	logoutTokenTTL = 2 * time.Minute
	// backchannelLogoutTimeout bounds one delivery attempt.
	backchannelLogoutTimeout = 10 * time.Second
	// logoutTokenType is the JWT typ header (§2.4 recommends logout+jwt).
	logoutTokenType = "logout+jwt"
)

// backchannelTarget is one (relying party, session) a logout token goes to.
type backchannelTarget struct {
	org       orgctx.Org
	clientID  string
	uri       string
	userID    string
	sessionID string
}

// validateBackChannelLogoutURI accepts an empty value (no back-channel
// logout for this client) or an absolute https URL; http is allowed only for
// the loopback hosts a developer runs a relying party on, mirroring the
// redirect_uri rule in dcr.go.
func validateBackChannelLogoutURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return errors.New("back_channel_logout_uri must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return errors.New("back_channel_logout_uri must be https (http only for localhost)")
}

// mintLogoutToken builds and signs the logout token for one relying party.
func (s *Service) mintLogoutToken(org orgctx.Org, clientID, userID, sessionID string) (string, error) {
	kid, key := s.signingKey()
	if key == nil {
		return "", errors.New("no signing key")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": s.issuerForOrg(org),
		"sub": s.subjectFor(userID, clientID),
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(logoutTokenTTL).Unix(),
		"jti": GenerateRandomToken(16),
		"events": map[string]interface{}{
			backchannelLogoutEvent: map[string]interface{}{},
		},
		"sid": sessionID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = logoutTokenType
	return tok.SignedString(key)
}

// backchannelLogoutTargets resolves which relying parties learn that
// sessionID ended. The session row supplies the tenant and the user; the
// login client and every client holding a refresh token bound to the session
// are candidates; only those registered with a back_channel_logout_uri in
// that tenant are targets.
func (s *Service) backchannelLogoutTargets(ctx context.Context, sessionID string) ([]backchannelTarget, error) {
	var userID, orgID, loginClient string
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore addressed by the globally-unique session id from the revocation funnel; the row's own org_id scopes every query below
		`SELECT user_id::text, org_id::text, COALESCE(client_id, '') FROM sessions WHERE id = $1`,
		sessionID).Scan(&userID, &orgID, &loginClient)
	if err != nil {
		return nil, fmt.Errorf("session row: %w", err)
	}

	candidates := map[string]struct{}{}
	if loginClient != "" {
		candidates[loginClient] = struct{}{}
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT DISTINCT client_id FROM oauth_refresh_tokens WHERE session_id = $1 AND org_id = $2`,
		sessionID, orgID)
	if err != nil {
		return nil, fmt.Errorf("refresh-token clients: %w", err)
	}
	for rows.Next() {
		var cid string
		if rows.Scan(&cid) == nil && cid != "" {
			candidates[cid] = struct{}{}
		}
	}
	rows.Close()
	if len(candidates) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(candidates))
	for cid := range candidates {
		ids = append(ids, cid)
	}

	org := orgctx.Org{ID: orgID}
	// The slug decides the per-tenant issuer (issuerForOrg); a tenant without
	// a row here gets the base issuer, as its ID tokens did.
	_ = s.db.Pool.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1`, orgID).Scan(&org.Slug)

	crow, err := s.db.Pool.Query(ctx, `
		SELECT client_id, back_channel_logout_uri
		  FROM oauth_clients
		 WHERE org_id = $1 AND client_id = ANY($2)
		   AND COALESCE(back_channel_logout_uri, '') <> ''`, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("client logout uris: %w", err)
	}
	defer crow.Close()
	var targets []backchannelTarget
	for crow.Next() {
		var cid, uri string
		if crow.Scan(&cid, &uri) != nil {
			continue
		}
		targets = append(targets, backchannelTarget{org: org, clientID: cid, uri: uri, userID: userID, sessionID: sessionID})
	}
	return targets, nil
}

// deliverLogoutToken mints and POSTs one logout token. It returns nil only
// when the relying party answered 200 (§2.8).
func (s *Service) deliverLogoutToken(ctx context.Context, t backchannelTarget) error {
	token, err := s.mintLogoutToken(t.org, t.clientID, t.userID, t.sessionID)
	if err != nil {
		return err
	}
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.uri, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	client := &http.Client{Timeout: backchannelLogoutTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relying party answered %d", resp.StatusCode)
	}
	return nil
}

// notifyBackchannelLogout tells every relying party of sessionID that it has
// ended. Called from revokeSessionWithRedis after the row is revoked; it
// returns immediately and does its work in the background. An observer, set
// by tests, learns how many deliveries succeeded and failed for the session.
func (s *Service) notifyBackchannelLogout(sessionID string) {
	if s == nil || s.db == nil || !isValidSessionID(sessionID) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), backchannelLogoutTimeout+5*time.Second)
		defer cancel()
		delivered, failed := s.fanOutBackchannelLogout(ctx, sessionID)
		if s.backchannelObserver != nil {
			s.backchannelObserver(sessionID, delivered, failed)
		}
	}()
}

// fanOutBackchannelLogout is the synchronous body of notifyBackchannelLogout.
func (s *Service) fanOutBackchannelLogout(ctx context.Context, sessionID string) (delivered, failed int) {
	targets, err := s.backchannelLogoutTargets(ctx, sessionID)
	if err != nil {
		s.logger.Warn("back-channel logout: could not resolve relying parties",
			logsafe.String("session_id", sessionID), zap.Error(err))
		return 0, 0
	}
	for _, t := range targets {
		status := "delivered"
		meta := map[string]interface{}{"client_id": t.clientID, "session_id": t.sessionID}
		if derr := s.deliverLogoutToken(ctx, t); derr != nil {
			status = "failed"
			meta["error"] = derr.Error()
			failed++
			s.logger.Warn("back-channel logout delivery failed",
				logsafe.String("client_id", t.clientID), logsafe.String("session_id", t.sessionID), zap.Error(derr))
		} else {
			delivered++
		}
		s.logAuditEvent(orgctx.With(ctx, t.org), "authentication", "oauth", "backchannel_logout", status,
			t.userID, "", t.clientID, "client", meta)
	}
	return delivered, failed
}

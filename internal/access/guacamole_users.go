// Package access — per-user Guacamole broker identities (PAM hardening).
//
// Today every PAM session is brokered through the shared Guacamole admin account,
// and the token embedded in the browser connect URL is that admin token — a user
// could lift it from DevTools and drive the Guacamole admin API. This file adds
// standing NON-admin Guacamole accounts (one per OpenIDX user per broker),
// mirroring ziti_user_sync.go. The account holds READ on only the connection the
// user is launching (granted JIT at connect, revoked at session end), and the
// browser token is minted as this account — so a stolen token can reach exactly
// that one connection and never the admin REST API.
//
// Gated by cfg.GuacamolePerUserIdentities (GuacamoleClient.perUserIdentities);
// every entry point falls back to the shared-admin path on any error.
package access

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// randomGuacPassword returns a 32-byte base64url random password (no padding).
func randomGuacPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// guacUsernameFor derives the Guacamole username for an OpenIDX user: email, else
// username, else the user_id. Trimmed; empty inputs skipped.
func guacUsernameFor(email, username, userID string) string {
	for _, v := range []string{email, username, userID} {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return userID
}

// ensureGuacUserRecord returns (guacUsername, plaintextPassword) for (broker,user),
// creating the guacamole_users row (and the Guacamole account) on first use.
// Idempotent and safe under concurrent connects (ON CONFLICT). Runs under the
// connect request ctx so RLS scopes the row to the caller's org.
func (s *Service) ensureGuacUserRecord(ctx context.Context, gc *GuacamoleClient, orgID, userID string) (string, string, error) {
	// 1. Existing mapping?
	var guacUser, encPw string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT guac_username, guac_password_enc FROM guacamole_users
		  WHERE broker = $1 AND user_id = $2`, gc.component, userID).Scan(&guacUser, &encPw)
	if err == nil {
		pw, derr := gc.tokenCipher.Decrypt(encPw)
		if derr != nil {
			return "", "", fmt.Errorf("decrypt guac password: %w", derr)
		}
		if aerr := gc.ensureGuacAccount(ctx, guacUser, pw); aerr != nil { // self-heal drift
			return "", "", aerr
		}
		return guacUser, pw, nil
	}
	if err != pgx.ErrNoRows {
		return "", "", err
	}

	// 2. Derive the username from the OpenIDX user.
	var email, username string
	if uerr := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(email,''), COALESCE(username,'') FROM users WHERE id=$1 AND org_id=$2`,
		userID, orgID).Scan(&email, &username); uerr != nil {
		return "", "", fmt.Errorf("lookup user for guac identity: %w", uerr)
	}
	guacUser = guacUsernameFor(email, username, userID)

	pw, err := randomGuacPassword()
	if err != nil {
		return "", "", err
	}
	if aerr := gc.ensureGuacAccount(ctx, guacUser, pw); aerr != nil {
		return "", "", aerr
	}

	encPw, err = gc.tokenCipher.Encrypt(pw)
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO guacamole_users (org_id, user_id, broker, guac_username, guac_password_enc)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (broker, user_id) DO UPDATE SET updated_at = NOW()`,
		orgID, userID, gc.component, guacUser, encPw); err != nil {
		return "", "", err
	}
	return guacUser, pw, nil
}

// ensureGuacAccount creates the Guacamole account if absent (idempotent). New
// accounts get ZERO permissions — never any system/admin permission.
func (gc *GuacamoleClient) ensureGuacAccount(ctx context.Context, guacUser, password string) error {
	_, status, err := gc.apiRequest("GET", "/users/"+guacUser, nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		return nil
	}
	body := map[string]interface{}{
		"username":   guacUser,
		"password":   password,
		"attributes": map[string]string{},
	}
	resp, status, err := gc.apiRequest("POST", "/users", body)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusCreated {
		return nil
	}
	// Create race — another connect made it first.
	if status == http.StatusBadRequest && strings.Contains(strings.ToLower(string(resp)), "already exist") {
		return nil
	}
	return fmt.Errorf("guacamole create user %q: HTTP %d: %s", guacUser, status, string(resp))
}

// grantConnectionRead grants READ on connID to guacUser (JIT at connect).
func (gc *GuacamoleClient) grantConnectionRead(ctx context.Context, guacUser, connID string) error {
	return gc.patchConnectionPermission(ctx, guacUser, connID, "add")
}

// revokeConnectionRead removes READ on connID from guacUser (at session end).
func (gc *GuacamoleClient) revokeConnectionRead(ctx context.Context, guacUser, connID string) error {
	return gc.patchConnectionPermission(ctx, guacUser, connID, "remove")
}

func (gc *GuacamoleClient) patchConnectionPermission(ctx context.Context, guacUser, connID, op string) error {
	body := []map[string]string{
		{"op": op, "path": "/connectionPermissions/" + connID, "value": "READ"},
	}
	resp, status, err := gc.apiRequest("PATCH", "/users/"+guacUser+"/permissions", body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		if op == "remove" && status == http.StatusNotFound { // absent grant — no-op
			return nil
		}
		return fmt.Errorf("guacamole %s connectionPermission for %q: HTTP %d: %s", op, guacUser, status, string(resp))
	}
	return nil
}

// connectURLForBroker returns the browser connect URL and the per-user Guacamole
// username used (empty when the shared-admin path was used). When per-user
// identities are enabled it ensures the account, grants JIT READ on connID, and
// mints the token AS that account. On ANY provisioning error it logs and falls
// back to the legacy shared-admin URL so a session is never blocked by the new
// path.
func (s *Service) connectURLForBroker(ctx context.Context, gc *GuacamoleClient, orgID, userID, connID, clientIP string) (string, string) {
	if gc == nil || !gc.perUserIdentities {
		return gc.GetConnectionURLForClient(connID, clientIP), ""
	}
	guacUser, pw, err := s.ensureGuacUserRecord(ctx, gc, orgID, userID)
	if err != nil {
		s.logger.Warn("connectURLForBroker: per-user ensure failed; using shared token",
			zap.String("user_id", userID), zap.Error(err))
		return gc.GetConnectionURLForClient(connID, clientIP), ""
	}
	if err := gc.grantConnectionRead(ctx, guacUser, connID); err != nil {
		s.logger.Warn("connectURLForBroker: grant failed; using shared token",
			zap.String("guac_user", guacUser), zap.String("conn_id", connID), zap.Error(err))
		return gc.GetConnectionURLForClient(connID, clientIP), ""
	}
	url := gc.GetConnectionURLForUser(connID, guacUser, pw, clientIP)
	if url == "" {
		_ = gc.revokeConnectionRead(ctx, guacUser, connID) // clean up the just-granted READ
		return gc.GetConnectionURLForClient(connID, clientIP), ""
	}
	return url, guacUser
}

// resolveActiveSessionOwner maps an active-connection UUID to the per-user
// Guacamole account that owns it (guac_username, plaintext password), used to
// mint the owner-scoped read-only monitor share key. Resolves activeConnID →
// ConnectionIdentifier (via ListActiveSessions) → the newest active
// pam_entry_sessions.guac_username → guacamole_users password.
func (s *Service) resolveActiveSessionOwner(ctx context.Context, gc *GuacamoleClient, activeConnID string) (string, string, error) {
	sessions, err := gc.ListActiveSessions(ctx)
	if err != nil {
		return "", "", err
	}
	var connIdentifier string
	for _, sess := range sessions {
		if sess.Identifier == activeConnID {
			connIdentifier = sess.ConnectionIdentifier
			break
		}
	}
	if connIdentifier == "" {
		return "", "", fmt.Errorf("active connection %q not found", activeConnID)
	}

	var guacUser string
	if err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore pam_entry_sessions RLS enforces org scope via the request ctx; the lookup key is the global Guacamole connection identifier
		`SELECT guac_username FROM pam_entry_sessions
		  WHERE guac_connection_id = $1 AND guac_username IS NOT NULL
		  ORDER BY started_at DESC LIMIT 1`, connIdentifier).Scan(&guacUser); err != nil {
		return "", "", fmt.Errorf("resolve session owner username: %w", err)
	}

	var encPw string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT guac_password_enc FROM guacamole_users
		  WHERE broker = $1 AND guac_username = $2 LIMIT 1`, gc.component, guacUser).Scan(&encPw); err != nil {
		return "", "", fmt.Errorf("resolve session owner secret: %w", err)
	}
	pw, err := gc.tokenCipher.Decrypt(encPw)
	if err != nil {
		return "", "", err
	}
	return guacUser, pw, nil
}

// sweepStaleGuacGrants revokes per-connection READ for ended (or >12h stale
// active) PAM sessions so standing accounts don't accumulate access — the safety
// net for browser-closed sessions that never hit end/terminate. Re-revoking an
// already-absent grant is a tolerated 404 no-op, and only ended/stale rows are
// swept, so an active browser session is never cut mid-use. Runs under a
// bypass-RLS background context.
func (s *Service) sweepStaleGuacGrants(ctx context.Context) {
	//orgscope:ignore pam_entry_sessions,pam_entries cross-org maintenance sweep runs under a bypass-RLS background context
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT pes.guac_username, pes.guac_connection_id, COALESCE(e.reach_mode,'')
		  FROM pam_entry_sessions pes JOIN pam_entries e ON e.id = pes.entry_id
		 WHERE pes.guac_username IS NOT NULL AND pes.guac_connection_id IS NOT NULL
		   AND (pes.status <> 'active' OR pes.started_at < NOW() - INTERVAL '12 hours')
		 LIMIT 200`)
	if err != nil {
		s.logger.Warn("sweepStaleGuacGrants: query failed", zap.Error(err))
		return
	}
	type g struct{ user, conn, reach string }
	var targets []g
	for rows.Next() {
		var t g
		if rows.Scan(&t.user, &t.conn, &t.reach) == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()
	for _, t := range targets {
		if b := s.brokerFor(t.reach); b != nil && b.perUserIdentities {
			_ = b.revokeConnectionRead(ctx, t.user, t.conn)
		}
	}
}

// sweepDeprovisionGuacUsers deletes the Guacamole account + guacamole_users row
// for any mapping whose OpenIDX user is disabled or gone. Deleting the account
// cascades its connectionPermissions in the postgres auth backend, so lingering
// grants die with it. Runs under a bypass-RLS background context.
func (s *Service) sweepDeprovisionGuacUsers(ctx context.Context) {
	//orgscope:ignore users,guacamole_users cross-org maintenance sweep runs under a bypass-RLS background context
	rows, err := s.db.Pool.Query(ctx, `
		SELECT gu.id, gu.broker, gu.guac_username
		  FROM guacamole_users gu LEFT JOIN users u ON u.id = gu.user_id
		 WHERE u.id IS NULL OR u.enabled = false
		 LIMIT 100`)
	if err != nil {
		s.logger.Warn("sweepDeprovisionGuacUsers: query failed", zap.Error(err))
		return
	}
	type d struct{ rowID, broker, guacUser string }
	var targets []d
	for rows.Next() {
		var t d
		if rows.Scan(&t.rowID, &t.broker, &t.guacUser) == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()
	for _, t := range targets {
		var b *GuacamoleClient
		if t.broker == "guacamole-ziti" {
			b = s.guacamoleZitiClient
		} else {
			b = s.guacamoleClient
		}
		if b == nil {
			continue
		}
		_, status, derr := b.apiRequest("DELETE", "/users/"+t.guacUser, nil)
		if derr == nil && (status/100 == 2 || status == http.StatusNotFound) {
			if _, err := s.db.Pool.Exec(ctx, `DELETE FROM guacamole_users WHERE id = $1`, t.rowID); err != nil {
				s.logger.Warn("sweepDeprovisionGuacUsers: row delete failed", zap.String("row", t.rowID), zap.Error(err))
			}
		}
	}
}

// StartGuacGrantSweeper runs the stale-grant + deprovision sweeps every 5 minutes
// under a bypass-RLS context. Started only when a broker has per-user identities.
func (s *Service) StartGuacGrantSweeper(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepStaleGuacGrants(ctx)
				s.sweepDeprovisionGuacUsers(ctx)
			}
		}
	}()
}

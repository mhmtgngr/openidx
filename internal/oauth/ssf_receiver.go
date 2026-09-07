package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// SSF receiver: accept a pushed SET (RFC 8935) from an upstream transmitter,
// validate it, and apply the CAEP event. The differentiating actuator is
// network termination: a session-revoked signal severs the subject's OpenIDX
// sessions (which the access-proxy + continuous-verify honor to cut the user off
// the Ziti overlay), not just a token flag.

// SSFReceiverConfig configures trust for inbound SETs. Set via env
// SSF_RECEIVER_ISSUER + SSF_RECEIVER_JWKS_URL to accept a specific upstream.
type SSFReceiverConfig struct {
	Issuer  string
	JWKSURL string
}

// handleSSFReceive is POST /ssf/events — the push delivery endpoint.
func (s *Service) handleSSFReceive(c *gin.Context) {
	if !strings.Contains(c.GetHeader("Content-Type"), "secevent+jwt") &&
		!strings.Contains(c.GetHeader("Content-Type"), "application/jwt") {
		// Be lenient: some transmitters omit the media type. Only reject clearly
		// wrong bodies below when parsing fails.
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"err": "invalid_request", "description": "empty body"})
		return
	}
	setJWT := strings.TrimSpace(string(body))

	claims, err := s.validateInboundSET(c.Request.Context(), setJWT)
	if err != nil {
		s.logger.Warn("SSF receive: SET validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"err": "authentication_failed", "description": err.Error()})
		return
	}

	jti, _ := claims["jti"].(string)
	issuer, _ := claims["iss"].(string)
	if jti == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err": "invalid_request", "description": "missing jti"})
		return
	}

	// The organization this event is applied in. resolveUserBySubject and
	// applyCAEPEvent have always read it and refused without it, so the EFFECT of
	// an inbound SET was already scoped; until v172 the ledger row recording it
	// was not, because nothing ever wrote org_id. Resolving it here, once, means
	// the record and the effect name the same tenant.
	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		s.logger.Warn("SSF receive: no organization on the request; refusing to apply",
			zap.String("jti", jti), zap.String("issuer", issuer))
		c.JSON(http.StatusBadRequest, gin.H{"err": "invalid_request", "description": "no organization for this receiver"})
		return
	}

	// Dedup: if we already applied this jti FOR THIS TENANT, ack without
	// re-applying. Before v172 jti was the table's install-wide primary key, so
	// this read and the key it rests on now agree.
	//
	// The read half of the replay protection had the same defect the write half
	// below is documented as having had: the error was discarded. No row is the
	// NORMAL answer here and arrives as pgx.ErrNoRows, so the two had to be told
	// apart -- and anything else means the dedup did not run. Applying a
	// Security Event Token you cannot check for replay is the unsafe direction,
	// so it is refused rather than applied a second time.
	var exists bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT true FROM ssf_received_events WHERE jti=$1 AND org_id=$2`, jti, org.ID).Scan(&exists); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("SSF replay check failed; refusing the event rather than applying it twice",
			zap.String("jti", jti), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"err": "temporarily_unavailable", "description": "replay check unavailable"})
		return
	}
	if exists {
		c.JSON(http.StatusAccepted, gin.H{"status": "accepted"})
		return
	}

	eventType, subject, eventClaims := extractCAEPEvent(claims)
	outcome, detail := s.applyCAEPEvent(c.Request.Context(), eventType, subject, eventClaims)

	// This write is the replay protection: the event has already been applied
	// above, so a failure here means the next re-delivery of the same SET applies
	// it a second time. It used to be discarded with `_, _ =`, which is how a
	// stale test fixture presented as a missing row rather than as an error.
	if _, err := s.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO ssf_received_events (jti, org_id, issuer, event_type, subject, outcome, detail)
        VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (org_id, jti) DO NOTHING`,
		jti, org.ID, ssfNullIfEmpty(issuer), ssfNullIfEmpty(eventType), ssfNullIfEmpty(subject), outcome, ssfNullIfEmpty(detail),
	); err != nil {
		s.logger.Error("SSF receive: event applied but NOT recorded; a re-delivery will apply it again",
			zap.String("jti", jti), zap.String("event", eventType), zap.Error(err))
	}

	s.logger.Info("SSF receive: event applied",
		zap.String("event", eventType), zap.String("subject", subject),
		zap.String("outcome", outcome), zap.String("issuer", issuer))

	// RFC 8935: 202 Accepted acknowledges receipt.
	c.JSON(http.StatusAccepted, gin.H{"status": "accepted"})
}

// validateInboundSET parses + verifies the SET signature against the configured
// upstream issuer's JWKS, or (when the issuer is this service) our own keys.
func (s *Service) validateInboundSET(ctx context.Context, setJWT string) (jwt.MapClaims, error) {
	// Parse unverified to read the issuer, then choose the key source.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	unverified, _, err := parser.ParseUnverified(setJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse SET: %w", err)
	}
	uc, _ := unverified.Claims.(jwt.MapClaims)
	iss, _ := uc["iss"].(string)

	cfg := s.ssfReceiverConfig
	keyfunc := s.verificationKeyfunc
	if iss != "" && iss == cfg.Issuer && cfg.JWKSURL != "" {
		// Trusted external issuer: verify against its JWKS.
		keyfunc = s.jwksKeyfunc(ctx, cfg.JWKSURL)
	} else if iss != s.issuer {
		return nil, fmt.Errorf("untrusted SET issuer %q", iss)
	}

	parsed, err := jwt.Parse(setJWT, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid SET")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid SET claims")
	}
	return claims, nil
}

// jwksKeyfunc returns a jwt.Keyfunc that resolves the token's kid against the
// issuer's JWKS (fetched fresh; small and cache-free for correctness).
func (s *Service) jwksKeyfunc(ctx context.Context, jwksURL string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch jwks: %w", err)
		}
		defer resp.Body.Close()
		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			return nil, fmt.Errorf("decode jwks: %w", err)
		}
		for _, k := range jwks.Keys {
			if kid != "" && k.Kid != kid {
				continue
			}
			pub, err := parseJWKRSA(k.N, k.E)
			if err == nil {
				return pub, nil
			}
		}
		return nil, fmt.Errorf("no matching jwk for kid %q", kid)
	}
}

// extractCAEPEvent pulls the first event type + subject + claims from a SET's
// events map.
func extractCAEPEvent(claims jwt.MapClaims) (eventType, subject string, eventClaims map[string]interface{}) {
	events, ok := claims["events"].(map[string]interface{})
	if !ok {
		return "", "", nil
	}
	for et, payload := range events {
		eventType = et
		if pm, ok := payload.(map[string]interface{}); ok {
			eventClaims = pm
			if subj, ok := pm["subject"].(map[string]interface{}); ok {
				if email, ok := subj["email"].(string); ok {
					subject = email
				} else if id, ok := subj["id"].(string); ok {
					subject = id
				} else if sub, ok := subj["sub"].(string); ok {
					subject = sub
				}
			}
		}
		break // first event only
	}
	return eventType, subject, eventClaims
}

// applyCAEPEvent enforces an inbound CAEP/RISC event locally. The headline
// behavior: a session-revoked / account-disabled event severs the subject's
// OpenIDX sessions, which the access-proxy + continuous-verify honor to cut the
// user off the Ziti overlay.
func (s *Service) applyCAEPEvent(ctx context.Context, eventType, subject string, eventClaims map[string]interface{}) (outcome, detail string) {
	switch eventType {
	case EventSessionRevoked, EventAccountDisabled, EventAccountPurged, EventCredentialChange:
		if subject == "" {
			return "ignored", "no subject"
		}
		userID := s.resolveUserBySubject(ctx, subject)
		if userID == "" {
			return "ignored", "subject not found locally"
		}
		// Revoke all sessions (Redis markers the proxy honors) + refresh tokens.
		if err := s.revokeAllUserSessions(ctx, userID); err != nil {
			return "error", err.Error()
		}
		_ = s.revokeAllUserRefreshTokens(ctx, userID)
		// Account-disabled/purged also disables the local account.
		if eventType == EventAccountDisabled || eventType == EventAccountPurged {
			if org, oerr := orgctx.From(ctx); oerr == nil {
				_, _ = s.db.Pool.Exec(ctx,
					`UPDATE users SET enabled=false, updated_at=NOW() WHERE id=$1 AND org_id=$2`, userID, org.ID)
			}
		}
		return "applied", fmt.Sprintf("revoked sessions for user %s", userID)
	default:
		return "ignored", "unsupported event type"
	}
}

// resolveUserBySubject maps a SET subject (email or user id) to a local user id.
func (s *Service) resolveUserBySubject(ctx context.Context, subject string) string {
	org, err := orgctx.From(ctx)
	if err != nil {
		return ""
	}
	var userID string
	if strings.Contains(subject, "@") {
		_ = s.db.Pool.QueryRow(ctx,
			`SELECT id FROM users WHERE lower(email)=lower($1) AND org_id=$2`, subject, org.ID).Scan(&userID)
	} else {
		_ = s.db.Pool.QueryRow(ctx,
			`SELECT id FROM users WHERE id::text=$1 AND org_id=$2`, subject, org.ID).Scan(&userID)
	}
	return userID
}

// parseJWKRSA builds an *rsa.PublicKey from base64url modulus + exponent.
func parseJWKRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, err
	}
	eInt := 0
	for _, b := range e {
		eInt = eInt<<8 | int(b)
	}
	if eInt == 0 {
		eInt = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: eInt}, nil
}

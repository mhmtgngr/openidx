// Package access — the watermark over a privileged session (migration 242).
//
// The OpenIDX session window draws the watermark over the broker's frame, so
// a screenshot or a photo of a privileged session carries the name of the
// person who ran it. The text is composed here, from the users row and the
// session id, and handed to the window with the connect URL: the browser does
// not choose what it says. An external user's session is always watermarked
// (I7 of the third-party access framework is the hardening; this is its
// visible half); an internal user's when the organization's policy asks.
//
// It is a deterrent, not enforcement: anything drawn in a browser can be
// hidden by its user. The recording is the record.
package access

import (
	"context"
	"strings"
	"time"
)

// pamWatermark is what the session window draws.
type pamWatermark struct {
	Text string `json:"text"`
}

// pamWatermarkFor composes the watermark for a launch, or nil when none is
// due. A user who cannot be read still gets the user id: a watermark that
// names somebody is the point, and an empty one would be no watermark.
func (s *Service) pamWatermarkFor(ctx context.Context, orgID, userID, sessionID string, external bool, pol PamPolicy) *pamWatermark {
	if !external && !pol.WatermarkInternal {
		return nil
	}
	who := userID
	if s.db != nil && s.db.Pool != nil && userID != "" {
		var username, email string
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(username, ''), COALESCE(email, '') FROM users WHERE id = $1::uuid AND org_id = $2::uuid`,
			userID, orgID).Scan(&username, &email); err == nil {
			switch {
			case email != "":
				who = email
			case username != "":
				who = username
			}
		}
	}
	parts := []string{who}
	if sessionID != "" {
		parts = append(parts, "session "+shortID(sessionID))
	}
	parts = append(parts, time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	return &pamWatermark{Text: strings.Join(parts, " · ")}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

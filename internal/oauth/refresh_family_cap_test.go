package oauth

import (
	"net/url"
	"testing"
	"time"
)

// The limit that never bound.
//
// oauth_clients.refresh_token_lifetime is enforced — GetRefreshToken refuses a
// token past its expires_at — and rotation issues each successor with
// `now + lifetime`. So the window restarts on every use, and every native client
// refreshes far more often than the window: the desktop agent hourly, the phone
// whenever it opens. The thirty days the native clients were seeded with
// therefore bound only on a device that went DARK for thirty days, which is the
// opposite of the case the number exists for. A phone taken while unlocked kept
// a working chain for as long as it kept refreshing.
//
// These cases are about the family, not the token: how long an AUTHORIZATION
// may be stretched by continuous use. The first is the one that would have
// failed before v187 — it rotates the chain forward past the cap, exactly as a
// device in use does, and requires the refusal anyway.

// capFixture seeds a client with a family cap and a chain whose origin is under
// the caller's control, which is what makes "old family, fresh token" — the
// state a live device is always in — expressible.
func (f *refreshGrantFixture) seedCappedClient(t *testing.T, clientID, secret string, maxLifetime int) {
	t.Helper()
	f.seedClient(t, clientID, secret, true)
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE oauth_clients SET refresh_token_max_lifetime = $2 WHERE client_id = $1 AND org_id = $3`,
		clientID, maxLifetime, grantOrg); err != nil {
		t.Fatalf("set cap on %s: %v", clientID, err)
	}
}

// mintRefreshInFamilyStartedAt writes a token whose FAMILY began at the given
// time while the token itself is brand new — the shape every rotated chain has,
// and the one a per-token expiry cannot see.
func (f *refreshGrantFixture) mintRefreshInFamilyStartedAt(t *testing.T, tok, clientID, family string, started time.Time) {
	t.Helper()
	rt := &RefreshToken{
		Token:           tok,
		ClientID:        clientID,
		UserID:          grantUser,
		Scope:           "openid offline_access",
		FamilyID:        family,
		ExpiresAt:       time.Now().Add(14 * 24 * time.Hour),
		CreatedAt:       time.Now(),
		FamilyStartedAt: started,
	}
	if err := f.svc.CreateRefreshToken(f.ctx, rt); err != nil {
		t.Fatalf("mint refresh token %s: %v", tok, err)
	}
}

func TestRefreshFamilyCap(t *testing.T) {
	f := newRefreshGrantFixture(t)
	f.seedCappedClient(t, "capped", "capped-secret", 90*24*3600) // 90 days

	t.Run("a fresh token in a family past its cap is refused", func(t *testing.T) {
		const family = "11111111-1111-1111-1111-111111111111"
		f.mintRefreshInFamilyStartedAt(t, "cap-expired", "capped", family,
			time.Now().Add(-91*24*time.Hour))

		w, body := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"cap-expired"},
		}, "capped", "capped-secret")

		if w.Code != 400 {
			t.Fatalf("status %d, want 400: a family past its cap must not mint anything.\n%v", w.Code, body)
		}
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
		// The token itself is nowhere near its own expiry — that is the point.
		// Per-token expiry would have let this through.
		if body["access_token"] != nil {
			t.Error("an access token was minted for a family past its cap")
		}
	})

	t.Run("and the whole family is revoked, not just the token presented", func(t *testing.T) {
		const family = "22222222-2222-2222-2222-222222222222"
		f.mintRefreshInFamilyStartedAt(t, "cap-old-sibling", "capped", family,
			time.Now().Add(-91*24*time.Hour))
		f.mintRefreshInFamilyStartedAt(t, "cap-presented", "capped", family,
			time.Now().Add(-91*24*time.Hour))

		if w, _ := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"cap-presented"},
		}, "capped", "capped-secret"); w.Code != 400 {
			t.Fatalf("status %d, want 400", w.Code)
		}

		// Revoking only the presented token would leave every earlier entry in
		// the chain as a live way back in for whoever is holding one.
		for _, tok := range []string{"cap-presented", "cap-old-sibling"} {
			if _, revoked := f.tokenState(t, tok); !revoked {
				t.Errorf("%s is still live after its family passed the cap", tok)
			}
		}
	})

	t.Run("a family inside its cap still refreshes", func(t *testing.T) {
		const family = "33333333-3333-3333-3333-333333333333"
		f.mintRefreshInFamilyStartedAt(t, "cap-young", "capped", family,
			time.Now().Add(-30*24*time.Hour))

		w, body := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"cap-young"},
		}, "capped", "capped-secret")

		if w.Code != 200 {
			t.Fatalf("status %d, want 200: a 30-day-old family under a 90-day cap must refresh.\n%v", w.Code, body)
		}
		if body["refresh_token"] == nil {
			t.Fatal("no rotated refresh token in the response")
		}
	})

	t.Run("rotation carries the origin forward rather than restarting it", func(t *testing.T) {
		// This is the case that decides whether the cap can bind at all. If the
		// successor's family_started_at were set to now, every refresh would
		// reset the clock and the cap would be exactly as unreachable as the
		// per-token lifetime it replaces.
		const family = "44444444-4444-4444-4444-444444444444"
		started := time.Now().Add(-89 * 24 * time.Hour)
		f.mintRefreshInFamilyStartedAt(t, "cap-rotating", "capped", family, started)

		_, body := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"cap-rotating"},
		}, "capped", "capped-secret")
		rotated, _ := body["refresh_token"].(string)
		if rotated == "" {
			t.Fatalf("no rotated token to inspect: %v", body)
		}

		var got time.Time
		if err := f.db.Pool.QueryRow(f.ctx,
			"SELECT family_started_at FROM oauth_refresh_tokens WHERE token = $1", rotated).Scan(&got); err != nil {
			t.Fatalf("read the successor's family_started_at: %v", err)
		}
		if drift := got.Sub(started); drift < -time.Minute || drift > time.Minute {
			t.Fatalf("the successor's family started at %s, want the family's own origin %s "+
				"(drift %s). Rotation reset the clock, so the cap can never be reached.",
				got, started, drift)
		}

		// And the successor is refused once the family is past the cap, which is
		// the same chain one day later.
		if _, err := f.db.Pool.Exec(f.ctx,
			"UPDATE oauth_refresh_tokens SET family_started_at = $2 WHERE token = $1",
			rotated, time.Now().Add(-91*24*time.Hour)); err != nil {
			t.Fatalf("age the successor's family: %v", err)
		}
		if w, _ := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rotated},
		}, "capped", "capped-secret"); w.Code != 400 {
			t.Errorf("the rotated successor status %d, want 400 once its family is past the cap", w.Code)
		}
	})

	t.Run("an uncapped client is unaffected however old its family is", func(t *testing.T) {
		// Browser clients carry no cap on purpose: their token lives in a
		// browser rather than at rest on a device someone can pick up, and
		// capping the console would sign administrators out on a schedule
		// nobody asked for. A cap that leaked onto them would do exactly that.
		const family = "55555555-5555-5555-5555-555555555555"
		f.mintRefreshInFamilyStartedAt(t, "uncapped-ancient", "app", family,
			time.Now().Add(-5*365*24*time.Hour))

		w, body := f.post(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"uncapped-ancient"},
		}, "app", "s3cret")

		if w.Code != 200 {
			t.Fatalf("status %d, want 200: a client with no cap must not be capped.\n%v", w.Code, body)
		}
	})
}

// TestRefreshFamilyOriginDoesNotMoveWithCreatedAt states the invariant the whole
// mechanism rests on, at the level of the store rather than the handler:
// CreateRefreshToken must NOT overwrite an origin it was given.
func TestRefreshFamilyOriginDoesNotMoveWithCreatedAt(t *testing.T) {
	f := newRefreshGrantFixture(t)
	origin := time.Now().Add(-45 * 24 * time.Hour).UTC().Truncate(time.Second)

	if err := f.svc.CreateRefreshToken(f.ctx, &RefreshToken{
		Token:           "origin-kept",
		ClientID:        "app",
		UserID:          grantUser,
		Scope:           "openid offline_access",
		FamilyID:        "66666666-6666-6666-6666-666666666666",
		ExpiresAt:       time.Now().Add(time.Hour),
		FamilyStartedAt: origin,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := f.svc.GetRefreshToken(f.ctx, "origin-kept")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if drift := got.FamilyStartedAt.Sub(origin); drift < -time.Second || drift > time.Second {
		t.Errorf("family origin read back as %s, want %s", got.FamilyStartedAt, origin)
	}

	// And a token given no origin starts its own family now, rather than at the
	// zero time — which would put every new family instantly past any cap.
	if err := f.svc.CreateRefreshToken(f.ctx, &RefreshToken{
		Token:     "origin-defaulted",
		ClientID:  "app",
		UserID:    grantUser,
		Scope:     "openid offline_access",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	fresh, err := f.svc.GetRefreshToken(f.ctx, "origin-defaulted")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if time.Since(fresh.FamilyStartedAt) > time.Minute {
		t.Errorf("a new family's origin is %s, which is not now; every new chain "+
			"would start already expired under any cap", fresh.FamilyStartedAt)
	}
}

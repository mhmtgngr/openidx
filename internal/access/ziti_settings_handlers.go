package access

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// validateZitiConnSettings rejects obviously-broken connection settings at
// save time, so a typo'd controller URL can't be persisted silently and only
// discovered at the next (failing) connect.
func validateZitiConnSettings(in ZitiConnSettingsView) string {
	if in.ControllerURL == "" {
		return "controller_url is required"
	}
	u, err := url.Parse(in.ControllerURL)
	if err != nil || u.Host == "" {
		return "controller_url must be a valid URL (e.g. https://ziti-controller:1280)"
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "controller_url scheme must be https (or http for a lab)"
	}
	if in.AdminUser == "" {
		return "admin_user is required"
	}
	return ""
}

// requireAdminRole guards the access-service admin surface (Ziti connection
// management, PAM entry/folder/grant CRUD, guacamole credentials, temp-access,
// …). The router always attaches an auth middleware that sets "roles" from a
// verified JWT (AuthWithAPIKey in prod, SoftAuth in dev), so this enforces an
// admin role by default in EVERY environment. The all-callers-are-admin dev
// convenience is now an explicit opt-in (DevAdminBypass) — it is NOT implied by
// APP_ENV=development, so a box left in dev mode does not silently expose these
// mutations to anonymous callers.
func (s *Service) requireAdminRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.config != nil && s.config.DevAdminBypass {
			c.Next()
			return
		}
		if rolesRaw, ok := c.Get("roles"); ok {
			if roles, ok := rolesRaw.([]string); ok {
				for _, r := range roles {
					if r == "admin" || r == "super_admin" {
						c.Next()
						return
					}
				}
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
	}
}

// buildZitiConnParams resolves the effective connection: DB settings win, else
// env (cfg.Ziti*). Returns the decrypted plaintext password.
func (s *Service) buildZitiConnParams(ctx context.Context) (ctrlURL, user, pwd, dir string, insecure, enabled bool, err error) {
	ctx = orgctx.WithBypassRLS(ctx)
	if st, ok, lerr := loadZitiConnSettings(ctx, s.db); lerr == nil && ok {
		p, derr := st.decryptPassword(s.config.EncryptionKey)
		if derr != nil {
			return "", "", "", "", false, false, derr
		}
		return st.ControllerURL, st.AdminUser, p, st.IdentityDir, st.InsecureSkipVerify, st.Enabled, nil
	}
	// Env fallback (Phase-1 path).
	return s.config.ZitiCtrlURL, s.config.ZitiAdminUser, s.config.ZitiAdminPassword,
		s.config.ZitiIdentityDir, s.config.ZitiInsecureSkipVerify, s.config.ZitiEnabled, nil
}

// handleGetZitiSettings returns the stored connection (password masked), or an
// env-derived default when nothing is persisted yet.
func (s *Service) handleGetZitiSettings(c *gin.Context) {
	ctx := orgctx.WithBypassRLS(c.Request.Context())
	if st, ok, err := loadZitiConnSettings(ctx, s.db); err == nil && ok {
		c.JSON(http.StatusOK, st.View())
		return
	}
	// Default view from env so the form is pre-filled on first use.
	c.JSON(http.StatusOK, ZitiConnSettingsView{
		Enabled:            s.config.ZitiEnabled,
		ControllerURL:      s.config.ZitiCtrlURL,
		AdminUser:          s.config.ZitiAdminUser,
		AdminPassword:      "",
		IdentityDir:        s.config.ZitiIdentityDir,
		InsecureSkipVerify: s.config.ZitiInsecureSkipVerify,
	})
}

// handlePutZitiSettings persists the connection (does not reconnect).
func (s *Service) handlePutZitiSettings(c *gin.Context) {
	var in ZitiConnSettingsView
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateZitiConnSettings(in); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	ctx := orgctx.WithBypassRLS(c.Request.Context())
	if err := saveZitiConnSettings(ctx, s.db, s.config.EncryptionKey, in, uid); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("put ziti settings", err), s.logger)
		return
	}
	if st, _, err := loadZitiConnSettings(ctx, s.db); err == nil {
		c.JSON(http.StatusOK, st.View())
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": true})
}

// handleTestZitiSettings dry-runs a connection against the candidate settings
// WITHOUT touching the live manager or the real identity dir: it builds a
// throwaway manager in a temp identity dir, fetches the controller version,
// then tears it down.
func (s *Service) handleTestZitiSettings(c *gin.Context) {
	var in ZitiConnSettingsView
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// If the password came back masked, use the stored one.
	pwd := in.AdminPassword
	if pwd == "" || pwd == maskedSecret {
		ctx := orgctx.WithBypassRLS(c.Request.Context())
		if st, ok, _ := loadZitiConnSettings(ctx, s.db); ok {
			if p, err := st.decryptPassword(s.config.EncryptionKey); err == nil {
				pwd = p
			}
		}
	}
	tmpDir, err := os.MkdirTemp("", "ziti-test-*")
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("test ziti settings", err), s.logger)
		return
	}
	defer os.RemoveAll(tmpDir)

	zm, err := NewZitiManagerWithConn(s.config, in.ControllerURL, in.AdminUser, pwd, tmpDir, in.InsecureSkipVerify, s.db, s.logger)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"reachable": false, "authenticated": false, "error": err.Error()})
		return
	}
	defer zm.Close()
	ver, verr := zm.GetControllerVersion(c.Request.Context())
	if verr != nil {
		c.JSON(http.StatusOK, gin.H{"reachable": false, "authenticated": true, "error": verr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reachable": true, "authenticated": true, "controller_version": ver})
}

// handleZitiConnect (re)builds the live manager from the persisted/env settings
// and swaps it in with no restart. Serialized via the provider's op lock.
func (s *Service) handleZitiConnect(c *gin.Context) {
	p := s.zitiProvider
	if p == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ziti provider not initialized"})
		return
	}
	p.Lock()
	defer p.Unlock()

	ctx := orgctx.WithBypassRLS(c.Request.Context())
	ctrlURL, user, pwd, dir, insecure, _, perr := s.buildZitiConnParams(ctx)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": perr.Error()})
		return
	}
	if ctrlURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "controller_url not set"})
		return
	}

	// If the controller changed, drop the stale access-proxy identity so it
	// re-enrolls against the new controller.
	if cur := p.Get(); cur != nil {
		if prevURL := cur.cfg.ZitiCtrlURL; prevURL != "" && prevURL != ctrlURL {
			_ = os.Remove(filepath.Join(dir, "access-proxy.json"))
		}
	}

	zm, err := NewZitiManagerWithConn(s.config, ctrlURL, user, pwd, dir, insecure, s.db, s.logger)
	if err != nil {
		s.logger.Error("Ziti controller connection test failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "connect failed: could not reach the Ziti controller (see server logs for details)"})
		return
	}

	// Fresh monitor context; cancel rides with the slot so Swap can stop it.
	mctx, cancel := context.WithCancel(context.Background())
	zm.StartHealthMonitor(mctx)
	zm.StartCertificateMonitor(mctx)
	zm.StartUserSyncPoller(mctx)
	zm.StartPostureResultExpiryChecker(mctx)
	// Reconciler mode: the reconciler (running on a swap-surviving context)
	// stays the sole mutator — wake it to converge routes against the fresh
	// manager. Only the legacy imperative path hosts directly.
	if s.zitiReconciler == nil {
		go zm.HostAllServices(mctx)
	}
	p.Swap(zm, cancel)
	s.enqueueReconcile()

	// Persist enabled=true.
	if st, ok, _ := loadZitiConnSettings(ctx, s.db); ok {
		st.Enabled = true
		_ = saveZitiConnSettings(ctx, s.db, s.config.EncryptionKey, st.View(), "")
	}
	s.logger.Info("OpenZiti connected via admin panel", zap.String("controller", ctrlURL))
	s.handleZitiStatus(c)
}

// handleZitiDisconnect tears down the live manager (stops monitors + listeners)
// and persists enabled=false. No restart.
func (s *Service) handleZitiDisconnect(c *gin.Context) {
	p := s.zitiProvider
	if p == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	p.Lock()
	defer p.Unlock()
	p.Swap(nil, nil)

	ctx := orgctx.WithBypassRLS(c.Request.Context())
	if st, ok, _ := loadZitiConnSettings(ctx, s.db); ok {
		st.Enabled = false
		_ = saveZitiConnSettings(ctx, s.db, s.config.EncryptionKey, st.View(), "")
	}
	s.logger.Info("OpenZiti disconnected via admin panel")
	c.JSON(http.StatusOK, gin.H{"enabled": false, "message": "disconnected"})
}

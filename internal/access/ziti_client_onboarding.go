package access

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Client Onboarding & Enrollment Analytics API
// Makes OpenZiti easy to install and manage for end-users and admins
// ---------------------------------------------------------------------------

// ClientPlatform represents a supported tunneler/client download
type ClientPlatform struct {
	Platform    string `json:"platform"`
	Name        string `json:"name"`
	Description string `json:"description"`
	DownloadURL string `json:"download_url"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	FileType    string `json:"file_type"`
	SetupSteps  []string `json:"setup_steps"`
}

// EnrollmentAnalytics provides enrollment metrics
type EnrollmentAnalytics struct {
	TotalUsers      int     `json:"total_users"`
	TotalIdentities int     `json:"total_identities"`
	Enrolled        int     `json:"enrolled"`
	Pending         int     `json:"pending"`
	Unsynced        int     `json:"unsynced"`
	EnrollmentRate  float64 `json:"enrollment_rate"`
	RecentEnrolled  int     `json:"recent_enrolled"`
	StaleIdentities int     `json:"stale_identities"`
}

// OnboardingStatus is per-user setup progress
type OnboardingStatus struct {
	HasIdentity  bool   `json:"has_identity"`
	IsEnrolled   bool   `json:"is_enrolled"`
	HasServices  bool   `json:"has_services"`
	IdentityName string `json:"identity_name,omitempty"`
	EnrollmentJWT string `json:"enrollment_jwt,omitempty"`
	SetupStep    int    `json:"setup_step"` // 0=no identity, 1=identity created, 2=jwt available, 3=enrolled, 4=connected
	SetupMessage string `json:"setup_message"`
}

// ---------------------------------------------------------------------------
// GET /api/v1/access/ziti/client-platforms
// Returns available tunneler downloads per platform
// ---------------------------------------------------------------------------

func (s *Service) handleGetClientPlatforms(c *gin.Context) {
	platforms := []ClientPlatform{
		{
			Platform:    "windows",
			Name:        "Ziti Desktop Edge for Windows",
			Description: "Windows desktop tunneler with system tray integration",
			DownloadURL: "https://github.com/openziti/desktop-edge-win/releases/latest",
			Version:     "latest",
			Arch:        "x86_64",
			FileType:    ".exe",
			SetupSteps: []string{
				"Download and run the installer (.exe)",
				"Open Ziti Desktop Edge from the system tray",
				"Click 'Add Identity' and select your .jwt file",
				"Wait for enrollment to complete — you're connected!",
			},
		},
		{
			Platform:    "macos",
			Name:        "Ziti Desktop Edge for macOS",
			Description: "macOS tunneler with menu bar integration",
			DownloadURL: "https://github.com/openziti/desktop-edge-mac/releases/latest",
			Version:     "latest",
			Arch:        "universal",
			FileType:    ".pkg",
			SetupSteps: []string{
				"Download and install the .pkg file",
				"Open Ziti Desktop Edge from the menu bar",
				"Click 'Add Identity' and select your .jwt file",
				"Approve the network extension when prompted",
				"Wait for enrollment — you're connected!",
			},
		},
		{
			Platform:    "linux",
			Name:        "Ziti Edge Tunnel for Linux",
			Description: "CLI-based tunneler for Linux workstations and servers",
			DownloadURL: "https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest",
			Version:     "latest",
			Arch:        "x86_64 / arm64",
			FileType:    "deb / rpm / binary",
			SetupSteps: []string{
				"Install via package manager: apt install ziti-edge-tunnel (Debian/Ubuntu) or dnf install ziti-edge-tunnel (RHEL/Fedora)",
				"Save your .jwt file to /opt/openziti/etc/identities/",
				"Run: sudo ziti-edge-tunnel enroll --jwt /path/to/identity.jwt --identity /opt/openziti/etc/identities/identity.json",
				"Start the service: sudo systemctl enable --now ziti-edge-tunnel",
			},
		},
		{
			Platform:    "mobile-ios",
			Name:        "Ziti Mobile Edge for iOS",
			Description: "iOS tunneler for iPhone and iPad",
			DownloadURL: "https://apps.apple.com/app/ziti-mobile-edge/id1460484353",
			Version:     "latest",
			Arch:        "universal",
			FileType:    "App Store",
			SetupSteps: []string{
				"Install from the App Store",
				"Open the app and tap 'Add Identity'",
				"Scan the QR code or paste the JWT token",
				"Allow the VPN configuration when prompted",
			},
		},
		{
			Platform:    "mobile-android",
			Name:        "Ziti Mobile Edge for Android",
			Description: "Android tunneler for phones and tablets",
			DownloadURL: "https://play.google.com/store/apps/details?id=org.openziti.mobile",
			Version:     "latest",
			Arch:        "universal",
			FileType:    "Play Store",
			SetupSteps: []string{
				"Install from Google Play Store",
				"Open the app and tap 'Add Identity'",
				"Scan the QR code or paste the JWT token",
				"Allow the VPN configuration when prompted",
			},
		},
		{
			Platform:    "browser",
			Name:        "BrowZer (Browser-based, no install)",
			Description: "Access services directly in the browser — zero client install required",
			DownloadURL: "",
			Version:     "built-in",
			Arch:        "any",
			FileType:    "none",
			SetupSteps: []string{
				"No installation needed — BrowZer runs in your browser",
				"Navigate to the BrowZer-enabled service URL provided by your admin",
				"Sign in with your organization credentials (SSO)",
				"You're connected! The service loads directly in your browser.",
			},
		},
	}

	// Filter by platform if requested
	if platform := c.Query("platform"); platform != "" {
		filtered := []ClientPlatform{}
		for _, p := range platforms {
			if strings.EqualFold(p.Platform, platform) {
				filtered = append(filtered, p)
			}
		}
		c.JSON(http.StatusOK, gin.H{"platforms": filtered})
		return
	}

	c.JSON(http.StatusOK, gin.H{"platforms": platforms})
}

// ---------------------------------------------------------------------------
// GET /api/v1/access/ziti/enrollment-analytics
// Admin endpoint: enrollment metrics for dashboard
// ---------------------------------------------------------------------------

func (s *Service) handleGetEnrollmentAnalytics(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var analytics EnrollmentAnalytics

	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM users WHERE status = 'active'`).Scan(&analytics.TotalUsers)

	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities`).Scan(&analytics.TotalIdentities)

	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = true`).Scan(&analytics.Enrolled)

	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = false`).Scan(&analytics.Pending)

	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM users u LEFT JOIN ziti_identities z ON z.user_id = u.id WHERE z.id IS NULL AND u.status = 'active'`).Scan(&analytics.Unsynced)

	// Recently enrolled (last 7 days)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = true AND updated_at > NOW() - INTERVAL '7 days'`).Scan(&analytics.RecentEnrolled)

	// Stale identities (created > 30 days ago, still not enrolled)
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = false AND created_at < NOW() - INTERVAL '30 days'`).Scan(&analytics.StaleIdentities)

	if analytics.TotalUsers > 0 {
		analytics.EnrollmentRate = float64(analytics.Enrolled) / float64(analytics.TotalUsers) * 100
	}

	c.JSON(http.StatusOK, analytics)
}

// ---------------------------------------------------------------------------
// GET /api/v1/access/ziti/onboarding-status
// Per-user: returns current user's setup progress
// ---------------------------------------------------------------------------

func (s *Service) handleGetOnboardingStatus(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	uid, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user_id"})
		return
	}

	status := OnboardingStatus{
		SetupStep:    0,
		SetupMessage: "No Ziti identity found. Ask your administrator to sync your account.",
	}

	var name string
	var enrolled bool
	var enrollmentJWT *string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT name, enrolled, enrollment_jwt FROM ziti_identities WHERE user_id = $1 LIMIT 1`, uid).
		Scan(&name, &enrolled, &enrollmentJWT)

	if err != nil {
		c.JSON(http.StatusOK, status)
		return
	}

	status.HasIdentity = true
	status.IdentityName = name
	status.SetupStep = 1
	status.SetupMessage = "Identity created. Download a tunneler client to get started."

	if enrollmentJWT != nil && *enrollmentJWT != "" {
		status.EnrollmentJWT = *enrollmentJWT
		status.SetupStep = 2
		status.SetupMessage = "Enrollment token ready. Import the .jwt file into your tunneler client."
	}

	if enrolled {
		status.IsEnrolled = true
		status.EnrollmentJWT = "" // Don't expose JWT for already-enrolled identities
		status.SetupStep = 3
		status.SetupMessage = "Client enrolled successfully. You can access zero-trust services."

		// Check if user has access to any services (via policies)
		var svcCount int
		_ = s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT COUNT(*) FROM ziti_services WHERE enabled = true`).Scan(&svcCount)
		if svcCount > 0 {
			status.HasServices = true
			status.SetupStep = 4
			status.SetupMessage = fmt.Sprintf("You're connected! %d services are available through the zero-trust overlay.", svcCount)
		}
	}

	c.JSON(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// POST /api/v1/access/ziti/identities/:id/enrollment-qr
// Generates base64-encoded QR code data for mobile enrollment
// ---------------------------------------------------------------------------

func (s *Service) handleGetEnrollmentQR(c *gin.Context) {
	id := c.Param("id")

	var enrollmentJWT *string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT enrollment_jwt FROM ziti_identities WHERE id=$1", id).Scan(&enrollmentJWT)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity not found"})
		return
	}

	if enrollmentJWT == nil || *enrollmentJWT == "" {
		c.JSON(http.StatusGone, gin.H{"error": "enrollment JWT not available (identity may already be enrolled)"})
		return
	}

	// Return the JWT as a QR-compatible payload (base64 data URI for frontend QR library)
	// Frontend will render this as a QR code using a JS library
	qrData := base64.StdEncoding.EncodeToString([]byte(*enrollmentJWT))
	c.JSON(http.StatusOK, gin.H{
		"qr_data":  qrData,
		"raw_jwt":  *enrollmentJWT,
		"identity": id,
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/access/ziti/identities/:id/send-enrollment
// Sends enrollment instructions to the user (via email if configured)
// ---------------------------------------------------------------------------

func (s *Service) handleSendEnrollment(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")

	var name, enrollmentJWT string
	var userID *string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT name, enrollment_jwt, user_id FROM ziti_identities WHERE id=$1", id).
		Scan(&name, &enrollmentJWT, &userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity not found"})
		return
	}

	if enrollmentJWT == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no enrollment JWT available"})
		return
	}

	if userID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "identity not linked to a user"})
		return
	}

	// Look up user email
	var email string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT email FROM users WHERE id=$1", *userID).Scan(&email)
	if err != nil || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user email not found"})
		return
	}

	// Log the enrollment send event (actual email sending depends on email service config)
	s.logAuditEvent(c, "enrollment_instructions_sent", id, "ziti_identity", map[string]interface{}{
		"user_email":    email,
		"identity_name": name,
	})

	s.logger.Info("Enrollment instructions requested",
		zap.String("identity", name),
		zap.String("email", email),
		zap.String("identity_id", id))

	c.JSON(http.StatusOK, gin.H{
		"message":  "Enrollment instructions queued",
		"email":    email,
		"identity": name,
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/access/ziti/bulk-enroll
// Admin: bulk create identities + enrollment JWTs for multiple users
// ---------------------------------------------------------------------------

func (s *Service) handleBulkEnroll(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var req struct {
		UserIDs []string `json:"user_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.UserIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_ids must not be empty"})
		return
	}

	if len(req.UserIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 100 users per batch"})
		return
	}

	type enrollResult struct {
		UserID     string `json:"user_id"`
		IdentityID string `json:"identity_id,omitempty"`
		Name       string `json:"name,omitempty"`
		Status     string `json:"status"`
		Error      string `json:"error,omitempty"`
	}

	results := []enrollResult{}
	success, failed := 0, 0

	for _, userID := range req.UserIDs {
		// Check if already has identity
		var existingID string
		err := s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT id FROM ziti_identities WHERE user_id=$1", userID).Scan(&existingID)
		if err == nil {
			results = append(results, enrollResult{UserID: userID, IdentityID: existingID, Status: "already_exists"})
			continue
		}

		// Sync user → creates identity + JWT
		syncResult, err := s.zitiManager.SyncUserToZiti(c.Request.Context(), userID)
		if err != nil {
			results = append(results, enrollResult{UserID: userID, Status: "failed", Error: err.Error()})
			failed++
			continue
		}

		results = append(results, enrollResult{
			UserID:     userID,
			IdentityID: syncResult.ZitiID,
			Name:       syncResult.UserID,
			Status:     "created",
		})
		success++
	}

	s.logAuditEvent(c, "bulk_enrollment_initiated", "", "ziti_identity", map[string]interface{}{
		"total":   len(req.UserIDs),
		"success": success,
		"failed":  failed,
	})

	c.JSON(http.StatusOK, gin.H{
		"results":  results,
		"created":  success,
		"failed":   failed,
		"existing": len(req.UserIDs) - success - failed,
	})
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/access/ziti/stale-identities
// Admin: clean up identities that are > 30 days old and never enrolled
// ---------------------------------------------------------------------------

func (s *Service) handleCleanupStaleIdentities(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	thresholdDays := 30
	if v := c.Query("threshold_days"); v != "" {
		fmt.Sscan(v, &thresholdDays)
		if thresholdDays < 7 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "threshold_days must be at least 7"})
			return
		}
	}

	dryRun := c.Query("dry_run") == "true"

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, ziti_id, name FROM ziti_identities
		 WHERE enrolled = false AND created_at < NOW() - ($1 || ' days')::INTERVAL`,
		fmt.Sprintf("%d", thresholdDays))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type staleIdentity struct {
		ID     string `json:"id"`
		ZitiID string `json:"ziti_id"`
		Name   string `json:"name"`
	}

	stale := []staleIdentity{}
	for rows.Next() {
		var s staleIdentity
		if err := rows.Scan(&s.ID, &s.ZitiID, &s.Name); err == nil {
			stale = append(stale, s)
		}
	}

	if dryRun {
		c.JSON(http.StatusOK, gin.H{
			"dry_run": true,
			"count":   len(stale),
			"stale":   stale,
		})
		return
	}

	deleted := 0
	for _, si := range stale {
		// Delete from Ziti controller
		if err := s.zitiManager.DeleteIdentity(c.Request.Context(), si.ZitiID); err != nil {
			s.logger.Warn("Failed to delete stale identity from controller",
				zap.String("id", si.ID), zap.Error(err))
		}
		// Delete from DB
		if _, err := s.db.Pool.Exec(c.Request.Context(),
			"DELETE FROM ziti_identities WHERE id=$1", si.ID); err == nil {
			deleted++
		}
	}

	s.logAuditEvent(c, "stale_identities_cleaned", "", "ziti_identity", map[string]interface{}{
		"threshold_days": thresholdDays,
		"deleted":        deleted,
	})

	c.JSON(http.StatusOK, gin.H{
		"deleted":        deleted,
		"threshold_days": thresholdDays,
	})
}

// ---------------------------------------------------------------------------
// GET /api/v1/access/ziti/setup-checklist
// Returns a comprehensive setup checklist for admins
// ---------------------------------------------------------------------------

func (s *Service) handleGetSetupChecklist(c *gin.Context) {
	type ChecklistItem struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Completed   bool   `json:"completed"`
		Action      string `json:"action"` // link or action to take
		Priority    int    `json:"priority"`
	}

	items := []ChecklistItem{}

	// 1. Controller connected
	controllerOK := false
	if s.zitiManager != nil {
		if _, err := s.zitiManager.GetControllerVersion(c.Request.Context()); err == nil {
			controllerOK = true
		}
	}
	items = append(items, ChecklistItem{
		ID:          "controller",
		Title:       "Connect to Ziti Controller",
		Description: "Verify the Ziti controller is reachable and the SDK is initialized.",
		Completed:   controllerOK,
		Action:      "/ziti-network",
		Priority:    1,
	})

	// 2. At least one router
	var routerCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_edge_routers WHERE is_online = true`).Scan(&routerCount)
	if routerCount == 0 {
		// Try from manager
		if routers, err := s.zitiManager.ListEdgeRouters(c.Request.Context()); err == nil {
			for _, r := range routers {
				if r.IsOnline {
					routerCount++
				}
			}
		}
	}
	items = append(items, ChecklistItem{
		ID:          "routers",
		Title:       "Deploy Edge Routers",
		Description: "At least one online edge router is required to route traffic.",
		Completed:   routerCount > 0,
		Action:      "/ziti-network",
		Priority:    2,
	})

	// 3. Services created
	var svcCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_services WHERE enabled = true`).Scan(&svcCount)
	items = append(items, ChecklistItem{
		ID:          "services",
		Title:       "Register Services",
		Description: "Add services that users will access through the zero-trust overlay.",
		Completed:   svcCount > 0,
		Action:      "/ziti-network",
		Priority:    3,
	})

	// 4. Identities synced
	var identCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities`).Scan(&identCount)
	items = append(items, ChecklistItem{
		ID:          "identities",
		Title:       "Create User Identities",
		Description: "Sync users to create Ziti identities for tunneler enrollment.",
		Completed:   identCount > 0,
		Action:      "/ziti-network",
		Priority:    4,
	})

	// 5. Service policies
	policyCount := 0
	if policies, err := s.zitiManager.ListServicePolicies(c.Request.Context()); err == nil {
		policyCount = len(policies)
	}
	items = append(items, ChecklistItem{
		ID:          "policies",
		Title:       "Create Service Policies",
		Description: "Grant identities permission to dial (access) services via service policies.",
		Completed:   policyCount > 0,
		Action:      "/ziti-network",
		Priority:    5,
	})

	// 6. At least one enrolled identity
	var enrolledCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = true`).Scan(&enrolledCount)
	items = append(items, ChecklistItem{
		ID:          "enrolled",
		Title:       "Enroll Client Tunnelers",
		Description: "At least one identity should complete tunneler enrollment.",
		Completed:   enrolledCount > 0,
		Action:      "/client-setup",
		Priority:    6,
	})

	// 7. BrowZer configured (optional but recommended)
	var browzerConfigured bool
	var browzerCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_browzer_config`).Scan(&browzerCount)
	browzerConfigured = browzerCount > 0
	items = append(items, ChecklistItem{
		ID:          "browzer",
		Title:       "Enable BrowZer (Optional)",
		Description: "BrowZer lets users access services in the browser without installing a tunneler.",
		Completed:   browzerConfigured,
		Action:      "/browzer-management",
		Priority:    7,
	})

	// Compute overall progress
	completedCount := 0
	for _, item := range items {
		if item.Completed {
			completedCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"items":     items,
		"total":     len(items),
		"completed": completedCount,
		"progress":  float64(completedCount) / float64(len(items)) * 100,
	})
}

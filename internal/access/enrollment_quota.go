package access

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The per-tenant enrolment quota, in one place.
//
// Three handlers mint agent_enrollment_tokens rows -- the admin token endpoint,
// the Android QR and the onboarding wizard's session -- and until this file
// none of them asked how many the tenant had already minted. A device
// enrolment token is what admits a machine to the fleet; a console credential
// that can mint them without limit can enrol without limit. v197 made the
// table per-tenant so the count is possible; the plan left the NUMBER open as
// a product decision, and it was decided at 100 an hour on 2026-09-20.
//
// The window is a rolling hour counted from the table, not a bucket in Redis:
// the rows are the record, they are already per-tenant, and the count survives
// a restart. Two requests racing at the boundary can both pass and the tenant
// mints N+1; the quota is a ceiling on abuse, not a ledger, and that is an
// accepted imprecision rather than a lock on the mint path.
const defaultEnrollmentQuotaPerHour = 100

const enrollmentQuotaWindow = time.Hour

// enrollmentQuotaPerHour is the configured quota; 0 means no quota, which
// startup reports as an open gate (config.ReportModeGates).
func (h *AgentAPIHandler) enrollmentQuotaPerHour() int {
	if h.conf == nil {
		return defaultEnrollmentQuotaPerHour
	}
	if h.conf.AgentEnrollmentQuotaPerHour < 0 {
		return defaultEnrollmentQuotaPerHour
	}
	return h.conf.AgentEnrollmentQuotaPerHour
}

// enrollmentQuotaExceeded reports whether the tenant has already minted the
// quota within the window, and if so how long until the oldest in-window
// token ages out and one more may be minted.
func (h *AgentAPIHandler) enrollmentQuotaExceeded(ctx context.Context, orgID string) (retryAfter time.Duration, exceeded bool, err error) {
	quota := h.enrollmentQuotaPerHour()
	if quota == 0 || h.db == nil || h.db.Pool == nil {
		return 0, false, nil
	}
	var minted int
	var oldest *time.Time
	err = h.db.Pool.QueryRow(ctx, `
		SELECT count(*), min(created_at)
		FROM agent_enrollment_tokens
		WHERE org_id = $1 AND created_at > NOW() - $2::interval
	`, orgID, enrollmentQuotaWindow.String()).Scan(&minted, &oldest)
	if err != nil {
		return 0, false, err
	}
	if minted < quota {
		return 0, false, nil
	}
	retryAfter = time.Second
	if oldest != nil {
		if until := time.Until(oldest.Add(enrollmentQuotaWindow)); until > retryAfter {
			retryAfter = until
		}
	}
	return retryAfter, true, nil
}

// refuseIfEnrollmentQuotaExceeded is what every mint site calls before its
// INSERT. It answers the request itself when the tenant is over quota (429
// with Retry-After) or when the count cannot be taken (500 -- refusing to
// mint is the safe direction for an admission credential), and returns true
// in both cases so the caller stops. A false return means: mint.
func (h *AgentAPIHandler) refuseIfEnrollmentQuotaExceeded(c *gin.Context, orgID string) bool {
	retryAfter, exceeded, err := h.enrollmentQuotaExceeded(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("enrollment quota: count failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return true
	}
	if !exceeded {
		return false
	}
	secs := int(retryAfter.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	// The tenant id is deliberately not a field here: on the wizard's path it
	// arrives from a token claim (caller-supplied bytes), and the request
	// logger already stamps org_id on every line of this request.
	h.logger.Warn("enrollment quota exceeded",
		zap.Int("quota_per_hour", h.enrollmentQuotaPerHour()),
		zap.Int("retry_after_seconds", secs))
	c.Header("Retry-After", strconv.Itoa(secs))
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":             "enrollment_quota_exceeded",
		"error_description": "this tenant has minted its hourly quota of enrollment tokens; retry after the Retry-After interval",
		"retry_after":       secs,
	})
	return true
}

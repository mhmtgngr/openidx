package audit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// Usage metering query API (Wave A4): reads the daily rollup for the caller's
// org so operators can bill/report Ziti fabric usage per service / identity.

// UsageRow is one metered counter in the response.
type UsageRow struct {
	Day     string `json:"day"`
	Metric  string `json:"metric"`
	Service string `json:"service,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Count   int64  `json:"count"`
}

// UsageSummary aggregates totals for the window.
type UsageSummary struct {
	OverlayLogins int64            `json:"overlay_logins"`
	ServiceDials  int64            `json:"service_dials"`
	ByService     map[string]int64 `json:"by_service"`
	Rows          []UsageRow       `json:"rows"`
	From          string           `json:"from"`
	To            string           `json:"to"`
}

// meteringOrgID resolves the caller's org, or "" (all orgs — platform admin).
func meteringOrgID(c *gin.Context) string {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		return ""
	}
	return org.ID
}

// handleGetUsage serves GET /api/v1/audit/usage?from=YYYY-MM-DD&to=YYYY-MM-DD.
// Returns the daily rollup + a summary for the caller's org.
func (s *Service) handleGetUsage(c *gin.Context) {
	orgID := meteringOrgID(c)

	// Default window: last 30 days.
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)
	if v := c.Query("from"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			from = t
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			to = t
		}
	}
	limit := 1000
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
			limit = n
		}
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
        SELECT to_char(day,'YYYY-MM-DD'), metric, service, COALESCE(user_id::text,''), count
          FROM usage_metering_daily
         WHERE day >= $1::date AND day <= $2::date
           AND (org_id::text = $3 OR $3 = '')
         ORDER BY day DESC, count DESC
         LIMIT $4`,
		from.Format("2006-01-02"), to.Format("2006-01-02"), orgID, limit)
	if err != nil {
		s.logger.Error("usage query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	defer rows.Close()

	summary := UsageSummary{
		ByService: map[string]int64{},
		Rows:      []UsageRow{},
		From:      from.Format("2006-01-02"),
		To:        to.Format("2006-01-02"),
	}
	for rows.Next() {
		var r UsageRow
		if err := rows.Scan(&r.Day, &r.Metric, &r.Service, &r.UserID, &r.Count); err != nil {
			continue
		}
		summary.Rows = append(summary.Rows, r)
		switch r.Metric {
		case metricOverlayLogin:
			summary.OverlayLogins += r.Count
		case metricServiceDial:
			summary.ServiceDials += r.Count
			if r.Service != "" {
				summary.ByService[r.Service] += r.Count
			}
		}
	}
	c.JSON(http.StatusOK, summary)
}

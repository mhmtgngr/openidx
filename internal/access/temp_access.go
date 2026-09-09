// Package access provides temporary access link functionality for support/vendor access
package access

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/notifications"
)

// TempAccessLink represents a temporary access link for support/vendor access
type TempAccessLink struct {
	ID               string     `json:"id"`
	Token            string     `json:"token"`
	Name             string     `json:"name"`
	Description      string     `json:"description,omitempty"`
	PamEntryID       string     `json:"pam_entry_id,omitempty"`
	Protocol         string     `json:"protocol"` // ssh, rdp, vnc
	TargetHost       string     `json:"target_host"`
	TargetPort       int        `json:"target_port"`
	Username         string     `json:"username,omitempty"`
	CreatedBy        string     `json:"created_by"`
	CreatedByEmail   string     `json:"created_by_email"`
	ExpiresAt        time.Time  `json:"expires_at"`
	MaxUses          int        `json:"max_uses"` // 0 = unlimited
	CurrentUses      int        `json:"current_uses"`
	AllowedIPs       []string   `json:"allowed_ips,omitempty"` // IP whitelist
	NotifyOnUse      bool       `json:"notify_on_use"`
	RouteID          string     `json:"route_id,omitempty"`
	GuacConnectionID string     `json:"guacamole_connection_id,omitempty"`
	AccessURL        string     `json:"access_url"`
	Status           string     `json:"status"` // active, expired, revoked, used
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP       string     `json:"last_used_ip,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// TempAccessUsage tracks usage of temporary access links
type TempAccessUsage struct {
	ID             string     `json:"id"`
	LinkID         string     `json:"link_id"`
	IPAddress      string     `json:"ip_address"`
	UserAgent      string     `json:"user_agent"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Duration       int        `json:"duration_seconds,omitempty"`
}

// CreateTempAccessRequest is the request to create a temp access link.
//
// The target is a PAM entry, not a hostname. Everything that decides HOW the
// session is brokered — reach mode, recording, the vault credential, the Ziti
// intercept port — lives on that entry, so a link cannot be issued to a target
// whose controls nobody configured, and cannot drift from them afterwards.
// Protocol, host, port and username used to be fields here and are now read
// from the entry.
type CreateTempAccessRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  string   `json:"description"`
	PamEntryID   string   `json:"pam_entry_id" binding:"required,uuid"`
	DurationMins int      `json:"duration_mins" binding:"required,min=5,max=10080"` // 5 mins to 7 days
	MaxUses      int      `json:"max_uses"`                                         // 0 = unlimited
	AllowedIPs   []string `json:"allowed_ips"`
	NotifyOnUse  bool     `json:"notify_on_use"`
}

// generateSecureToken generates a cryptographically secure token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// handleCreateTempAccess creates a new temporary access link
func (s *Service) handleCreateTempAccess(c *gin.Context) {
	var req CreateTempAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateAllowedIPs(req.AllowedIPs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	// Get current user from context.
	//
	// The issuer is not decoration. created_by is the accountability record for
	// who let an outside party onto an internal host, and it is now also the
	// address the notify_on_use notification is delivered to — so a link with no
	// resolvable issuer would be both unattributable and silently unnotifiable.
	// The route is authenticated, but SoftAuth (ACCESS_API_REQUIRE_AUTH=false)
	// leaves the key unset, and the old code formatted that straight into a UUID
	// column as the literal "<nil>", which failed the INSERT with a generic 500.
	userEmail, _ := c.Get("email")
	creatorID := ""
	if v, ok := c.Get("user_id"); ok {
		creatorID = strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	if _, err := uuid.Parse(creatorID); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "a temporary access link must record the user who issued it, and this " +
				"request carries no identified user",
			"code": "issuer_unresolved"})
		return
	}

	// Generate secure token
	token, err := generateSecureToken(32)
	if err != nil {
		s.logger.Error("failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}

	linkID := uuid.New().String()
	expiresAt := time.Now().Add(time.Duration(req.DurationMins) * time.Minute)

	// The entry is the target, and loading it here is also the validation: a
	// link cannot be issued for a row that does not exist, belongs to another
	// tenant, or is not a launchable session (a credential or a note has
	// nothing to broker).
	entry, typeInfo, err := s.pamLaunchEntryByID(c.Request.Context(), req.PamEntryID, org.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, errPamEntryNotLaunchable) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "pam_entry_id must name a launchable session entry in this organization"})
			return
		}
		s.logger.Error("temp access: entry lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the target entry"})
		return
	}

	// Protocol/host/port/username are copied from the entry so the list view can
	// show what a link points at without joining. They are a DISPLAY copy: the
	// redemption reads the entry again and brokers from that, so an entry edited
	// after issuance takes effect on the next use rather than the link carrying a
	// stale target.
	link := TempAccessLink{
		ID:             linkID,
		Token:          token,
		Name:           req.Name,
		Description:    req.Description,
		PamEntryID:     entry.ID,
		Protocol:       typeInfo.Protocol,
		TargetHost:     entry.Hostname,
		TargetPort:     entry.Port,
		Username:       entry.Username,
		CreatedBy:      creatorID,
		CreatedByEmail: fmt.Sprintf("%v", userEmail),
		ExpiresAt:      expiresAt,
		MaxUses:        req.MaxUses,
		CurrentUses:    0,
		AllowedIPs:     req.AllowedIPs,
		NotifyOnUse:    req.NotifyOnUse,
		Status:         "active",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// No Guacamole connection is built here any more. It used to be created at
	// issuance with an EMPTY parameter map — no credential, no recording — and
	// the redemption merely redirected to it. The connection is now built by
	// launchPamSession at redemption, from the entry, with the credential
	// injected and recording configured, which is the entire point of routing
	// through that core.

	accessURL, err := tempAccessURL(s.config.AccessProxyDomain, token)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": err.Error(), "code": "access_proxy_domain_unset"})
		return
	}
	link.AccessURL = accessURL

	// Store in database
	query := `
		INSERT INTO temp_access_links (
			id, token, name, description, pam_entry_id, protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, notify_on_use, route_id,
			guacamole_connection_id, access_url, status, created_at, updated_at, org_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)`

	_, err = s.db.Pool.Exec(c.Request.Context(), query,
		link.ID, link.Token, link.Name, link.Description, link.PamEntryID, link.Protocol,
		link.TargetHost, link.TargetPort, link.Username, link.CreatedBy,
		link.CreatedByEmail, link.ExpiresAt, link.MaxUses, link.CurrentUses,
		link.AllowedIPs, link.NotifyOnUse,
		link.RouteID, link.GuacConnectionID, link.AccessURL, link.Status,
		link.CreatedAt, link.UpdatedAt, org.ID,
	)
	if err != nil {
		s.logger.Error("failed to create temp access link", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access link"})
		return
	}

	// Audit log
	s.auditLog(c, "temp_access.created", map[string]interface{}{
		"link_id":     link.ID,
		"target_host": link.TargetHost,
		"protocol":    link.Protocol,
		"expires_at":  link.ExpiresAt,
	})

	c.JSON(http.StatusCreated, link)
}

// handleListTempAccess lists all temporary access links
func (s *Service) handleListTempAccess(c *gin.Context) {
	status := c.DefaultQuery("status", "")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `
		SELECT id, token, name, description, COALESCE(pam_entry_id::text,''), protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, notify_on_use, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE org_id = $2 AND ($1 = '' OR status = $1)
		ORDER BY created_at DESC
		LIMIT 100`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, status, org.ID)
	if err != nil {
		s.logger.Error("failed to list temp access links", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list access links"})
		return
	}
	defer rows.Close()

	var links []TempAccessLink
	for rows.Next() {
		var link TempAccessLink
		err := rows.Scan(
			&link.ID, &link.Token, &link.Name, &link.Description, &link.PamEntryID, &link.Protocol,
			&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
			&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
			&link.AllowedIPs, &link.NotifyOnUse,
			&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
			&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Auto-expire if past expiration
		if time.Now().After(link.ExpiresAt) && link.Status == "active" {
			link.Status = "expired"
		}

		// Mask token for security (only show first 8 chars)
		if len(link.Token) > 8 {
			link.Token = link.Token[:8] + "..."
		}

		links = append(links, link)
	}

	c.JSON(http.StatusOK, gin.H{"links": links})
}

// handleGetTempAccess gets a specific temp access link
func (s *Service) handleGetTempAccess(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `
		SELECT id, token, name, description, COALESCE(pam_entry_id::text,''), protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, notify_on_use, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE id = $1 AND org_id = $2`

	var link TempAccessLink
	err = s.db.Pool.QueryRow(c.Request.Context(), query, id, org.ID).Scan(
		&link.ID, &link.Token, &link.Name, &link.Description, &link.PamEntryID, &link.Protocol,
		&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
		&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
		&link.AllowedIPs, &link.NotifyOnUse,
		&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
		&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	c.JSON(http.StatusOK, link)
}

// handleRevokeTempAccess revokes a temp access link
func (s *Service) handleRevokeTempAccess(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `UPDATE temp_access_links SET status = 'revoked', updated_at = $1 WHERE id = $2 AND org_id = $3`
	result, err := s.db.Pool.Exec(c.Request.Context(), query, time.Now(), id, org.ID)
	if err != nil {
		s.logger.Error("failed to revoke temp access link", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke access link"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	// Audit log
	s.auditLog(c, "temp_access.revoked", map[string]interface{}{"link_id": id})

	c.JSON(http.StatusOK, gin.H{"message": "access link revoked"})
}

// tempAccessURL builds the address a vendor is sent, or refuses.
//
// The link's whole value is a URL someone outside can open, so an unconfigured
// base is a refusal rather than a guess. It used to fall back to
// browzer.localtest.me — a test domain that resolves to loopback — which
// produced a link that looked issued, could be sent to a vendor, and reached
// nothing. Failing at issuance puts the error in front of the operator who can
// fix it, instead of in front of the outside party who cannot.
func tempAccessURL(proxyDomain, token string) (string, error) {
	domain := strings.TrimSpace(proxyDomain)
	if domain == "" {
		return "", fmt.Errorf("access_proxy_domain is not configured, so a vendor link would " +
			"have no address to point at. Set it before issuing temporary access.")
	}
	return fmt.Sprintf("https://%s/temp-access/%s", domain, token), nil
}

// renderTempAccessError writes the page an anonymous redeemer is shown when
// their link is refused.
//
// NOT c.HTML, and that is the whole point. Every refusal on this route was
// written as `c.HTML(status, "error.html", …)` — six of them: not found,
// expired, revoked, IP not allowed, legacy, target unavailable, ZTNA denied.
// Nothing in this repository has ever registered a template renderer
// (no LoadHTMLGlob, no LoadHTMLFiles, no SetHTMLTemplate anywhere) and no
// error.html exists, so gin's HTMLRender was nil and every one of those calls
// dereferenced it and panicked. The decisions were right; the vendor got a
// dropped request or a bare 500 from the recovery middleware, and never the
// reason.
//
// It is the branch's defect class once more, this time in the other direction:
// the control enforces and cannot say so. Writing the page directly is what
// makes it independent of a deployment step nobody performs — there is one page
// shape here, so a template registry buys nothing and costs a whole class of
// silent failure.
//
// Both values are escaped: title and message are ours today, but message
// carries checkPamZTNA's reason and the link id, and a page that interpolates
// anything from a row into markup without escaping is one migration away from
// being a hole.
func renderTempAccessError(c *gin.Context, status int, title, message string) {
	page := fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1f2933;
      background:#f5f7fa;margin:0;display:flex;min-height:100vh;
      align-items:center;justify-content:center;padding:24px}
 main{background:#fff;border:1px solid #d9e2ec;border-radius:12px;
      padding:32px;max-width:34rem}
 h1{font-size:1.25rem;margin:0 0 12px}
 p{margin:0;color:#3e4c59}
</style></head>
<body><main><h1>%s</h1><p>%s</p></main></body></html>
`, template.HTMLEscapeString(title), template.HTMLEscapeString(title),
		template.HTMLEscapeString(message))
	c.Data(status, "text/html; charset=utf-8", []byte(page))
}

// tempLinkLaunchFailurePage is what an anonymous redeemer is shown when the
// brokered launch fails.
//
// THE SIGNATURE IS THE GUARANTEE. It takes the link id and nothing else — not
// the pamLaunchFailure — so the page cannot vary with the reason, and adding a
// new failure to the launch core cannot leak a new sentence onto this page.
//
// Everything that reaches here is a misconfiguration of THIS deployment: no
// broker, no overlay, the vault unreachable. The vendor can neither cause it
// nor fix it, and is not entitled to be told which of those it is — the raw
// failure names the OpenZiti broker and the credential store, to somebody with
// no account here. Before this the whole object was serialised to them as JSON,
// on a route that renders HTML.
//
// The link id is deliberately included: it is the one thing the vendor can
// usefully quote back, they already hold it, and it is the operator's index
// into the log line and audit row that do carry the reason.
func tempLinkLaunchFailurePage(linkID string) (title, message string) {
	return "Session Unavailable",
		"This session could not be started. Nothing is wrong with your link — ask " +
			"the person who sent it to check the connection, quoting reference " + linkID + "."
}

// tempLinkNotifyRecipient returns the user id to be told that this link has
// just been used, or "" when nobody is.
//
// Separated from the send so the decision is provable without a database. The
// recipient is the link's CREATOR rather than a free-text address, which is a
// deliberate narrowing of what the console's switch used to imply. The
// notification service is keyed by user id, so a creator is deliverable through
// the channels that user has already configured; an arbitrary notify_email
// would have needed its own sender, and a free-text recipient on a security
// notification is a way to make the product email anyone. The sponsor is also
// who actually needs to know — it is their vendor, and their link.
//
// A link whose creator is unknown (created_by NULL, which the column permits)
// notifies nobody, which would be a switch that is on and does nothing — the
// exact defect this change exists to remove. So handleCreateTempAccess refuses
// to issue a link at all without a resolvable issuer, and this returns "" only
// for a row predating that rule.
func tempLinkNotifyRecipient(link TempAccessLink) string {
	if !link.NotifyOnUse {
		return ""
	}
	return strings.TrimSpace(link.CreatedBy)
}

// notifyTempLinkUsed tells the person who issued the link that it has just been
// used, when they asked to be told.
//
// notify_on_use was a switch on the console's create form that sent nothing:
// stored, read back into the struct, and never once acted on.
//
// Best-effort, like every other notification in this package: an outside party
// has already reached an internal host by the time this runs, the audit row and
// the usage row are the durable record, and a failed notification must not turn
// a working session into an error page.
func (s *Service) notifyTempLinkUsed(ctx context.Context, link TempAccessLink, orgID, clientIP string) {
	recipient := tempLinkNotifyRecipient(link)
	if recipient == "" {
		return
	}
	notif := notifications.NewService(s.db, s.logger)
	body := fmt.Sprintf("The temporary access link %q was just used from %s.", link.Name, clientIP)
	if err := notif.CreateMultiChannelNotification(ctx, recipient, orgID,
		notifications.TypeSecurity, "Temporary access link used", body, "/ziti-network",
		map[string]interface{}{
			"link_id":    link.ID,
			"link_name":  link.Name,
			"ip_address": clientIP,
			"kind":       "temp_access_link",
		}); err != nil {
		s.logger.Warn("temp access: use notification failed",
			zap.String("link_id", link.ID), zap.Error(err))
	}
}

// tempLinkVerdict is the outcome of the gates a redemption is held to.
type tempLinkVerdict struct {
	Refuse  bool
	Status  int
	Title   string
	Message string
}

// tempLinkGate decides whether this redemption may proceed.
//
// WHY THIS IS A FUNCTION AND NOT FOUR ifs IN THE HANDLER. `GET
// /temp-access/:token` is one of the very few routes this product serves
// anonymously, and `public_surface_test.go` makes every such route carry a
// written justification. The justification for this one is the list of checks
// performed here — so those checks are the load-bearing security argument for
// the whole route, and they were, until now, four inline conditionals inside a
// DB-backed handler with no test of their own. Pulling them out makes the
// argument provable by a table test that needs no Postgres.
//
// WHAT IS DELIBERATELY NOT HERE: MFA. The register used to claim this handler
// checked it, and it never did — `require_mfa` was stored, selected back, and
// never compared to anything. The field is gone rather than implemented,
// because implementing it here would mean a second, weaker authentication
// system bolted onto an anonymous URL: with no session there is no
// `sessions.mfa_verified_at` for `STEPUP_GATE` to read, so it would have to be
// a bespoke OTP. Vendor MFA belongs where every other factor in this product
// lives — on an identity. `docs/VENDOR-ACCESS-ROADMAP.md` V1 carries that:
// the vendor becomes a real, time-boxed user reaching the target through
// BrowZer, at which point the existing gate applies with no new machinery.
//
// The IP allowlist is exact string equality, which means a CIDR entry matches
// nothing. That is a usability trap rather than a hole — it fails closed, and
// an operator who writes a range locks everyone out including themselves —
// and it is roadmap item V0.4. `TestTheAllowlistIsExactMatchOnly` pins the
// present behaviour so that fix arrives with a red proof.
func tempLinkGate(link TempAccessLink, clientIP string, now time.Time) tempLinkVerdict {
	if now.After(link.ExpiresAt) {
		return tempLinkVerdict{true, http.StatusGone, "Access Link Expired",
			"This temporary access link has expired."}
	}
	if link.Status == "revoked" {
		return tempLinkVerdict{true, http.StatusForbidden, "Access Link Revoked",
			"This access link has been revoked by an administrator."}
	}
	if link.MaxUses > 0 && link.CurrentUses >= link.MaxUses {
		return tempLinkVerdict{true, http.StatusForbidden, "Access Link Exhausted",
			"This access link has reached its maximum usage limit."}
	}
	if len(link.AllowedIPs) > 0 && !ipAllowed(clientIP, link.AllowedIPs) {
		return tempLinkVerdict{true, http.StatusForbidden, "Access Denied",
			"Your IP address is not authorized to use this access link."}
	}
	return tempLinkVerdict{}
}

// ipAllowed reports whether clientIP matches any entry, where an entry is
// either a single address or a CIDR range.
//
// This was string equality, so "203.0.113.0/24" matched nothing and an operator
// who wrote a range had allowed no address at all — including their own. It
// failed CLOSED, which is why it was a usability trap rather than a hole, but
// the trap is the kind that gets a control switched off: the link stops working,
// nobody can see why, and the next one is issued with no allowlist.
//
// netip rather than net: it parses and compares without allocating, and it
// normalises IPv6, so ::1 and 0:0:0:0:0:0:0:1 are the same address here where
// as strings they were two. An unparseable entry matches nothing rather than
// erroring — creation validates the list, so a bad entry here means the row
// predates that validation, and refusing is the safe reading.
func ipAllowed(clientIP string, allowed []string) bool {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	// An IPv4-mapped IPv6 client address (::ffff:203.0.113.9) must compare
	// against an IPv4 rule, which is what a proxy in front of the service can
	// hand us.
	addr = addr.Unmap()

	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if prefix, err := netip.ParsePrefix(entry); err == nil && prefix.Contains(addr) {
				return true
			}
			continue
		}
		if rule, err := netip.ParseAddr(entry); err == nil && rule.Unmap() == addr {
			return true
		}
	}
	return false
}

// validateAllowedIPs rejects an allowlist entry that is neither an address nor
// a CIDR range, at creation, so the operator is told rather than discovering it
// when the vendor cannot connect and the link looks fine.
func validateAllowedIPs(entries []string) error {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, err := netip.ParsePrefix(entry); err != nil {
				return fmt.Errorf("allowed_ips: %q is not a valid CIDR range", entry)
			}
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			return fmt.Errorf("allowed_ips: %q is not a valid IP address or CIDR range", entry)
		}
	}
	return nil
}

// handleUseTempAccess redeems a link: it holds the request to tempLinkGate,
// records the use, then brokers the entry's session through the same launch
// core as the console's Connect button. It used to redirect to a Guacamole
// connection built at issuance, which is what let a vendor past every control.
func (s *Service) handleUseTempAccess(c *gin.Context) {
	token := c.Param("token")

	// TENANCY (v148). This is a pre-tenant-resolution lookup: the vendor
	// redeeming the link has no session and no organization on the context, and
	// the token is the globally-unique secret that identifies the link. v148
	// puts temp_access_links under FORCE RLS, so this read and the use-count
	// write below run BYPASSED — the same treatment as v145's magic-link
	// redemption, api-key-by-hash and route-by-host, and pinned the same way by
	// TestPreResolutionLookupsUnderRLS. Without the bypass the belt returns zero
	// rows here and every vendor link stops redeeming, which is exactly the
	// breakage v71 declined the belt to avoid.
	//
	// The org_id the read returns is what scopes the usage row that follows, so
	// the record of the access lands in the tenant that issued the link.
	redeemCtx := orgctx.WithBypassRLS(c.Request.Context())

	//orgscope:ignore public token-redemption path — no authenticated org context; keyed by a globally-unique unguessable secret token, not an enumerable id
	query := `
		SELECT id, token, name, COALESCE(pam_entry_id::text,''), COALESCE(created_by::text,''), protocol, target_host, target_port, username,
			expires_at, max_uses, current_uses, allowed_ips,
			notify_on_use, guacamole_connection_id, status, org_id
		FROM temp_access_links
		WHERE token = $1`

	var link TempAccessLink
	var linkOrgID string
	err := s.db.Pool.QueryRow(redeemCtx, query, token).Scan(
		&link.ID, &link.Token, &link.Name, &link.PamEntryID, &link.CreatedBy, &link.Protocol, &link.TargetHost,
		&link.TargetPort, &link.Username, &link.ExpiresAt, &link.MaxUses,
		&link.CurrentUses, &link.AllowedIPs, &link.NotifyOnUse,
		&link.GuacConnectionID, &link.Status, &linkOrgID,
	)
	if err != nil {
		renderTempAccessError(c, http.StatusNotFound, "Access Link Not Found",
			"This access link is invalid or has been removed.")
		return
	}

	clientIP := c.ClientIP()
	if v := tempLinkGate(link, clientIP, time.Now()); v.Refuse {
		renderTempAccessError(c, v.Status, v.Title, v.Message)
		return
	}

	if link.PamEntryID == "" {
		// A link issued before migration v188 has no entry to launch. There is
		// nothing to infer it from — target_host is a hostname, and picking a
		// pam_entries row for the operator would be inventing an authorization —
		// so it is refused rather than falling back to the old redirect, which
		// would keep the ungated path alive for exactly the links issued while
		// it was the only path.
		s.auditLog(c, "temp_access.refused_legacy", map[string]interface{}{
			"link_id": link.ID, "ip_address": clientIP,
		})
		renderTempAccessError(c, http.StatusGone, "Access Link Must Be Re-Issued",
			"This link was created before privileged sessions were required to run through the "+
				"brokered launch path. Ask the person who sent it to create a new one.")
		return
	}

	// Update usage stats. Bypassed for the same reason as the read above; the
	// org term is still in the predicate so the write cannot wander off the link
	// the token resolved.
	//orgscope:ignore public token-redemption path — id resolved from the unique-token lookup above; redeemer has no org context
	updateQuery := `
		UPDATE temp_access_links
		SET current_uses = current_uses + 1, last_used_at = $1, last_used_ip = $2, updated_at = $1
		WHERE id = $3 AND org_id = $4`
	if _, err := s.db.Pool.Exec(redeemCtx, updateQuery, time.Now(), clientIP, link.ID, linkOrgID); err != nil {
		s.logger.Error("temp access: failed to record link use",
			zap.String("link_id", link.ID), zap.Error(err))
	}

	// Log usage. This is the record that an outside party connected to an
	// internal host, so a failure to write it is not something to swallow: the
	// access happens either way, and an unrecorded one is worse than a refused
	// one. Both Execs here discarded their errors before v148.
	usageID := uuid.New().String()
	usageQuery := `
		INSERT INTO temp_access_usage (id, link_id, ip_address, user_agent, connected_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := s.db.Pool.Exec(redeemCtx, usageQuery, usageID, link.ID, clientIP, c.Request.UserAgent(), time.Now(), linkOrgID); err != nil {
		s.logger.Error("temp access: failed to record vendor connection",
			zap.String("link_id", link.ID), zap.String("target_host", link.TargetHost), zap.Error(err))
	}

	// Audit log
	s.auditLog(c, "temp_access.used", map[string]interface{}{
		"link_id":     link.ID,
		"ip_address":  clientIP,
		"target_host": link.TargetHost,
	})

	s.notifyTempLinkUsed(redeemCtx, link, linkOrgID, clientIP)

	// Everything below is the launch, and it runs through the SAME core the
	// console's Connect button uses. Before this, redemption redirected to a
	// Guacamole connection built at issuance with no parameters: no ZTNA check,
	// always the direct broker, no recording, and no credential — so the vendor
	// had to be told a password out of band.
	// The vendor is anonymous, so the tenant is the link's and every statement
	// below carries it in SQL. The bypass is the same one the lookup above runs
	// under and for the same reason (v148): there is no organization on this
	// request's context to satisfy the belt with.
	c.Request = c.Request.WithContext(orgctx.WithBypassRLS(c.Request.Context()))

	entry, typeInfo, err := s.pamLaunchEntryByID(c.Request.Context(), link.PamEntryID, linkOrgID)
	if err != nil {
		s.logger.Warn("temp access: target entry unavailable",
			zap.String("link_id", link.ID), zap.Error(err))
		renderTempAccessError(c, http.StatusGone, "Target Unavailable",
			"The target this link points at is no longer available.")
		return
	}

	// The overlay gate, before a credential is resolved — the same ordering and
	// the same reason as handlePamConnect. userID is empty: the actor here is the
	// link, and the audit row carries its id.
	if v := s.checkPamZTNA(c, linkOrgID, "", entry.ID, entry.ReachMode, typeInfo.Protocol); v.Refuse {
		renderTempAccessError(c, http.StatusForbidden, "Access Denied", v.Reason)
		return
	}

	// The entry's approval gate is NOT consulted here, deliberately. Approval
	// asks a human to authorise a named user's launch; a vendor link has no user
	// to name and no way to request one. Issuing the link IS the authorisation —
	// an admin created it, for this entry, with an expiry — which is the same
	// reasoning that lets an admin bypass their own approval gate in
	// handlePamConnect. The link's own limits (window, use cap, IP allowlist)
	// are what bound it.
	res, fail := s.launchPamSession(c, linkOrgID, &entry, typeInfo.Protocol, nil,
		"pam-"+entry.ID, entry.GuacConnectionID,
		func(ctx context.Context, connID string) {
			if _, err := s.db.Pool.Exec(ctx,
				//orgscope:ignore pam_entries UPDATE keyed by the entry id the org-scoped load above resolved
				`UPDATE pam_entries SET guacamole_connection_id = $2 WHERE id = $1`, entry.ID, connID); err != nil {
				s.logger.Warn("temp access: connection id persist failed", zap.Error(err))
			}
		})
	if fail != nil {
		// The code and the detail go to the log and the audit row, where the
		// operator is. The page gets neither — see tempLinkLaunchFailurePage.
		s.logger.Warn("temp access: launch failed",
			zap.String("link_id", link.ID), zap.String("code", fail.Code),
			zap.Int("status", fail.Status), zap.String("detail", fail.Message))
		s.auditLog(c, "temp_access.launch_failed", map[string]interface{}{
			"link_id": link.ID, "code": fail.Code, "ip_address": clientIP,
		})
		failTitle, failMessage := tempLinkLaunchFailurePage(link.ID)
		renderTempAccessError(c, http.StatusServiceUnavailable, failTitle, failMessage)
		return
	}

	c.Redirect(http.StatusFound, res.ConnectURL)
}

// handleGetTempAccessUsage gets usage history for a temp access link
func (s *Service) handleGetTempAccessUsage(c *gin.Context) {
	linkID := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	// Verify the link belongs to the caller's org, so a cross-org id gets the
	// same 404 as an id that does not exist rather than an empty history.
	var ok bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM temp_access_links WHERE id = $1 AND org_id = $2)`, linkID, org.ID).Scan(&ok); err != nil || !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	// The org predicate below is not redundant with that check. Until v148 this
	// query read `WHERE link_id = $1` alone and was safe only because the
	// statement above happened to run first — safety living in the order two
	// statements are written in, which is the shape v143 and v147 both found
	// recorded as though it were a property of the schema. The check above
	// proves the LINK is the caller's; only this predicate proves the ROWS are.
	query := `
		SELECT id, link_id, ip_address, user_agent, connected_at, disconnected_at
		FROM temp_access_usage
		WHERE link_id = $1 AND org_id = $2
		ORDER BY connected_at DESC
		LIMIT 50`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, linkID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get usage history"})
		return
	}
	defer rows.Close()

	var usage []TempAccessUsage
	for rows.Next() {
		var u TempAccessUsage
		err := rows.Scan(&u.ID, &u.LinkID, &u.IPAddress, &u.UserAgent, &u.ConnectedAt, &u.DisconnectedAt)
		if err != nil {
			continue
		}
		if u.DisconnectedAt != nil {
			u.Duration = int(u.DisconnectedAt.Sub(u.ConnectedAt).Seconds())
		}
		usage = append(usage, u)
	}

	c.JSON(http.StatusOK, gin.H{"usage": usage})
}

// auditLog helper for audit logging
func (s *Service) auditLog(c *gin.Context, eventType string, details map[string]interface{}) {
	// Implementation would send to audit service
	s.logger.Info("audit event",
		zap.String("event_type", eventType),
		zap.Any("details", details),
		zap.String("ip", c.ClientIP()),
	)
}

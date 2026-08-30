package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The local mirror (ziti_service_policies / ziti_services) is what
// collectZitiPillar — and therefore GET /my/ziti/services and the admin access
// map — resolve a user's overlay reach from. The controller is the source of
// truth; this file keeps the mirror honest about it in two ways:
//
//  1. write-through: every policy the reconciler converges is upserted into the
//     mirror (ON CONFLICT (ziti_id) DO UPDATE, never DO NOTHING — the old
//     DO NOTHING is why stale identity_roles never self-corrected), and
//  2. refresh: a periodic pass that lists the controller and converges the
//     mirror against it, which is what repairs rows nothing has touched since.
//
// ORG ATTRIBUTION. Mirror rows are org-scoped (org_id NOT NULL, FK to
// organizations); controller policies are not. A policy is attributed ONLY from
// in-DB data: its serviceRoles are resolved to service names and matched against
// proxy_routes.ziti_service_name, and the route's org_id is used when EXACTLY
// one org matches. Zero matches (which includes the genuinely platform-wide
// policies — the dark-tier dial policies and the agent bind/dial policies) or
// more than one match means the policy is SKIPPED and COUNTED, never guessed,
// never attached to the default org, and never deleted. A visibly partial mirror
// is a correct outcome; a wrong org assignment leaks reach across tenants.
//
// KNOWN GAP (deliberate follow-up, not this change): platform-wide policies have
// no org at all and org_id is NOT NULL with an FK, so there is no honest way to
// store them today. Representing them properly needs a migration making org_id
// nullable plus every reader matching `org_id = $1 OR org_id IS NULL`. Until
// then they are surfaced as a count (mirror stats + a warn log), not stored.

// zitiPagination is the controller's meta.pagination block. Its ABSENCE means
// completeness is UNKNOWN — never "the collection is empty" — so a response
// without it is an error, not an empty success.
type zitiPagination struct {
	Limit      int `json:"limit"`
	Offset     int `json:"offset"`
	TotalCount int `json:"totalCount"`
}

// zitiListPageLimit is the page size requested from the controller. The
// controller is free to ignore it (and does, above its own maximum), so the
// pager advances by what it RECEIVED, never by what it asked for.
const zitiListPageLimit = 500

// zitiListMaxPages bounds the pager so a controller that never advances cannot
// spin forever.
const zitiListMaxPages = 200

// listAllEdgeEntities pages through an edge-management collection and returns
// every entity. It is the paging the existing list helpers do not do: they send
// limit=1000 and decode only `data`, so a larger installation is silently
// truncated with no way to tell.
//
// Errors (transport, non-200, missing meta.pagination, a stalled page) are
// returned rather than swallowed: a caller that converges a mirror must be able
// to tell "I saw everything" from "I saw some of it".
func listAllEdgeEntities[T any](zm *ZitiManager, collection string) ([]T, error) {
	var out []T
	offset := 0
	for page := 0; ; page++ {
		if page >= zitiListMaxPages {
			return nil, fmt.Errorf("ziti: listing %s exceeded %d pages", collection, zitiListMaxPages)
		}
		data, status, err := zm.mgmtRequest("GET",
			fmt.Sprintf("/edge/management/v1/%s?limit=%d&offset=%d", collection, zitiListPageLimit, offset), nil)
		if err != nil {
			return nil, fmt.Errorf("ziti: listing %s: %w", collection, err)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("ziti: unexpected status %d listing %s", status, collection)
		}
		var resp struct {
			Data []T `json:"data"`
			Meta struct {
				Pagination *zitiPagination `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("ziti: parsing %s listing: %w", collection, err)
		}
		if resp.Meta.Pagination == nil {
			// Completeness unknown. Refusing here is the whole point: treating it
			// as a complete empty listing would let a refresh delete every row.
			return nil, fmt.Errorf("ziti: %s listing has no meta.pagination; completeness unknown", collection)
		}
		total := resp.Meta.Pagination.TotalCount
		out = append(out, resp.Data...)
		if len(resp.Data) == 0 {
			if len(out) < total {
				return nil, fmt.Errorf("ziti: %s listing stalled at %d of %d", collection, len(out), total)
			}
			return out, nil
		}
		offset += len(resp.Data) // advance by received, not by the requested limit
		if offset >= total {
			return out, nil
		}
	}
}

// ---------------------------------------------------------------------------
// Write-through mirror
// ---------------------------------------------------------------------------

// mirrorServicePolicy upserts one policy row so the mirror matches what was just
// applied to the controller. An empty orgID means the caller could not attribute
// the policy to an org (platform-wide, or a route with no org): the row is NOT
// written — it is counted and warned about instead (R2).
func (zm *ZitiManager) mirrorServicePolicy(ctx context.Context, orgID, zitiID, name, policyType string, serviceRoles, identityRoles []string) {
	if zm.db == nil || zm.db.Pool == nil || zitiID == "" {
		return
	}
	if orgID == "" {
		zm.mirrorSkippedNoOrg.Add(1)
		zm.logger.Warn("ziti mirror: policy has no attributable org; not mirrored (platform-wide policies cannot be represented while ziti_service_policies.org_id is NOT NULL)",
			zap.String("policy", name), zap.String("type", policyType))
		return
	}
	if _, err := upsertMirrorPolicy(ctx, zm.db, mirrorPolicyRow{
		ZitiID:        zitiID,
		Name:          name,
		PolicyType:    policyType,
		ServiceRoles:  serviceRoles,
		IdentityRoles: identityRoles,
		OrgID:         orgID,
	}); err != nil {
		zm.logger.Warn("ziti mirror: policy upsert failed",
			zap.String("policy", name), zap.Error(err))
	}
}

// MirrorWritesSkippedNoOrg reports how many converged policies could not be
// mirrored because they have no attributable org. Surfaced on the reconciler
// status endpoint so the gap is visible rather than silent.
func (zm *ZitiManager) MirrorWritesSkippedNoOrg() int64 { return zm.mirrorSkippedNoOrg.Load() }

// mirrorPolicyRow is one row of the ziti_service_policies mirror.
type mirrorPolicyRow struct {
	ZitiID        string
	Name          string
	PolicyType    string
	ServiceRoles  []string
	IdentityRoles []string
	OrgID         string
}

// upsertMirrorPolicy writes one mirror row keyed on the controller's policy id.
// It reports whether the row was inserted (false = an existing row was updated).
//
// ON CONFLICT (ziti_id) DO UPDATE — never DO NOTHING. DO NOTHING is exactly the
// bug this replaces: the four stale rows on the box kept identity_roles that no
// user identity carries, and no later write could correct them.
func upsertMirrorPolicy(ctx context.Context, db *database.PostgresDB, r mirrorPolicyRow) (inserted bool, err error) {
	svcJSON, err := json.Marshal(nonNilRoles(r.ServiceRoles))
	if err != nil {
		return false, err
	}
	identJSON, err := json.Marshal(nonNilRoles(r.IdentityRoles))
	if err != nil {
		return false, err
	}
	ctx = orgctx.WithBypassRLS(ctx)
	err = db.Pool.QueryRow(ctx,
		`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (ziti_id) DO UPDATE
		    SET name = EXCLUDED.name,
		        policy_type = EXCLUDED.policy_type,
		        service_roles = EXCLUDED.service_roles,
		        identity_roles = EXCLUDED.identity_roles,
		        org_id = EXCLUDED.org_id
		 RETURNING (xmax = 0)`,
		r.ZitiID, r.Name, r.PolicyType, svcJSON, identJSON, r.OrgID).Scan(&inserted)
	return inserted, err
}

// nonNilRoles keeps JSONB columns as `[]` rather than `null` for an empty set.
func nonNilRoles(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// ---------------------------------------------------------------------------
// Org attribution (R1)
// ---------------------------------------------------------------------------

// routeOrg is what proxy_routes knows about a Ziti service name.
type routeOrg struct {
	OrgID string
	ToURL string
}

// mirrorAttributor resolves a controller policy or service to an owning org
// using only in-DB data. It never parses an org out of a policy NAME: names like
// `openidx-dial-openidx-Netgraph` are not a reliable encoding, and sanitizeAttr
// is lossy, so a name is not evidence of ownership.
type mirrorAttributor struct {
	routesByService map[string]routeOrg // proxy_routes.ziti_service_name -> owning org
	serviceNameByID map[string]string   // controller service id -> service name
}

// loadMirrorAttributor reads the install-wide route table. RLS is bypassed on
// purpose: attribution has to see every org's routes to decide that exactly one
// of them owns a policy.
func loadMirrorAttributor(ctx context.Context, db *database.PostgresDB) (*mirrorAttributor, error) {
	a := &mirrorAttributor{
		routesByService: map[string]routeOrg{},
		serviceNameByID: map[string]string{},
	}
	ctx = orgctx.WithBypassRLS(ctx)
	rows, err := db.Pool.Query(ctx,
		//orgscope:ignore install-wide Ziti mirror attribution; deliberately reads every org's routes so an ambiguous (multi-org) service name can be detected and skipped
		`SELECT ziti_service_name, COALESCE(org_id::text, ''), COALESCE(to_url, '')
		   FROM proxy_routes
		  WHERE ziti_enabled = true
		    AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// A service name owned by two orgs is ambiguous, so it must attribute to
	// nothing at all rather than to whichever row was read last.
	ambiguous := map[string]bool{}
	for rows.Next() {
		var name, org, toURL string
		if err := rows.Scan(&name, &org, &toURL); err != nil {
			return nil, err
		}
		if prev, ok := a.routesByService[name]; ok && prev.OrgID != org {
			ambiguous[name] = true
			continue
		}
		a.routesByService[name] = routeOrg{OrgID: org, ToURL: toURL}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for name := range ambiguous {
		delete(a.routesByService, name)
	}
	return a, nil
}

// candidateServiceNames turns a policy's serviceRoles into the service names it
// could refer to. `#all` yields no candidate at all: a wildcard names no
// particular service, so it cannot attribute an org.
func (a *mirrorAttributor) candidateServiceNames(serviceRoles []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, role := range serviceRoles {
		switch {
		case role == "#all":
			// deliberately no candidate
		case strings.HasPrefix(role, "@"):
			ref := strings.TrimPrefix(role, "@")
			if name, ok := a.serviceNameByID[ref]; ok {
				add(name)
			} else {
				add(ref) // @name is legal too
			}
		case strings.HasPrefix(role, "#"):
			// Service role attributes are the service's own name by construction
			// (ensureServiceAttr / CreateService both tag the service with it).
			add(strings.TrimPrefix(role, "#"))
		default:
			add(role)
		}
	}
	return out
}

// attribute resolves an org for the given serviceRoles. It requires EXACTLY one
// matching org: zero (platform-wide or unknown services) and more than one both
// mean "skip and count".
func (a *mirrorAttributor) attribute(serviceRoles []string) (orgID string, reason string) {
	cands := a.candidateServiceNames(serviceRoles)
	if len(cands) == 0 {
		return "", "no service-role names a route (wildcard or platform-wide policy)"
	}
	orgs := map[string]bool{}
	matched := 0
	unorged := 0
	for _, c := range cands {
		r, ok := a.routesByService[c]
		if !ok {
			continue
		}
		matched++
		if r.OrgID == "" {
			unorged++
			continue
		}
		orgs[r.OrgID] = true
	}
	switch {
	case matched == 0:
		return "", "no matching ziti-enabled route (platform-wide or unknown service)"
	case unorged > 0:
		// A matched route with no org cannot be attributed honestly either.
		return "", "matched a route with no org_id"
	case len(orgs) > 1:
		return "", fmt.Sprintf("service-roles span %d orgs", len(orgs))
	}
	for o := range orgs {
		return o, ""
	}
	return "", "no org resolved"
}

// ---------------------------------------------------------------------------
// Refresh pass
// ---------------------------------------------------------------------------

// MirrorRefreshStats is the outcome of one refresh. The skip counts are the
// point of the struct: they are what makes a deliberately partial mirror visible
// instead of looking like an empty one.
type MirrorRefreshStats struct {
	PoliciesOnController int      `json:"policies_on_controller"`
	PoliciesInserted     int      `json:"policies_inserted"`
	PoliciesUpdated      int      `json:"policies_updated"`
	PoliciesDeleted      int      `json:"policies_deleted"`
	PoliciesSkipped      int      `json:"policies_skipped_unattributed"`
	SkipReasons          []string `json:"skipped_examples,omitempty"`
	ServicesOnController int      `json:"services_on_controller"`
	ServicesInserted     int      `json:"services_inserted"`
	ServicesUpdated      int      `json:"services_updated"`
	ServicesSkipped      int      `json:"services_skipped_unattributed"`
	// WritesSkippedNoOrg is the cumulative count of converged policies that
	// could not be mirrored for lack of an org (see mirrorServicePolicy).
	WritesSkippedNoOrg int64     `json:"write_through_skipped_no_org"`
	LastRefreshAt      time.Time `json:"last_refresh_at,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
}

// maxSkipExamples bounds how many skip reasons are carried in the stats.
const maxSkipExamples = 20

// refreshZitiMirror converges the local mirror against the controller.
//
// R4: a failed refresh changes NOTHING. Both listings are completed (with real
// paging) BEFORE any write, so a controller that is unreachable — or that
// answers without meta.pagination — leaves the mirror exactly as it was. A
// partial listing can never be mistaken for "the controller has nothing".
//
// R3: rows are deleted only when the complete listing positively proves the
// policy is gone. Anything that could not be attributed is left alone.
func refreshZitiMirror(ctx context.Context, zm *ZitiManager, db *database.PostgresDB, logger *zap.Logger) (MirrorRefreshStats, error) {
	var stats MirrorRefreshStats
	if zm == nil || db == nil || db.Pool == nil {
		return stats, errors.New("ziti mirror refresh: no manager or database")
	}

	// ---- read everything first; nothing is written until both succeed ----
	policies, err := listAllEdgeEntities[ZitiServicePolicyInfo](zm, "service-policies")
	if err != nil {
		return stats, err
	}
	services, err := listAllEdgeEntities[ZitiServiceInfo](zm, "services")
	if err != nil {
		return stats, err
	}
	attributor, err := loadMirrorAttributor(ctx, db)
	if err != nil {
		return stats, err
	}
	for _, s := range services {
		if s.ID != "" && s.Name != "" {
			attributor.serviceNameByID[s.ID] = s.Name
		}
	}
	stats.PoliciesOnController = len(policies)
	stats.ServicesOnController = len(services)

	// ---- services: insert/update only, never delete ----
	// A service row is attributed by its own name against the route table. The
	// mirror is NOT pruned here: a missing controller service is a weaker signal
	// than a missing policy (rows carry route linkage other code paths read), and
	// nothing in the reach verdict depends on removing them.
	for _, s := range services {
		if s.Name == "" || s.ID == "" {
			continue
		}
		r, ok := attributor.routesByService[s.Name]
		if !ok || r.OrgID == "" {
			stats.ServicesSkipped++
			addSkip(&stats, s.Name, "service has no ziti-enabled route with an org")
			continue
		}
		host, port := parseHostPort(r.ToURL)
		ins, err := upsertMirrorService(ctx, db, s.ID, s.Name, host, port, r.OrgID)
		if err != nil {
			logger.Warn("ziti mirror: service upsert failed",
				zap.String("service", s.Name), zap.Error(err))
			continue
		}
		if ins {
			stats.ServicesInserted++
		} else {
			stats.ServicesUpdated++
		}
	}

	// ---- policies ----
	present := map[string]bool{}
	for _, p := range policies {
		if p.ID == "" {
			continue
		}
		present[p.ID] = true
		org, reason := attributor.attribute(p.ServiceRoles)
		if org == "" {
			stats.PoliciesSkipped++
			addSkip(&stats, p.Name, reason)
			continue
		}
		ins, err := upsertMirrorPolicy(ctx, db, mirrorPolicyRow{
			ZitiID:        p.ID,
			Name:          p.Name,
			PolicyType:    p.Type,
			ServiceRoles:  p.ServiceRoles,
			IdentityRoles: p.IdentityRoles,
			OrgID:         org,
		})
		if err != nil {
			logger.Warn("ziti mirror: policy upsert failed",
				zap.String("policy", p.Name), zap.Error(err))
			continue
		}
		if ins {
			stats.PoliciesInserted++
		} else {
			stats.PoliciesUpdated++
		}
	}

	// ---- prune (R3) ----
	// Safe only because the listing above is complete: every controller policy id
	// is in `present`, so a mirror row whose ziti_id is absent is positively gone,
	// not merely unseen. The row's own org_id is in-DB fact, so no guess is made.
	deleted, err := pruneMirrorPolicies(ctx, db, present)
	if err != nil {
		logger.Warn("ziti mirror: prune failed", zap.Error(err))
	}
	stats.PoliciesDeleted = deleted

	stats.WritesSkippedNoOrg = zm.MirrorWritesSkippedNoOrg()
	stats.LastRefreshAt = time.Now().UTC()

	if stats.PoliciesSkipped > 0 || stats.ServicesSkipped > 0 {
		logger.Warn("ziti mirror: some controller objects could not be attributed to an org and were skipped (not stored, not deleted)",
			zap.Int("policies_skipped", stats.PoliciesSkipped),
			zap.Int("services_skipped", stats.ServicesSkipped),
			zap.Strings("examples", stats.SkipReasons))
	}
	logger.Info("ziti mirror refreshed",
		zap.Int("policies", stats.PoliciesOnController),
		zap.Int("inserted", stats.PoliciesInserted),
		zap.Int("updated", stats.PoliciesUpdated),
		zap.Int("deleted", stats.PoliciesDeleted),
		zap.Int("skipped", stats.PoliciesSkipped))
	return stats, nil
}

func addSkip(stats *MirrorRefreshStats, name, reason string) {
	if len(stats.SkipReasons) >= maxSkipExamples {
		return
	}
	stats.SkipReasons = append(stats.SkipReasons, name+": "+reason)
}

// upsertMirrorService writes one ziti_services row. It is keyed on `name`
// because that is what attribution and every reader join on; a controller that
// re-created a service under a new id therefore corrects the row in place.
// A collision on the OTHER unique key (ziti_id, held by a differently-named row)
// is reported, not forced.
func upsertMirrorService(ctx context.Context, db *database.PostgresDB, zitiID, name, host string, port int, orgID string) (inserted bool, err error) {
	if host == "" {
		host = "unknown"
	}
	ctx = orgctx.WithBypassRLS(ctx)
	err = db.Pool.QueryRow(ctx,
		`INSERT INTO ziti_services (ziti_id, name, host, port, org_id, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)
		 ON CONFLICT (name) DO UPDATE
		    SET ziti_id = EXCLUDED.ziti_id,
		        host = EXCLUDED.host,
		        port = EXCLUDED.port,
		        org_id = EXCLUDED.org_id,
		        enabled = true
		 RETURNING (xmax = 0)`,
		zitiID, name, host, port, orgID).Scan(&inserted)
	var pgErr *pgconn.PgError
	if err != nil && errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return false, fmt.Errorf("ziti mirror: service %q collides on %s; left untouched", name, pgErr.ConstraintName)
	}
	return inserted, err
}

// pruneMirrorPolicies removes mirror rows whose controller policy is positively
// absent from a COMPLETE listing. It refuses to run on an empty listing: an
// installation with zero policies is indistinguishable, from here, from a
// listing that silently returned nothing, and wiping the mirror on that is the
// failure mode R4 exists to prevent.
func pruneMirrorPolicies(ctx context.Context, db *database.PostgresDB, present map[string]bool) (int, error) {
	if len(present) == 0 {
		return 0, nil
	}
	keep := make([]string, 0, len(present))
	for id := range present {
		keep = append(keep, id)
	}
	sort.Strings(keep)
	ctx = orgctx.WithBypassRLS(ctx)
	tag, err := db.Pool.Exec(ctx,
		//orgscope:ignore install-wide Ziti mirror prune; each row keeps its own org_id and is removed only when the complete controller listing proves its policy is gone
		`DELETE FROM ziti_service_policies WHERE ziti_id <> ALL($1)`, keep)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Reconciler wiring
// ---------------------------------------------------------------------------

// mirrorState holds the last refresh outcome for the status endpoint.
type mirrorState struct {
	mu    sync.Mutex
	stats MirrorRefreshStats
}

func (m *mirrorState) set(s MirrorRefreshStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = s
}

func (m *mirrorState) setError(err error, skipped int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.LastError = err.Error()
	m.stats.WritesSkippedNoOrg = skipped
}

func (m *mirrorState) snapshot() MirrorRefreshStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// RefreshMirror lists the controller and converges the local mirror. Exported so
// the status endpoint and tests can drive one pass directly. A failure is
// recorded and returned; the mirror is left untouched (R4).
func (rec *ZitiReconciler) RefreshMirror(ctx context.Context) (MirrorRefreshStats, error) {
	zm := rec.provider.Get()
	if zm == nil || !zm.IsInitialized() {
		return rec.mirror.snapshot(), errors.New("ziti mirror refresh: no live Ziti manager")
	}
	stats, err := refreshZitiMirror(ctx, zm, rec.db, rec.logger)
	if err != nil {
		rec.logger.Warn("ziti mirror refresh failed; mirror left unchanged", zap.Error(err))
		rec.mirror.setError(err, zm.MirrorWritesSkippedNoOrg())
		return rec.mirror.snapshot(), err
	}
	rec.mirror.set(stats)
	return stats, nil
}

// MirrorStats returns the last refresh outcome (zero-valued before the first).
func (rec *ZitiReconciler) MirrorStats() MirrorRefreshStats { return rec.mirror.snapshot() }

// routeOrgID returns the owning org of a proxy_route, or "" when there is no
// route (install-wide/internal provisioning) or the route carries no org. It is
// read install-wide on purpose: provisioning runs outside any request's org
// context, and an empty result means "do not mirror", never "use the default".
func (zm *ZitiManager) routeOrgID(ctx context.Context, routeID string) string {
	if routeID == "" || zm.db == nil || zm.db.Pool == nil {
		return ""
	}
	var org string
	err := zm.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide Ziti provisioning; reads the route's own org_id (the value being resolved) keyed by route id
		`SELECT COALESCE(org_id::text, '') FROM proxy_routes WHERE id = $1`, routeID).Scan(&org)
	if err != nil {
		return ""
	}
	return org
}

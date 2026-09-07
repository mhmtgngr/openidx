package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The half of upstream pools an operator can reach.
//
// v130 built the schema, upstream_pools.go renders a pool into the data plane's
// upstream object, and edge_routes.go feeds the renderer -- and nothing could
// create a pool, so upstream_pools was empty on every install and the renderer
// had nothing to render. This file is the missing half: list, create, update,
// delete a pool; add, drain and remove its members; and point a route at one.
//
// Two things here are not CRUD, and they are the reason this is worth building
// rather than deleting:
//
//   - A POOL CAN BE CONFIGURED AND NOT IN EFFECT. BuildUpstream refuses to
//     render a pool with no usable member, because an upstream with no node
//     black-holes the route; the route falls back to its single to_url instead.
//     That is the right runtime behaviour and the wrong thing to leave silent:
//     an operator who has just drained the last member believes traffic stopped.
//     Every response that describes a pool carries in_effect and, when it is
//     false, why -- so the page can say "this pool is not serving; 2 routes are
//     on their single target".
//
//   - DELETING A POOL MOVES TRAFFIC. proxy_routes.upstream_pool_id is
//     ON DELETE SET NULL, so deleting a pool silently reverts every route using
//     it to one backend with no health checking. The delete refuses while any
//     route still names the pool and says which, rather than reporting success
//     for a change the operator did not ask for.

// upstreamPoolMemberView is one backend as the API describes it.
type upstreamPoolMemberView struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
}

// upstreamPoolView is a pool as the API describes it.
//
// InEffect and NotInEffectReason are computed, not stored: they are the answer
// to "is this pool actually serving traffic", which is a property of the
// members and cannot be read off the pool row.
type upstreamPoolView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	Algorithm string `json:"algorithm"`
	HashOn    string `json:"hash_on"`
	HashKey   string `json:"hash_key"`

	HealthCheckEnabled  bool   `json:"health_check_enabled"`
	HealthCheckPath     string `json:"health_check_path"`
	HealthyThreshold    int    `json:"healthy_threshold"`
	UnhealthyThreshold  int    `json:"unhealthy_threshold"`
	HealthCheckInterval int    `json:"health_check_interval"`
	HealthCheckTimeout  int    `json:"health_check_timeout"`
	Retries             *int   `json:"retries"`

	Members []upstreamPoolMemberView `json:"members"`

	// RoutesUsing is how many proxy_routes name this pool. Zero means the pool
	// exists and carries no traffic whatever its members say.
	RoutesUsing int `json:"routes_using"`
	// InEffect is whether a route on this pool would actually be served by it.
	InEffect          bool   `json:"in_effect"`
	NotInEffectReason string `json:"not_in_effect_reason,omitempty"`
}

// poolEffect answers "would a route on this pool be served by it", using the
// same renderer the reconciler uses rather than reimplementing the rule. A
// second implementation of "is this pool usable" would drift from the one that
// decides, and the drift would show up as a page saying the opposite of what
// the edge does.
func poolEffect(p *UpstreamPool, routesUsing int) (bool, string) {
	if _, err := p.BuildUpstream("http", "", ""); err != nil {
		return false, "no usable member: every member is disabled, drained to an unreachable address, or the pool is empty — routes on this pool fall back to their single target"
	}
	if routesUsing == 0 {
		return false, "no route points at this pool yet"
	}
	return true, ""
}

// poolRecord is one pool plus the two things the pool row cannot tell you:
// what its members are called and how many routes point at it. Carried together
// so nothing has to be stashed on the Service, which several requests share.
type poolRecord struct {
	pool        *UpstreamPool
	description string
	memberIDs   map[string]string // "host:port" -> member id
	routesUsing int
}

func (r poolRecord) view() upstreamPoolView {
	p := r.pool
	v := upstreamPoolView{
		ID: p.ID, Name: p.Name, Description: r.description,
		Algorithm: p.Algorithm, HashOn: p.HashOn, HashKey: p.HashKey,
		HealthCheckEnabled:  p.HealthCheckEnabled,
		HealthCheckPath:     p.HealthCheckPath,
		HealthyThreshold:    p.HealthyThreshold,
		UnhealthyThreshold:  p.UnhealthyThreshold,
		HealthCheckInterval: p.HealthCheckInterval,
		HealthCheckTimeout:  p.HealthCheckTimeout,
		Retries:             p.Retries,
		Members:             make([]upstreamPoolMemberView, 0, len(p.Members)),
		RoutesUsing:         r.routesUsing,
	}
	for _, m := range p.Members {
		v.Members = append(v.Members, upstreamPoolMemberView{
			ID:   r.memberIDs[fmt.Sprintf("%s:%d", m.Host, m.Port)],
			Host: m.Host, Port: m.Port, Weight: m.Weight, Enabled: m.Enabled,
		})
	}
	v.InEffect, v.NotInEffectReason = poolEffect(p, r.routesUsing)
	return v
}

// ---- validation ---------------------------------------------------------
//
// The CHECK constraints in v130 are the backstop, not the interface. A pool
// rejected by the database arrives at the operator as a 500 with no field name,
// so every constraint is also checked here, where the message can say which
// value is wrong.

var errPoolValidation = errors.New("invalid upstream pool")

func validatePoolShape(algorithm, hashOn, healthPath string,
	healthy, unhealthy, interval, timeout int, retries *int) error {
	if algorithm != "roundrobin" && algorithm != "chash" {
		return fmt.Errorf("%w: algorithm must be roundrobin or chash", errPoolValidation)
	}
	switch hashOn {
	case "vars", "header", "cookie":
	default:
		return fmt.Errorf("%w: hash_on must be vars, header or cookie", errPoolValidation)
	}
	if !strings.HasPrefix(healthPath, "/") {
		return fmt.Errorf("%w: health_check_path must start with /", errPoolValidation)
	}
	if healthy < 1 || healthy > 10 {
		return fmt.Errorf("%w: healthy_threshold must be between 1 and 10", errPoolValidation)
	}
	if unhealthy < 1 || unhealthy > 10 {
		return fmt.Errorf("%w: unhealthy_threshold must be between 1 and 10", errPoolValidation)
	}
	if interval < 1 || interval > 300 {
		return fmt.Errorf("%w: health_check_interval must be between 1 and 300 seconds", errPoolValidation)
	}
	if timeout < 1 || timeout > 60 {
		return fmt.Errorf("%w: health_check_timeout must be between 1 and 60 seconds", errPoolValidation)
	}
	if retries != nil && (*retries < 0 || *retries > 10) {
		return fmt.Errorf("%w: retries must be between 0 and 10, or omitted to let the data plane decide", errPoolValidation)
	}
	return nil
}

func validateMemberShape(host string, port, weight int) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: host is required", errPoolValidation)
	}
	// A member whose host carries a scheme or a path is the commonest mistake
	// here, and the rendered node would be a string APISIX cannot dial.
	if strings.ContainsAny(host, "/:") {
		return fmt.Errorf("%w: host must be a bare hostname or IP — the port is a separate field", errPoolValidation)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port must be between 1 and 65535", errPoolValidation)
	}
	if weight < 0 || weight > 1000 {
		return fmt.Errorf("%w: weight must be between 0 and 1000 (0 drains the member without removing it)", errPoolValidation)
	}
	return nil
}

// A duplicate pool name or a backend listed twice is a 409 the operator can act
// on, not a 500 that reads as an outage. isUniqueViolation
// (remote_support_legal_hold.go) already draws that line; reused here rather
// than written again.

// ---- reads ---------------------------------------------------------------

// loadPoolsForOrg reads every pool in the caller's org with its members and the
// number of routes pointing at it.
//
// Org-scoped by predicate, not only by RLS: the belt is there to catch the
// query that forgets, and this one does not forget.
func (s *Service) loadPoolsForOrg(ctx context.Context, orgID string, poolID string) ([]poolRecord, error) {
	args := []interface{}{orgID}
	where := "WHERE org_id = $1"
	if poolID != "" {
		where += " AND id = $2"
		args = append(args, poolID)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id::text, name, COALESCE(description,''), algorithm, hash_on, hash_key,
		        health_check_enabled, health_check_path,
		        healthy_threshold, unhealthy_threshold,
		        health_check_interval, health_check_timeout, retries
		 FROM upstream_pools `+where+` ORDER BY name`, args...)
	if err != nil {
		return nil, fmt.Errorf("query upstream pools: %w", err)
	}
	defer rows.Close()

	var records []poolRecord
	ids := make([]string, 0)
	for rows.Next() {
		var p UpstreamPool
		var desc string
		var retries *int
		if err := rows.Scan(&p.ID, &p.Name, &desc, &p.Algorithm, &p.HashOn, &p.HashKey,
			&p.HealthCheckEnabled, &p.HealthCheckPath,
			&p.HealthyThreshold, &p.UnhealthyThreshold,
			&p.HealthCheckInterval, &p.HealthCheckTimeout, &retries); err != nil {
			return nil, fmt.Errorf("scan upstream pool: %w", err)
		}
		p.Retries = retries
		records = append(records, poolRecord{
			pool: &p, description: desc, memberIDs: map[string]string{},
		})
		ids = append(ids, p.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return records, nil
	}

	byID := make(map[string]*poolRecord, len(records))
	for i := range records {
		byID[records[i].pool.ID] = &records[i]
	}

	// Members. Org-scoped on the member row too: a member carries its own
	// org_id, so scoping only through the pool would trust a join to do the
	// isolation the predicate should state.
	mrows, err := s.db.Pool.Query(ctx,
		`SELECT id::text, pool_id::text, host, port, weight, enabled
		 FROM upstream_pool_members
		 WHERE org_id = $1 AND pool_id = ANY($2)
		 ORDER BY host, port`, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("query upstream pool members: %w", err)
	}
	defer mrows.Close()

	for mrows.Next() {
		var id, mPoolID string
		var m UpstreamMember
		if err := mrows.Scan(&id, &mPoolID, &m.Host, &m.Port, &m.Weight, &m.Enabled); err != nil {
			return nil, fmt.Errorf("scan upstream pool member: %w", err)
		}
		if r, ok := byID[mPoolID]; ok {
			r.pool.Members = append(r.pool.Members, m)
			r.memberIDs[fmt.Sprintf("%s:%d", m.Host, m.Port)] = id
		}
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}

	// Routes using each pool. This number decides whether a delete is allowed
	// and whether the pool is in effect, so a failure reading it must not be
	// reported as zero -- zero is "safe to delete, nothing is on it".
	urows, err := s.db.Pool.Query(ctx,
		`SELECT upstream_pool_id::text, COUNT(*)
		 FROM proxy_routes
		 WHERE org_id = $1 AND upstream_pool_id = ANY($2)
		 GROUP BY upstream_pool_id`, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("count routes per pool: %w", err)
	}
	defer urows.Close()
	for urows.Next() {
		var id string
		var n int
		if err := urows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("scan pool usage: %w", err)
		}
		if r, ok := byID[id]; ok {
			r.routesUsing = n
		}
	}
	return records, urows.Err()
}

func (s *Service) handleListUpstreamPools(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	records, err := s.loadPoolsForOrg(c.Request.Context(), org.ID, "")
	if err != nil {
		s.logger.Error("Failed to list upstream pools", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list upstream pools"})
		return
	}

	out := make([]upstreamPoolView, 0, len(records))
	for _, r := range records {
		out = append(out, r.view())
	}
	c.JSON(http.StatusOK, gin.H{"pools": out, "total": len(out)})
}

func (s *Service) handleGetUpstreamPool(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	records, err := s.loadPoolsForOrg(c.Request.Context(), org.ID, c.Param("id"))
	if err != nil {
		s.logger.Error("Failed to get upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get upstream pool"})
		return
	}
	if len(records) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "upstream pool not found"})
		return
	}
	c.JSON(http.StatusOK, records[0].view())
}

// ---- writes --------------------------------------------------------------

func (s *Service) handleCreateUpstreamPool(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Algorithm   string `json:"algorithm"`
		HashOn      string `json:"hash_on"`
		HashKey     string `json:"hash_key"`

		HealthCheckEnabled  *bool  `json:"health_check_enabled"`
		HealthCheckPath     string `json:"health_check_path"`
		HealthyThreshold    int    `json:"healthy_threshold"`
		UnhealthyThreshold  int    `json:"unhealthy_threshold"`
		HealthCheckInterval int    `json:"health_check_interval"`
		HealthCheckTimeout  int    `json:"health_check_timeout"`
		Retries             *int   `json:"retries"`

		// Members may be supplied inline. A pool created with none is legal and
		// reports itself as not in effect until one is added.
		Members []struct {
			Host    string `json:"host"`
			Port    int    `json:"port"`
			Weight  *int   `json:"weight"`
			Enabled *bool  `json:"enabled"`
		} `json:"members"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The defaults mirror v130's column defaults exactly, so a pool created
	// through the API and one created by an INSERT that names only the required
	// columns are the same pool.
	if req.Algorithm == "" {
		req.Algorithm = "roundrobin"
	}
	if req.HashOn == "" {
		req.HashOn = "vars"
	}
	if req.HashKey == "" {
		req.HashKey = "remote_addr"
	}
	if req.HealthCheckPath == "" {
		req.HealthCheckPath = "/"
	}
	if req.HealthyThreshold == 0 {
		req.HealthyThreshold = 2
	}
	if req.UnhealthyThreshold == 0 {
		req.UnhealthyThreshold = 3
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = 5
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = 3
	}
	healthEnabled := true
	if req.HealthCheckEnabled != nil {
		healthEnabled = *req.HealthCheckEnabled
	}

	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if err := validatePoolShape(req.Algorithm, req.HashOn, req.HealthCheckPath,
		req.HealthyThreshold, req.UnhealthyThreshold,
		req.HealthCheckInterval, req.HealthCheckTimeout, req.Retries); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, m := range req.Members {
		w := 1
		if m.Weight != nil {
			w = *m.Weight
		}
		if err := validateMemberShape(m.Host, m.Port, w); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// One transaction: a pool that exists with only some of the members the
	// operator declared is a load balancer weighted differently from what they
	// asked for, which is worse than the create having failed.
	tx, err := s.db.Pool.Begin(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to begin upstream pool create", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upstream pool"})
		return
	}
	defer func() { _ = tx.Rollback(c.Request.Context()) }()

	var id string
	err = tx.QueryRow(c.Request.Context(),
		`INSERT INTO upstream_pools (org_id, name, description, algorithm, hash_on, hash_key,
		    health_check_enabled, health_check_path, healthy_threshold, unhealthy_threshold,
		    health_check_interval, health_check_timeout, retries)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 RETURNING id::text`,
		org.ID, strings.TrimSpace(req.Name), req.Description, req.Algorithm, req.HashOn, req.HashKey,
		healthEnabled, req.HealthCheckPath, req.HealthyThreshold, req.UnhealthyThreshold,
		req.HealthCheckInterval, req.HealthCheckTimeout, req.Retries).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an upstream pool with that name already exists"})
			return
		}
		s.logger.Error("Failed to create upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upstream pool"})
		return
	}

	for _, m := range req.Members {
		weight := 1
		if m.Weight != nil {
			weight = *m.Weight
		}
		enabled := true
		if m.Enabled != nil {
			enabled = *m.Enabled
		}
		if _, err := tx.Exec(c.Request.Context(),
			`INSERT INTO upstream_pool_members (pool_id, org_id, host, port, weight, enabled)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			id, org.ID, strings.TrimSpace(m.Host), m.Port, weight, enabled); err != nil {
			if isUniqueViolation(err) {
				c.JSON(http.StatusConflict, gin.H{
					"error": fmt.Sprintf("member %s:%d is listed twice — a backend listed twice would silently double its share", m.Host, m.Port)})
				return
			}
			s.logger.Error("Failed to create upstream pool member", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upstream pool"})
			return
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		s.logger.Error("Failed to commit upstream pool create", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upstream pool"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_created", id, "upstream_pool", map[string]interface{}{
		"name":      req.Name,
		"algorithm": req.Algorithm,
		"members":   len(req.Members),
	})

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": "upstream pool created",
		// Said at creation because it is the state a new pool is always in, and
		// the operator's next question is why traffic has not moved.
		"in_effect": false,
		"note":      "no route points at this pool yet — set upstream_pool_id on a route to put it in effect",
	})
}

func (s *Service) handleUpdateUpstreamPool(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Algorithm   *string `json:"algorithm"`
		HashOn      *string `json:"hash_on"`
		HashKey     *string `json:"hash_key"`

		HealthCheckEnabled  *bool   `json:"health_check_enabled"`
		HealthCheckPath     *string `json:"health_check_path"`
		HealthyThreshold    *int    `json:"healthy_threshold"`
		UnhealthyThreshold  *int    `json:"unhealthy_threshold"`
		HealthCheckInterval *int    `json:"health_check_interval"`
		HealthCheckTimeout  *int    `json:"health_check_timeout"`
		// Retries is tri-state on the wire: absent leaves it, null clears it
		// back to "let the data plane decide", a number sets it. RetriesSet
		// separates "absent" from "null", which a *int alone cannot.
		Retries    *int  `json:"retries"`
		RetriesSet *bool `json:"retries_set"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	records, err := s.loadPoolsForOrg(c.Request.Context(), org.ID, id)
	if err != nil {
		s.logger.Error("Failed to load upstream pool for update", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update upstream pool"})
		return
	}
	if len(records) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "upstream pool not found"})
		return
	}
	record := records[0]
	p := record.pool
	description := record.description

	if req.Name != nil {
		p.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		description = *req.Description
	}
	if req.Algorithm != nil {
		p.Algorithm = *req.Algorithm
	}
	if req.HashOn != nil {
		p.HashOn = *req.HashOn
	}
	if req.HashKey != nil {
		p.HashKey = *req.HashKey
	}
	if req.HealthCheckEnabled != nil {
		p.HealthCheckEnabled = *req.HealthCheckEnabled
	}
	if req.HealthCheckPath != nil {
		p.HealthCheckPath = *req.HealthCheckPath
	}
	if req.HealthyThreshold != nil {
		p.HealthyThreshold = *req.HealthyThreshold
	}
	if req.UnhealthyThreshold != nil {
		p.UnhealthyThreshold = *req.UnhealthyThreshold
	}
	if req.HealthCheckInterval != nil {
		p.HealthCheckInterval = *req.HealthCheckInterval
	}
	if req.HealthCheckTimeout != nil {
		p.HealthCheckTimeout = *req.HealthCheckTimeout
	}
	if req.Retries != nil {
		p.Retries = req.Retries
	} else if req.RetriesSet != nil && !*req.RetriesSet {
		p.Retries = nil
	}

	if p.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if err := validatePoolShape(p.Algorithm, p.HashOn, p.HealthCheckPath,
		p.HealthyThreshold, p.UnhealthyThreshold,
		p.HealthCheckInterval, p.HealthCheckTimeout, p.Retries); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE upstream_pools SET name=$1, description=$2, algorithm=$3, hash_on=$4, hash_key=$5,
		    health_check_enabled=$6, health_check_path=$7, healthy_threshold=$8,
		    unhealthy_threshold=$9, health_check_interval=$10, health_check_timeout=$11,
		    retries=$12, updated_at=NOW()
		 WHERE id=$13 AND org_id=$14`,
		p.Name, description, p.Algorithm, p.HashOn, p.HashKey,
		p.HealthCheckEnabled, p.HealthCheckPath, p.HealthyThreshold,
		p.UnhealthyThreshold, p.HealthCheckInterval, p.HealthCheckTimeout,
		p.Retries, id, org.ID)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an upstream pool with that name already exists"})
			return
		}
		s.logger.Error("Failed to update upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update upstream pool"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "upstream pool not found"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_updated", id, "upstream_pool", map[string]interface{}{
		"name":      p.Name,
		"algorithm": p.Algorithm,
	})

	record.description = description
	c.JSON(http.StatusOK, record.view())
}

// handleDeleteUpstreamPool refuses while routes still point at the pool.
//
// The foreign key is ON DELETE SET NULL, so the database would happily accept
// this and revert every route to its single to_url with no health checking --
// a traffic change the operator did not ask for and would not be told about.
// Refusing and naming the routes makes the detach an explicit act.
func (s *Service) handleDeleteUpstreamPool(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT name FROM proxy_routes
		 WHERE org_id = $1 AND upstream_pool_id = $2 ORDER BY name LIMIT 25`, org.ID, id)
	if err != nil {
		s.logger.Error("Failed to check routes before deleting an upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete upstream pool"})
		return
	}
	var inUse []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			s.logger.Error("Failed to scan routes before deleting an upstream pool", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete upstream pool"})
			return
		}
		inUse = append(inUse, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Error("Failed to read routes before deleting an upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete upstream pool"})
		return
	}
	if len(inUse) > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error": "upstream pool is still in use",
			"detail": "deleting it would move these routes back to a single backend with no health checking; " +
				"clear upstream_pool_id on each route first",
			"routes": inUse,
		})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM upstream_pools WHERE id=$1 AND org_id=$2`, id, org.ID)
	if err != nil {
		s.logger.Error("Failed to delete upstream pool", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete upstream pool"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "upstream pool not found"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_deleted", id, "upstream_pool", nil)
	c.JSON(http.StatusOK, gin.H{"message": "upstream pool deleted"})
}

// ---- members -------------------------------------------------------------

func (s *Service) handleAddUpstreamPoolMember(c *gin.Context) {
	poolID := c.Param("id")

	var req struct {
		Host    string `json:"host" binding:"required"`
		Port    int    `json:"port" binding:"required"`
		Weight  *int   `json:"weight"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	weight := 1
	if req.Weight != nil {
		weight = *req.Weight
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := validateMemberShape(req.Host, req.Port, weight); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// The pool is confirmed to belong to the caller's org BEFORE the insert.
	// Without this, another tenant's pool id would take a member carrying this
	// org's org_id — a row that passes RLS here and changes what their pool
	// serves.
	var exists bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM upstream_pools WHERE id=$1 AND org_id=$2)`,
		poolID, org.ID).Scan(&exists); err != nil {
		s.logger.Error("Failed to load pool before adding a member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add member"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "upstream pool not found"})
		return
	}

	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO upstream_pool_members (pool_id, org_id, host, port, weight, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id::text`,
		poolID, org.ID, strings.TrimSpace(req.Host), req.Port, weight, enabled).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "that backend is already a member of this pool — listing it twice would silently double its share"})
			return
		}
		s.logger.Error("Failed to add upstream pool member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add member"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_member_added", poolID, "upstream_pool", map[string]interface{}{
		"host": req.Host, "port": req.Port, "weight": weight, "enabled": enabled,
	})
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "member added"})
}

func (s *Service) handleUpdateUpstreamPoolMember(c *gin.Context) {
	poolID, memberID := c.Param("id"), c.Param("memberId")

	var req struct {
		Weight  *int  `json:"weight"`
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Weight == nil && req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nothing to change: send weight, enabled, or both"})
		return
	}
	if req.Weight != nil && (*req.Weight < 0 || *req.Weight > 1000) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "weight must be between 0 and 1000 (0 drains the member without removing it)"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE upstream_pool_members
		 SET weight = COALESCE($1, weight), enabled = COALESCE($2, enabled), updated_at = NOW()
		 WHERE id=$3 AND pool_id=$4 AND org_id=$5`,
		req.Weight, req.Enabled, memberID, poolID, org.ID)
	if err != nil {
		s.logger.Error("Failed to update upstream pool member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update member"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_member_updated", poolID, "upstream_pool", map[string]interface{}{
		"member_id": memberID, "weight": req.Weight, "enabled": req.Enabled,
	})
	s.respondWithPoolEffect(c, org.ID, poolID, "member updated")
}

func (s *Service) handleDeleteUpstreamPoolMember(c *gin.Context) {
	poolID, memberID := c.Param("id"), c.Param("memberId")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM upstream_pool_members WHERE id=$1 AND pool_id=$2 AND org_id=$3`,
		memberID, poolID, org.ID)
	if err != nil {
		s.logger.Error("Failed to delete upstream pool member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove member"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}

	s.logAuditEvent(c, "upstream_pool_member_removed", poolID, "upstream_pool", map[string]interface{}{
		"member_id": memberID,
	})
	s.respondWithPoolEffect(c, org.ID, poolID, "member removed")
}

// respondWithPoolEffect answers a member change with what the pool now does.
//
// This is the whole point of the member endpoints returning more than "ok".
// Removing or draining the last enabled member does not stop the routes on that
// pool -- BuildUpstream refuses to render an empty upstream, so they revert to
// their single to_url. An operator who has just drained a pool for maintenance
// and is told "member removed" would reasonably believe traffic stopped.
func (s *Service) respondWithPoolEffect(c *gin.Context, orgID, poolID, message string) {
	records, err := s.loadPoolsForOrg(c.Request.Context(), orgID, poolID)
	if err != nil || len(records) == 0 {
		if err != nil {
			s.logger.Warn("member changed but the pool could not be re-read to report its effect",
				logsafe.String("pool_id", poolID), zap.Error(err))
		}
		// The change itself succeeded; say so without claiming an effect that
		// was not measured.
		c.JSON(http.StatusOK, gin.H{"message": message})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": message, "pool": records[0].view()})
}

// resolvePoolForRoute validates a route's requested upstream_pool_id.
//
// Returns (nil, nil) when the route is being put back on its single to_url.
// A pool id belonging to another tenant is indistinguishable from one that does
// not exist, which is the point.
func (s *Service) resolvePoolForRoute(ctx context.Context, orgID, poolID string) (*string, error) {
	poolID = strings.TrimSpace(poolID)
	if poolID == "" {
		return nil, nil
	}
	var id string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id::text FROM upstream_pools WHERE id=$1 AND org_id=$2`, poolID, orgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("upstream pool not found")
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

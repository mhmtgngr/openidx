package access

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The admin API for network resources (network_resources.go): the list, the
// create, one resource's network target, the organization's tunnel policy, and
// a CSV import for moving a VPN's rule set across
// (docs/migration-from-globalprotect.md). Every route is adminOnly and reaches
// only the caller's organization; each write asks the reconciler to converge.

// networkResourceView is one network resource as the API describes it.
type networkResourceView struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	ServiceName string         `json:"service_name"`
	Target      *NetworkTarget `json:"target"`
	// SyncStatus is the reconciler's converge state for the service:
	// "synced", "error: ...", or "" when it has not run since the change.
	SyncStatus string `json:"sync_status,omitempty"`
}

// networkPolicyView is the organization's tunnel policy.
type networkPolicyView struct {
	AlwaysOn                  bool   `json:"always_on"`
	SplitTunnel               bool   `json:"split_tunnel"`
	BlockDirectCorporateCIDRs bool   `json:"block_direct_corporate_cidrs"`
	UpdatedAt                 string `json:"updated_at,omitempty"`
}

func (s *Service) networkSyncStatus(name string) string {
	if s.zitiReconciler == nil {
		return ""
	}
	return s.zitiReconciler.StatusSnapshot()[name]
}

// loadNetworkTarget reads one application's target. ok is false when the
// application has none.
func (s *Service) loadNetworkTarget(ctx context.Context, orgID, appID string) (NetworkTarget, bool, error) {
	var t NetworkTarget
	var portRanges []byte
	var fwdPort *int
	var fwdAddr *string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT hosts, COALESCE(cidrs::text[], '{}'), dns_names, port_ranges, protocols, forward_address, forward_port
		   FROM network_targets WHERE application_id = $1 AND org_id = $2`, appID, orgID).
		Scan(&t.Hosts, &t.CIDRs, &t.DNSNames, &portRanges, &t.Protocols, &fwdAddr, &fwdPort)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	if len(portRanges) > 0 {
		_ = json.Unmarshal(portRanges, &t.PortRanges)
	}
	if fwdAddr != nil {
		t.ForwardAddress = *fwdAddr
	}
	if fwdPort != nil {
		t.ForwardPort = *fwdPort
	}
	t.ApplicationID = appID
	return t, true, nil
}

// networkAppKind returns the application's kind, or ok=false when the
// application is not in the organization.
func (s *Service) networkAppKind(ctx context.Context, orgID, appID string) (string, bool, error) {
	if _, err := uuid.Parse(appID); err != nil {
		return "", false, nil
	}
	var kind string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(kind, 'web') FROM applications WHERE id = $1 AND org_id = $2`, appID, orgID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return kind, err == nil, err
}

// upsertNetworkTarget writes a normalized target through exec (the pool, or a
// transaction). The conflict arm updates only a row of the same organization.
func (s *Service) upsertNetworkTarget(ctx context.Context, exec func(context.Context, string, ...interface{}) error, orgID string, t NetworkTarget) error {
	pr, _ := json.Marshal(t.PortRanges)
	var fwdAddr interface{}
	if t.ForwardAddress != "" {
		fwdAddr = t.ForwardAddress
	}
	var fwdPort interface{}
	if t.ForwardPort != 0 {
		fwdPort = t.ForwardPort
	}
	if t.Hosts == nil {
		t.Hosts = []string{}
	}
	if t.CIDRs == nil {
		t.CIDRs = []string{}
	}
	if t.DNSNames == nil {
		t.DNSNames = []string{}
	}
	return exec(ctx,
		`INSERT INTO network_targets (application_id, org_id, hosts, cidrs, dns_names, port_ranges, protocols, forward_address, forward_port)
		 VALUES ($1, $2, $3, $4::cidr[], $5, $6, $7, $8, $9)
		 ON CONFLICT (application_id) DO UPDATE SET
		   hosts = EXCLUDED.hosts, cidrs = EXCLUDED.cidrs, dns_names = EXCLUDED.dns_names,
		   port_ranges = EXCLUDED.port_ranges, protocols = EXCLUDED.protocols,
		   forward_address = EXCLUDED.forward_address, forward_port = EXCLUDED.forward_port,
		   updated_at = NOW()
		 WHERE network_targets.org_id = EXCLUDED.org_id`,
		t.ApplicationID, orgID, t.Hosts, t.CIDRs, t.DNSNames, string(pr), t.Protocols, fwdAddr, fwdPort)
}

// handleListNetworkResources lists the organization's network resources.
func (s *Service) handleListNetworkResources(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id::text, name, COALESCE(description, ''), COALESCE(enabled, true)
		   FROM applications WHERE org_id = $1 AND kind = 'network' ORDER BY name`, org.ID)
	if err != nil {
		s.logger.Error("list network resources", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list network resources"})
		return
	}
	var out []networkResourceView
	for rows.Next() {
		var v networkResourceView
		if err := rows.Scan(&v.ID, &v.Name, &v.Description, &v.Enabled); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list network resources"})
			return
		}
		out = append(out, v)
	}
	rows.Close()
	for i := range out {
		out[i].ServiceName = networkServiceName(out[i].ID)
		if t, ok, terr := s.loadNetworkTarget(ctx, org.ID, out[i].ID); terr == nil && ok {
			tt := t
			out[i].Target = &tt
		}
		out[i].SyncStatus = s.networkSyncStatus(out[i].ServiceName)
	}
	if out == nil {
		out = []networkResourceView{}
	}
	c.JSON(http.StatusOK, gin.H{"resources": out, "total": len(out)})
}

// createNetworkResource inserts a kind='network' application and, when given,
// its target, in one transaction. Returns the new id.
func (s *Service) createNetworkResource(ctx context.Context, orgID, name, description string, target *NetworkTarget) (string, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id := uuid.New().String()
	if _, err := tx.Exec(ctx,
		`INSERT INTO applications (id, client_id, name, description, type, protocol, enabled, kind, org_id)
		 VALUES ($1, $2, $3, $4, 'network', 'network', true, 'network', $5)`,
		id, "network-"+id, name, description, orgID); err != nil {
		return "", err
	}
	if target != nil {
		target.ApplicationID = id
		if err := s.upsertNetworkTarget(ctx, func(ctx context.Context, q string, args ...interface{}) error {
			_, e := tx.Exec(ctx, q, args...)
			return e
		}, orgID, *target); err != nil {
			return "", err
		}
	}
	return id, tx.Commit(ctx)
}

// handleCreateNetworkResource creates a network resource.
func (s *Service) handleCreateNetworkResource(c *gin.Context) {
	var req struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Target      *NetworkTarget `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required (at most 255 characters)"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var target *NetworkTarget
	if req.Target != nil {
		norm, verr := normalizeNetworkTarget(*req.Target)
		if verr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": verr.Error()})
			return
		}
		target = &norm
	}
	id, err := s.createNetworkResource(ctx, org.ID, req.Name, req.Description, target)
	if err != nil {
		s.logger.Error("create network resource", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create network resource"})
		return
	}
	s.logAuditEvent(c, "network_resource.create", id, "application", map[string]interface{}{"name": req.Name})
	s.enqueueReconcile()
	c.JSON(http.StatusCreated, networkResourceView{
		ID: id, Name: req.Name, Description: req.Description, Enabled: true,
		ServiceName: networkServiceName(id), Target: target,
	})
}

// handleGetNetworkTarget returns a resource's network target.
func (s *Service) handleGetNetworkTarget(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	appID := c.Param("id")
	if _, ok, err := s.networkAppKind(ctx, org.ID, appID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read resource"})
		return
	} else if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return
	}
	t, ok, err := s.loadNetworkTarget(ctx, org.ID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read network target"})
		return
	}
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "this resource has no network target"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"target":       t,
		"service_name": networkServiceName(appID),
		"sync_status":  s.networkSyncStatus(networkServiceName(appID)),
	})
}

// handlePutNetworkTarget sets a resource's network target. The resource must
// be of kind 'network': a web or privileged resource is reached another way,
// and giving it a tunneler intercept would open a second path past its
// conditions.
func (s *Service) handlePutNetworkTarget(c *gin.Context) {
	var req NetworkTarget
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	appID := c.Param("id")
	kind, ok, err := s.networkAppKind(ctx, org.ID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read resource"})
		return
	}
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return
	}
	if kind != "network" {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("resource is of kind %q; a network target belongs to a network resource", kind)})
		return
	}
	req.ApplicationID = appID
	norm, err := normalizeNetworkTarget(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.upsertNetworkTarget(ctx, func(ctx context.Context, q string, args ...interface{}) error {
		_, e := s.db.Pool.Exec(ctx, q, args...)
		return e
	}, org.ID, norm); err != nil {
		s.logger.Error("save network target", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save network target"})
		return
	}
	s.logAuditEvent(c, "network_resource.target_set", appID, "application", map[string]interface{}{
		"addresses": len(norm.interceptAddresses()), "port_ranges": len(norm.PortRanges),
	})
	s.enqueueReconcile()
	c.JSON(http.StatusOK, gin.H{"target": norm, "service_name": networkServiceName(appID)})
}

// handleDeleteNetworkTarget removes a resource's network target; the
// reconciler then removes its service from the overlay.
func (s *Service) handleDeleteNetworkTarget(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	appID := c.Param("id")
	if _, err := uuid.Parse(appID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM network_targets WHERE application_id = $1 AND org_id = $2`, appID, org.ID)
	if err != nil {
		s.logger.Error("delete network target", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete network target"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "this resource has no network target"})
		return
	}
	s.logAuditEvent(c, "network_resource.target_delete", appID, "application", nil)
	s.enqueueReconcile()
	c.Status(http.StatusNoContent)
}

// handleGetNetworkPolicy returns the organization's tunnel policy; a missing
// row is the defaults.
func (s *Service) handleGetNetworkPolicy(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	v := networkPolicyView{SplitTunnel: true}
	var updated *string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT always_on, split_tunnel, block_direct_corporate_cidrs, to_char(updated_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')
		   FROM org_network_policy WHERE org_id = $1`, org.ID).
		Scan(&v.AlwaysOn, &v.SplitTunnel, &v.BlockDirectCorporateCIDRs, &updated)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("read network policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read network policy"})
		return
	}
	if updated != nil {
		v.UpdatedAt = *updated
	}
	c.JSON(http.StatusOK, v)
}

// handlePutNetworkPolicy sets the organization's tunnel policy. Fields left
// out keep their stored (or default) value.
func (s *Service) handlePutNetworkPolicy(c *gin.Context) {
	var req struct {
		AlwaysOn                  *bool `json:"always_on"`
		SplitTunnel               *bool `json:"split_tunnel"`
		BlockDirectCorporateCIDRs *bool `json:"block_direct_corporate_cidrs"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var updatedBy interface{}
	if uid := c.GetString("user_id"); uid != "" {
		if _, perr := uuid.Parse(uid); perr == nil {
			updatedBy = uid
		}
	}
	var v networkPolicyView
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO org_network_policy (org_id, always_on, split_tunnel, block_direct_corporate_cidrs, updated_by)
		 VALUES ($1, COALESCE($2, false), COALESCE($3, true), COALESCE($4, false), $5)
		 ON CONFLICT (org_id) DO UPDATE SET
		   always_on = COALESCE($2, org_network_policy.always_on),
		   split_tunnel = COALESCE($3, org_network_policy.split_tunnel),
		   block_direct_corporate_cidrs = COALESCE($4, org_network_policy.block_direct_corporate_cidrs),
		   updated_by = $5, updated_at = NOW()
		 RETURNING always_on, split_tunnel, block_direct_corporate_cidrs, to_char(updated_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')`,
		org.ID, req.AlwaysOn, req.SplitTunnel, req.BlockDirectCorporateCIDRs, updatedBy).
		Scan(&v.AlwaysOn, &v.SplitTunnel, &v.BlockDirectCorporateCIDRs, &v.UpdatedAt)
	if err != nil {
		s.logger.Error("save network policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save network policy"})
		return
	}
	s.logAuditEvent(c, "network_policy.update", org.ID, "organization", map[string]interface{}{
		"always_on": v.AlwaysOn, "split_tunnel": v.SplitTunnel, "block_direct_corporate_cidrs": v.BlockDirectCorporateCIDRs,
	})
	c.JSON(http.StatusOK, v)
}

// ---- CSV import ----

// networkImportMaxRows bounds one import; a GlobalProtect rule set larger than
// this goes in several files.
const networkImportMaxRows = 500

// networkImportRow is one parsed CSV row.
type networkImportRow struct {
	Line   int           `json:"line"`
	Name   string        `json:"name"`
	Group  string        `json:"group,omitempty"`
	Target NetworkTarget `json:"target"`
	Error  string        `json:"error,omitempty"`
}

// splitCell splits a CSV cell on ';' or whitespace.
func splitCell(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' || r == '|' })
}

// parsePortList reads "443;8000-8100" into ranges.
func parsePortList(s string) ([]PortRange, error) {
	var out []PortRange
	for _, p := range splitCell(s) {
		lo, hi, isRange := strings.Cut(p, "-")
		l, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("port %q is not a number", p)
		}
		h := l
		if isRange {
			if h, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("port %q is not a range", p)
			}
		}
		out = append(out, PortRange{Low: l, High: h})
	}
	return out, nil
}

// parseNetworkImportCSV reads the import format. The header names the columns
// (any order, case-insensitive): name (required), hosts, cidrs, dns_names,
// ports, protocols, forward_address, forward_port, group. Lists inside a cell
// are separated by ';'. Each row is validated on its own; a bad row carries
// its error and does not stop the others.
func parseNetworkImportCSV(r io.Reader) ([]networkImportRow, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\uFEFF")))] = i
	}
	if _, ok := col["name"]; !ok {
		return nil, errors.New(`the header must name a "name" column`)
	}
	cell := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	var out []networkImportRow
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		if len(out) >= networkImportMaxRows {
			return nil, fmt.Errorf("more than %d rows; split the file", networkImportMaxRows)
		}
		row := networkImportRow{Line: line, Name: cell(rec, "name"), Group: cell(rec, "group")}
		t := NetworkTarget{
			Hosts:          splitCell(cell(rec, "hosts")),
			CIDRs:          splitCell(cell(rec, "cidrs")),
			DNSNames:       splitCell(cell(rec, "dns_names")),
			Protocols:      splitCell(cell(rec, "protocols")),
			ForwardAddress: cell(rec, "forward_address"),
		}
		var problems []string
		if row.Name == "" {
			problems = append(problems, "name is empty")
		}
		if ports := cell(rec, "ports"); ports != "" {
			pr, perr := parsePortList(ports)
			if perr != nil {
				problems = append(problems, perr.Error())
			}
			t.PortRanges = pr
		}
		if fp := cell(rec, "forward_port"); fp != "" {
			n, perr := strconv.Atoi(fp)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("forward_port %q is not a number", fp))
			}
			t.ForwardPort = n
		}
		if len(problems) == 0 {
			norm, verr := normalizeNetworkTarget(t)
			if verr != nil {
				problems = append(problems, verr.Error())
			}
			t = norm
		}
		row.Target = t
		if len(problems) > 0 {
			row.Error = strings.Join(problems, "; ")
		}
		out = append(out, row)
	}
	return out, nil
}

// handleImportNetworkResources creates network resources from a CSV body
// (text/csv, or multipart form field "file"). ?dry_run=true parses and
// validates without writing. A row naming a group assigns the new resource to
// that group of the organization; a group that does not exist is reported on
// the row and the resource is created unassigned.
func (s *Service) handleImportNetworkResources(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var src io.Reader = io.LimitReader(c.Request.Body, 2<<20)
	if fh, ferr := c.FormFile("file"); ferr == nil {
		f, oerr := fh.Open()
		if oerr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open the uploaded file"})
			return
		}
		defer f.Close()
		src = io.LimitReader(f, 2<<20)
	}
	rows, err := parseNetworkImportCSV(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dryRun := c.Query("dry_run") == "true"
	type result struct {
		networkImportRow
		ID      string `json:"id,omitempty"`
		Warning string `json:"warning,omitempty"`
	}
	results := make([]result, 0, len(rows))
	created, failed := 0, 0
	for _, r := range rows {
		res := result{networkImportRow: r}
		if r.Error != "" || dryRun {
			if r.Error != "" {
				failed++
			}
			results = append(results, res)
			continue
		}
		t := r.Target
		id, cerr := s.createNetworkResource(ctx, org.ID, r.Name, "Imported from CSV", &t)
		if cerr != nil {
			s.logger.Warn("network import: create failed", zap.Int("line", r.Line), zap.Error(cerr))
			res.Error = "failed to create the resource"
			failed++
			results = append(results, res)
			continue
		}
		res.ID = id
		created++
		if r.Group != "" {
			tag, gerr := s.db.Pool.Exec(ctx,
				`INSERT INTO group_application_assignments (group_id, application_id, org_id)
				 SELECT g.id, $1, $2 FROM groups g WHERE g.name = $3 AND g.org_id = $2
				 ON CONFLICT (group_id, application_id) DO NOTHING`, id, org.ID, r.Group)
			if gerr != nil || tag.RowsAffected() == 0 {
				res.Warning = fmt.Sprintf("group %q was not found; the resource is unassigned", r.Group)
			}
		}
		results = append(results, res)
	}
	if created > 0 {
		s.logAuditEvent(c, "network_resource.import", org.ID, "organization", map[string]interface{}{"created": created, "failed": failed})
		s.enqueueReconcile()
	}
	c.JSON(http.StatusOK, gin.H{"dry_run": dryRun, "created": created, "failed": failed, "rows": results})
}

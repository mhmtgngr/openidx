package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The network-resource orphan sweep.
//
// WHAT IT CLOSES. pruneNetworkServices, which runs inside every reconcile
// pass, is driven by the SERVICE listing: it finds an openidx-net-<app>
// service nobody wants and removes its policies and configs by name. Anything
// that outlived its service is invisible to it:
//
//   - a pass that created the -intercept/-host configs and then failed before
//     (or while) creating the service;
//   - a prune whose service delete succeeded and whose config or policy deletes
//     failed (those failures are logged at Debug and never retried, because the
//     next pass no longer lists the service);
//   - a Bind/Dial/service-edge-router policy left by an interrupted teardown.
//
// None of these grants reach on its own, but each is a controller object with
// nothing in the database pointing at it, and an intercept.v1 config still
// names the target's addresses. This sweep lists the controller side by the
// OBJECT, not by the service, so it sees them.
//
// WHAT IT MAY TOUCH. Only objects whose name is exactly one the network
// reconciler writes for an application id -- networkServicePrefix followed by
// a canonical lower-case UUID -- and, for configs, of the config type the
// reconciler writes under that name; for services, carrying the
// openidx-managed role attribute the reconciler sets. Anything else, however
// close its name, is never deleted. That is the ownership marker: the
// reconciler tags nothing else, so the name shape plus type is the proof.
//
// WHEN IT DELETES. An application's objects are orphaned only when the
// database, read AFTER the controller listing, says that application no longer
// owns a network service (row gone, disabled, moved off kind 'network', or no
// network target) -- the same predicate the reconciler's desired set uses.
// Every object of that application must be older than the grace period, so an
// object a reconcile pass on another replica is creating right now is never
// raced. A failed or incomplete listing, or a failed database read, aborts the
// run: an orphan is only ever inferred from a complete picture.
//
// HOW MUCH. ZITI_ORPHAN_SWEEP=observe (the default) logs and counts what it
// would delete and deletes nothing; enforce deletes, at most
// ZITI_ORPHAN_SWEEP_MAX_DELETES objects per run; off does not run. One
// replica per interval (leader.RunPeriodic).

const (
	orphanSweepOff     = "off"
	orphanSweepObserve = "observe"
	orphanSweepEnforce = "enforce"

	orphanSweepInterval          = 15 * time.Minute
	orphanSweepDefaultGrace      = 30 * time.Minute
	orphanSweepMinGrace          = 5 * time.Minute
	orphanSweepDefaultMaxDeletes = 20
	orphanSweepMaxMaxDeletes     = 500
)

// NetworkOrphanSweepConfig is the sweep's operator-set behaviour.
type NetworkOrphanSweepConfig struct {
	Mode       string        // off | observe | enforce
	Grace      time.Duration // an application with any younger object is left alone
	MaxDeletes int           // per run, enforce only
	Interval   time.Duration
}

// NetworkOrphanSweepConfigFromEnv reads ZITI_ORPHAN_SWEEP,
// ZITI_ORPHAN_SWEEP_GRACE_MINUTES and ZITI_ORPHAN_SWEEP_MAX_DELETES. An
// unrecognised mode reads as observe: a typo must not turn deletes on, and
// must not silently turn the report off either.
func NetworkOrphanSweepConfigFromEnv() NetworkOrphanSweepConfig {
	cfg := NetworkOrphanSweepConfig{
		Mode:       orphanSweepObserve,
		Grace:      orphanSweepDefaultGrace,
		MaxDeletes: orphanSweepDefaultMaxDeletes,
		Interval:   orphanSweepInterval,
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZITI_ORPHAN_SWEEP"))) {
	case orphanSweepOff, "false", "0", "disabled":
		cfg.Mode = orphanSweepOff
	case orphanSweepEnforce:
		cfg.Mode = orphanSweepEnforce
	}
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("ZITI_ORPHAN_SWEEP_GRACE_MINUTES"))); err == nil {
		cfg.Grace = time.Duration(v) * time.Minute
		if cfg.Grace < orphanSweepMinGrace {
			cfg.Grace = orphanSweepMinGrace
		}
	}
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("ZITI_ORPHAN_SWEEP_MAX_DELETES"))); err == nil && v > 0 {
		cfg.MaxDeletes = v
		if cfg.MaxDeletes > orphanSweepMaxMaxDeletes {
			cfg.MaxDeletes = orphanSweepMaxMaxDeletes
		}
	}
	return cfg
}

var networkOrphanObjectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "openidx",
	Name:      "ziti_network_orphans_total",
	Help:      "Network-resource Ziti objects the orphan sweep found with no owning application, by collection and outcome (would_delete, deleted, delete_failed, in_grace, over_cap).",
}, []string{"collection", "outcome"})

// networkOrphanObject is one controller object the network reconciler wrote,
// identified by the application it was written for.
type networkOrphanObject struct {
	Collection string // configs | services | service-policies | service-edge-router-policies
	ID         string
	Name       string
	AppID      string
	CreatedAt  time.Time
}

// networkAppRef is what the database says about one application id.
type networkAppRef struct {
	OrgID string // empty when the row is gone
	Owns  bool   // still owns a network service (the reconciler's desired predicate)
}

// zitiListedObject is the subset of a management-API list record the sweep
// reads. CreatedAt is zero when the controller did not send it, which counts
// as "not provably old".
type zitiListedObject struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
	ConfigTypeID   string    `json:"configTypeId"`
	RoleAttributes []string  `json:"roleAttributes"`
}

// networkAppIDFromServiceName returns the application id of a network service
// name, and only for the exact shape networkServiceName produces.
func networkAppIDFromServiceName(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, networkServicePrefix)
	if !ok {
		return "", false
	}
	u, err := uuid.Parse(rest)
	if err != nil || u.String() != rest {
		return "", false
	}
	return rest, true
}

// networkPolicyPrefixes are the service-policy names the reconciler writes for
// a network service (openidx-orgdial- is no longer written but one left by an
// earlier build is still the reconciler's).
var networkPolicyPrefixes = []string{"openidx-dial-", "openidx-orgdial-", "openidx-bind-"}

// classifyNetworkObject reports the application a listed object was written
// for, or false when the object is not provably the network reconciler's.
func (zm *ZitiManager) classifyNetworkObject(collection string, o zitiListedObject) (string, bool) {
	if o.ID == "" {
		return "", false
	}
	switch collection {
	case "configs":
		for suffix, typ := range map[string]string{"-intercept": "intercept.v1", "-host": "host.v1"} {
			svc, ok := strings.CutSuffix(o.Name, suffix)
			if !ok {
				continue
			}
			app, ok := networkAppIDFromServiceName(svc)
			if !ok {
				return "", false
			}
			want := zm.resolveConfigTypeID(typ)
			if want == "" || o.ConfigTypeID != want {
				return "", false
			}
			return app, true
		}
	case "services":
		app, ok := networkAppIDFromServiceName(o.Name)
		if !ok {
			return "", false
		}
		for _, a := range o.RoleAttributes {
			if a == "openidx-managed" {
				return app, true
			}
		}
	case "service-policies":
		for _, p := range networkPolicyPrefixes {
			if svc, ok := strings.CutPrefix(o.Name, p); ok {
				return networkAppIDFromServiceName(svc)
			}
		}
	case "service-edge-router-policies":
		if svc, ok := strings.CutPrefix(o.Name, "openidx-serp-"); ok {
			return networkAppIDFromServiceName(svc)
		}
	}
	return "", false
}

// networkOrphanDeleteOrder is the order an application's objects go in:
// what grants reach first, then the service, then the configs it referenced.
var networkOrphanDeleteOrder = []string{"service-policies", "service-edge-router-policies", "services", "configs"}

// NetworkOrphanSweepReport is one run's outcome.
type NetworkOrphanSweepReport struct {
	Mode         string
	Candidates   int // provably-ours objects listed
	OrphanApps   int // applications with no owner whose objects are past grace
	InGrace      int // objects of orphan applications left because one is too young
	WouldDelete  int // observe
	Deleted      int // enforce
	DeleteFailed int
	OverCap      int // left for the next run by MaxDeletes
}

// sweepNetworkOrphans runs one pass against zm. now is injected for tests.
func (rec *ZitiReconciler) sweepNetworkOrphans(ctx context.Context, zm *ZitiManager, cfg NetworkOrphanSweepConfig, now time.Time) (NetworkOrphanSweepReport, error) {
	rep := NetworkOrphanSweepReport{Mode: cfg.Mode}
	if cfg.Mode == orphanSweepOff {
		return rep, nil
	}
	// 1. The controller side, complete or not at all.
	byApp := map[string][]networkOrphanObject{}
	for _, coll := range networkOrphanDeleteOrder {
		listed, err := listAllPaged[zitiListedObject](zm, coll)
		if err != nil {
			return rep, fmt.Errorf("list %s: %w", coll, err)
		}
		for _, o := range listed {
			app, ok := zm.classifyNetworkObject(coll, o)
			if !ok {
				continue
			}
			byApp[app] = append(byApp[app], networkOrphanObject{
				Collection: coll, ID: o.ID, Name: o.Name, AppID: app, CreatedAt: o.CreatedAt,
			})
			rep.Candidates++
		}
	}
	if len(byApp) == 0 {
		return rep, nil
	}

	// 2. The database side, read after the listing: an application created
	// before its objects were listed is in this read.
	apps := make([]string, 0, len(byApp))
	for a := range byApp {
		apps = append(apps, a)
	}
	sort.Strings(apps)
	load := rec.loadNetworkRefs
	if load == nil {
		load = rec.loadNetworkOrphanRefs
	}
	refs, err := load(ctx, apps)
	if err != nil {
		return rep, fmt.Errorf("load network applications: %w", err)
	}

	audit := rec.auditOrphan
	if audit == nil {
		audit = rec.auditNetworkOrphanDeletion
	}
	cutoff := now.Add(-cfg.Grace)
	budget := cfg.MaxDeletes
	for _, app := range apps {
		if refs[app].Owns {
			continue
		}
		objs := byApp[app]
		young := false
		for _, o := range objs {
			if o.CreatedAt.IsZero() || o.CreatedAt.After(cutoff) {
				young = true
				break
			}
		}
		if young {
			rep.InGrace += len(objs)
			for _, o := range objs {
				networkOrphanObjectsTotal.WithLabelValues(o.Collection, "in_grace").Inc()
			}
			continue
		}
		rep.OrphanApps++
		sort.SliceStable(objs, func(i, j int) bool {
			return orphanCollectionRank(objs[i].Collection) < orphanCollectionRank(objs[j].Collection)
		})
		for _, o := range objs {
			if cfg.Mode != orphanSweepEnforce {
				rep.WouldDelete++
				networkOrphanObjectsTotal.WithLabelValues(o.Collection, "would_delete").Inc()
				rec.logger.Info("ziti orphan sweep: would delete a network object no application owns",
					zap.String("collection", o.Collection), zap.String("name", o.Name),
					zap.String("id", o.ID), zap.String("application_id", o.AppID),
					zap.Time("created_at", o.CreatedAt))
				continue
			}
			if budget <= 0 {
				// Left for the next run, counted so the operator sees the backlog.
				rep.OverCap++
				networkOrphanObjectsTotal.WithLabelValues(o.Collection, "over_cap").Inc()
				continue
			}
			budget--
			if derr := deleteZitiObjectByID(zm, o.Collection, o.ID); derr != nil {
				rep.DeleteFailed++
				networkOrphanObjectsTotal.WithLabelValues(o.Collection, "delete_failed").Inc()
				rec.logger.Warn("ziti orphan sweep: delete refused; leaving the rest of this application's objects for the next run",
					zap.String("collection", o.Collection), zap.String("name", o.Name),
					zap.String("id", o.ID), zap.Error(derr))
				break
			}
			rep.Deleted++
			networkOrphanObjectsTotal.WithLabelValues(o.Collection, "deleted").Inc()
			audit(ctx, o, refs[app])
		}
	}
	return rep, nil
}

func orphanCollectionRank(c string) int {
	for i, x := range networkOrphanDeleteOrder {
		if x == c {
			return i
		}
	}
	return len(networkOrphanDeleteOrder)
}

// deleteZitiObjectByID deletes one management-API object. Already gone (404)
// is success: another replica's reconcile prune may have got there first.
func deleteZitiObjectByID(zm *ZitiManager, collection, id string) error {
	_, status, err := zm.mgmtRequest("DELETE", "/edge/management/v1/"+collection+"/"+id, nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted, http.StatusNotFound:
		return nil
	}
	return fmt.Errorf("controller answered %d", status)
}

// loadNetworkOrphanRefs reads, for each application id, whether it still owns
// a network service -- the predicate loadDesiredNetworkServices selects on --
// and its organization for the audit record. An id with no row is absent from
// the map, which reads as "owns nothing".
func (rec *ZitiReconciler) loadNetworkOrphanRefs(ctx context.Context, appIDs []string) (map[string]networkAppRef, error) {
	if rec.db == nil || rec.db.Pool == nil {
		return nil, fmt.Errorf("no database")
	}
	rows, err := rec.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide Ziti orphan sweep; keyed by globally-unique application ids parsed from controller object names, each row reports its own org_id
		`SELECT a.id::text, COALESCE(a.org_id::text, ''),
		        (a.kind = 'network' AND a.enabled = true AND a.org_id IS NOT NULL
		         AND EXISTS (SELECT 1 FROM network_targets nt WHERE nt.application_id = a.id AND nt.org_id = a.org_id))
		   FROM applications a
		  WHERE a.id = ANY($1::uuid[])`, appIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]networkAppRef, len(appIDs))
	for rows.Next() {
		var id string
		var ref networkAppRef
		if err := rows.Scan(&id, &ref.OrgID, &ref.Owns); err != nil {
			return nil, err
		}
		out[id] = ref
	}
	return out, rows.Err()
}

// auditNetworkOrphanDeletion records one deletion: a structured AUDIT log line
// always, and a unified_audit_events row when the database is reachable,
// under the application's organization when its row still exists.
func (rec *ZitiReconciler) auditNetworkOrphanDeletion(ctx context.Context, o networkOrphanObject, ref networkAppRef) {
	rec.logger.Info("AUDIT",
		zap.String("service", "access-service"),
		zap.String("category", "ziti_orphan_sweep"),
		zap.String("action", "ziti_network_orphan_deleted"),
		zap.String("collection", o.Collection),
		zap.String("name", o.Name),
		zap.String("id", o.ID),
		zap.String("application_id", o.AppID),
		zap.Time("created_at", o.CreatedAt))
	if rec.db == nil || rec.db.Pool == nil {
		return
	}
	orgID := ref.OrgID
	if orgID == "" {
		orgID, _ = orgctx.AuditOrgID(ctx)
	}
	details, _ := json.Marshal(map[string]interface{}{
		"collection":     o.Collection,
		"ziti_id":        o.ID,
		"name":           o.Name,
		"application_id": o.AppID,
		"created_at":     o.CreatedAt.UTC().Format(time.RFC3339),
	})
	if _, err := rec.db.Pool.Exec(orgctx.WithBypassRLS(ctx), `
		INSERT INTO unified_audit_events (id, org_id, source, event_type, user_id, details, created_at)
		VALUES ($1, $2, 'access-service', 'ziti_network_orphan_deleted', NULL, $3, NOW())`,
		uuid.New().String(), orgID, details); err != nil {
		rec.logger.Warn("ziti orphan sweep: audit row not written; the AUDIT log line stands",
			zap.String("name", o.Name), zap.Error(err))
	}
}

// StartNetworkOrphanSweep runs the sweep every cfg.Interval on one replica
// (leader.RunPeriodic; a nil rdb means a single instance, which runs it). It
// returns at once; the loop ends with ctx.
func (rec *ZitiReconciler) StartNetworkOrphanSweep(ctx context.Context, rdb *redis.Client, cfg NetworkOrphanSweepConfig) {
	if cfg.Mode == orphanSweepOff {
		rec.logger.Info("ziti orphan sweep disabled (ZITI_ORPHAN_SWEEP=off)")
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = orphanSweepInterval
	}
	rec.logger.Info("ziti orphan sweep started",
		zap.String("mode", cfg.Mode), zap.Duration("grace", cfg.Grace),
		zap.Int("max_deletes", cfg.MaxDeletes), zap.Duration("interval", cfg.Interval))
	go leader.RunPeriodic(ctx, rdb, rec.logger, "access:ziti-network-orphan-sweep", cfg.Interval, func(ctx context.Context) {
		rec.runNetworkOrphanSweep(ctx, cfg)
	})
}

func (rec *ZitiReconciler) runNetworkOrphanSweep(ctx context.Context, cfg NetworkOrphanSweepConfig) {
	zm := rec.provider.Get()
	if zm == nil || !zm.IsInitialized() {
		rec.logger.Debug("ziti orphan sweep skipped: no live Ziti manager")
		return
	}
	// Not concurrently with this process's own reconcile pass; other
	// replicas are covered by the grace period.
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rep, err := rec.sweepNetworkOrphans(ctx, zm, cfg, time.Now())
	if err != nil {
		rec.logger.Warn("ziti orphan sweep: run abandoned, nothing deleted", zap.Error(err))
		return
	}
	if rep.OrphanApps == 0 && rep.InGrace == 0 {
		rec.logger.Debug("ziti orphan sweep: no orphans", zap.Int("candidates", rep.Candidates))
		return
	}
	rec.logger.Info("ziti orphan sweep: run complete",
		zap.String("mode", rep.Mode), zap.Int("candidates", rep.Candidates),
		zap.Int("orphan_applications", rep.OrphanApps), zap.Int("in_grace", rep.InGrace),
		zap.Int("would_delete", rep.WouldDelete), zap.Int("deleted", rep.Deleted),
		zap.Int("delete_failed", rep.DeleteFailed), zap.Int("over_cap", rep.OverCap))
}

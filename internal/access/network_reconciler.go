package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// DesiredNetworkService is the reconciler's view of one network resource: an
// enabled kind='network' application with a network_targets row.
type DesiredNetworkService struct {
	ApplicationID      string
	OrgID              string
	ServiceName        string
	Target             NetworkTarget
	RequireDeviceTrust bool
}

// loadDesiredNetworkServices reads every network resource (install-wide, like
// loadDesiredRoutes: the reconciler converges every organization's overlay).
// A row whose stored target no longer validates is skipped and reported in its
// converge status rather than rendered half-right.
func (rec *ZitiReconciler) loadDesiredNetworkServices(ctx context.Context) ([]DesiredNetworkService, error) {
	rows, err := rec.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide Ziti reconcile; each service is keyed by its application's globally-unique id and carries that row's org_id
		`SELECT a.id::text, a.org_id::text, nt.hosts, COALESCE(nt.cidrs::text[], '{}'), nt.dns_names,
		        nt.port_ranges, nt.protocols, COALESCE(nt.forward_address, ''), COALESCE(nt.forward_port, 0),
		        COALESCE(rc.require_device_trust, false)
		   FROM applications a
		   JOIN network_targets nt ON nt.application_id = a.id AND nt.org_id = a.org_id
		   LEFT JOIN resource_conditions rc ON rc.application_id = a.id AND rc.org_id = a.org_id
		  WHERE a.kind = 'network' AND a.enabled = true AND a.org_id IS NOT NULL
		  ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DesiredNetworkService
	for rows.Next() {
		var d DesiredNetworkService
		var t NetworkTarget
		var portRanges []byte
		if err := rows.Scan(&d.ApplicationID, &d.OrgID, &t.Hosts, &t.CIDRs, &t.DNSNames,
			&portRanges, &t.Protocols, &t.ForwardAddress, &t.ForwardPort, &d.RequireDeviceTrust); err != nil {
			rec.logger.Warn("reconciler: scan network resource failed", zap.Error(err))
			continue
		}
		d.ServiceName = networkServiceName(d.ApplicationID)
		if len(portRanges) > 0 {
			if err := json.Unmarshal(portRanges, &t.PortRanges); err != nil {
				rec.setStatus(d.ServiceName, "error: port_ranges does not parse: "+err.Error())
				continue
			}
		}
		t.ApplicationID = d.ApplicationID
		norm, err := normalizeNetworkTarget(t)
		if err != nil {
			rec.setStatus(d.ServiceName, "error: "+err.Error())
			continue
		}
		d.Target = norm
		out = append(out, d)
	}
	return out, rows.Err()
}

// ensureNetworkService converges one network resource's service, configs and
// policies. Idempotent: on a converged controller it only reads, because
// EnsureConfig reuses a config whose data is unchanged, EnsureServiceConfig
// attaches only what is missing, and EnsureServicePolicyForOrgSemantic updates
// a policy only when its roles or semantic differ.
func (rec *ZitiReconciler) ensureNetworkService(ctx context.Context, zm *ZitiManager, d DesiredNetworkService) error {
	// Re-validate at emit time: what is written to Ziti is exactly the
	// canonical, guard-checked target, whatever path produced d.
	target, err := normalizeNetworkTarget(d.Target)
	if err != nil {
		return fmt.Errorf("network target refused: %w", err)
	}
	d.Target = target
	// Build the configs once, gate exactly those maps, and write exactly
	// those maps: nothing reaches the controller that the guard did not see.
	interceptData, hostData := interceptV1Data(d.Target), hostV1Data(d.Target)
	if errs := guardEmittedConfigs(interceptData, hostData); len(errs) > 0 {
		return fmt.Errorf("network target refused: %s", strings.Join(errs, "; "))
	}
	interceptID, err := zm.EnsureConfig(ctx, d.ServiceName+"-intercept", "intercept.v1", interceptData)
	if err != nil {
		return err
	}
	hostID, err := zm.EnsureConfig(ctx, d.ServiceName+"-host", "host.v1", hostData)
	if err != nil {
		return err
	}

	svc, _ := zm.GetServiceByName(d.ServiceName)
	if svc == nil {
		if _, cerr := zm.createServiceWithConfigID(ctx, d.ServiceName, []string{d.ServiceName, "openidx-managed"}, hostID); cerr != nil {
			// Tolerate a create race with another actor.
			if again, _ := zm.GetServiceByName(d.ServiceName); again == nil {
				return cerr
			}
		}
		if svc, err = zm.GetServiceByName(d.ServiceName); err != nil || svc == nil {
			return fmt.Errorf("network service %s not found after create: %w", d.ServiceName, err)
		}
	}
	// The service itself is converged to exactly what the reconciler would
	// create: these two configs and no other (a foreign config attached to it
	// would change what is intercepted or where it lands), these role
	// attributes and no other (an extra one could match someone else's
	// policy), and encryption required.
	if err := zm.convergeNetworkServiceObject(ctx, svc.ID,
		[]string{hostID, interceptID}, []string{d.ServiceName, "openidx-managed"}); err != nil {
		return err
	}

	svcRole := "#" + d.ServiceName
	if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
		rec.logger.Warn("network service: tag routers failed", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.EnsureServicePolicyForOrg(ctx, d.OrgID, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{"#ziti-routers"}); err != nil {
		return fmt.Errorf("bind policy: %w", err)
	}
	dialRoles, semantic := networkDialPolicy(d.ApplicationID, rec.assignmentEnforce, d.RequireDeviceTrust)
	if _, err := zm.EnsureServicePolicyForOrgSemantic(ctx, d.OrgID, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, dialRoles, semantic); err != nil {
		return fmt.Errorf("dial policy: %w", err)
	}
	if err := zm.convergeServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.ServiceName,
		[]string{svcRole}, []string{"#all"}); err != nil {
		return fmt.Errorf("service edge router policy: %w", err)
	}
	// No per-org Dial policy for a network service: #org-<id> would grant
	// every member of the organization, wider than the assignment-scoped
	// policy above. One left by an earlier build is removed.
	if err := zm.deleteEdgeEntityByName(ctx, "service-policies", "openidx-orgdial-"+d.ServiceName); err != nil {
		return fmt.Errorf("remove per-org dial policy: %w", err)
	}
	// Nothing else may apply to the service: a Bind or Dial policy the
	// reconciler did not write (someone else's, or a #all selector) would
	// host or reach it outside the assignment. Such drift fails the
	// convergence, which removes the service (fail closed) and names the
	// policy in the status.
	return zm.refuseForeignServicePolicies(ctx, svc.ID, map[string]bool{
		"openidx-bind-" + d.ServiceName: true,
		"openidx-dial-" + d.ServiceName: true,
	})
}

// convergeNetworkServiceObject sets the service's configs and role
// attributes to exactly the given sets and encryptionRequired to true,
// patching only what differs.
func (zm *ZitiManager) convergeNetworkServiceObject(ctx context.Context, svcID string, configs, attrs []string) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/services/"+svcID, nil)
	if err != nil {
		return fmt.Errorf("read service: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d reading service %s", status, svcID)
	}
	var resp struct {
		Data struct {
			Configs            []string `json:"configs"`
			RoleAttributes     []string `json:"roleAttributes"`
			EncryptionRequired *bool    `json:"encryptionRequired"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse service: %w", err)
	}
	patch := map[string]interface{}{}
	if !sameRoleSet(resp.Data.Configs, configs) {
		patch["configs"] = configs
	}
	if !sameRoleSet(resp.Data.RoleAttributes, attrs) {
		patch["roleAttributes"] = attrs
	}
	if resp.Data.EncryptionRequired != nil && !*resp.Data.EncryptionRequired {
		patch["encryptionRequired"] = true
	}
	if len(patch) == 0 {
		return nil
	}
	body, _ := json.Marshal(patch)
	_, ps, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/services/"+svcID, body)
	if perr != nil {
		return fmt.Errorf("repair service: %w", perr)
	}
	if ps != http.StatusOK && ps != http.StatusAccepted {
		return fmt.Errorf("unexpected status %d repairing service %s", ps, svcID)
	}
	return nil
}

// convergeServiceEdgeRouterPolicy makes the named service-edge-router policy
// exist with exactly these roles and AnyOf, replacing one that differs.
func (zm *ZitiManager) convergeServiceEdgeRouterPolicy(ctx context.Context, name string, serviceRoles, edgeRouterRoles []string) error {
	data, status, err := zm.mgmtRequest("GET",
		"/edge/management/v1/service-edge-router-policies?filter="+zitiFilterEquals("name", name), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d reading %s", status, name)
	}
	var resp struct {
		Data []struct {
			ID              string   `json:"id"`
			Name            string   `json:"name"`
			Semantic        string   `json:"semantic"`
			ServiceRoles    []string `json:"serviceRoles"`
			EdgeRouterRoles []string `json:"edgeRouterRoles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	for _, p := range resp.Data {
		if p.Name != name {
			continue
		}
		if policySemantic(p.Semantic) == "AnyOf" && sameRoleSet(p.ServiceRoles, serviceRoles) && sameRoleSet(p.EdgeRouterRoles, edgeRouterRoles) {
			return nil
		}
		if err := zm.deleteEdgeEntityByName(ctx, "service-edge-router-policies", name); err != nil {
			return fmt.Errorf("replace drifted %s: %w", name, err)
		}
		break
	}
	return zm.EnsureServiceEdgeRouterPolicy(ctx, name, serviceRoles, edgeRouterRoles)
}

// refuseForeignServicePolicies fails when any service policy other than the
// allowed ones applies to the service.
func (zm *ZitiManager) refuseForeignServicePolicies(ctx context.Context, svcID string, allowed map[string]bool) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/services/"+svcID+"/service-policies?limit=1000", nil)
	if err != nil {
		return fmt.Errorf("read the policies that apply to the service: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d reading the policies that apply to the service", status)
	}
	var resp struct {
		Data []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	var foreign []string
	for _, p := range resp.Data {
		if !allowed[p.Name] {
			foreign = append(foreign, p.Type+" "+p.Name)
		}
	}
	if len(foreign) > 0 {
		return fmt.Errorf("policies the reconciler did not write apply to this service: %s", strings.Join(foreign, ", "))
	}
	return nil
}

// pruneNetworkServices removes the overlay objects of network services that
// are no longer desired: the target was deleted, the application disabled,
// deleted, or moved off kind 'network'. Only names under networkServicePrefix
// are touched, and only after the desired set loaded cleanly, so a failed read
// never tears down a working service.
func (rec *ZitiReconciler) pruneNetworkServices(ctx context.Context, zm *ZitiManager, desired []DesiredNetworkService) {
	keep := make(map[string]bool, len(desired))
	for _, d := range desired {
		keep[d.ServiceName] = true
	}
	services, err := zm.ListServices(ctx)
	if err != nil {
		rec.logger.Warn("network services: list for prune failed", zap.Error(err))
		return
	}
	for _, s := range services {
		if !strings.HasPrefix(s.Name, networkServicePrefix) || keep[s.Name] {
			continue
		}
		for _, p := range []struct{ collection, name string }{
			{"service-policies", "openidx-dial-" + s.Name},
			{"service-policies", "openidx-orgdial-" + s.Name},
			{"service-policies", "openidx-bind-" + s.Name},
			{"service-edge-router-policies", "openidx-serp-" + s.Name},
		} {
			if err := zm.deleteEdgeEntityByName(ctx, p.collection, p.name); err != nil {
				rec.logger.Debug("network prune: delete", zap.String("name", p.name), zap.Error(err))
			}
		}
		if err := zm.DeleteService(ctx, s.ID); err != nil {
			rec.logger.Warn("network prune: delete service failed", zap.String("svc", s.Name), zap.Error(err))
			continue
		}
		for _, c := range []string{s.Name + "-intercept", s.Name + "-host"} {
			if err := zm.deleteEdgeEntityByName(ctx, "configs", c); err != nil {
				rec.logger.Debug("network prune: delete config", zap.String("name", c), zap.Error(err))
			}
		}
		rec.statusMu.Lock()
		delete(rec.status, s.Name)
		rec.statusMu.Unlock()
		rec.logger.Info("network service removed", zap.String("svc", s.Name))
	}
}

// reconcileNetworkServices is the network-resource share of a reconcile pass.
//
// It fails closed at every step:
//   - the routers' advertised hosts join the guard's denylist first; a failed
//     or empty refresh keeps the last good list, and with none the pass
//     writes nothing;
//   - an incomplete denylist (host interface discovery failed with no earlier
//     result) likewise writes nothing;
//   - a failure to load the network resources (targets, conditions) removes
//     every network service's Dial policies, so nothing stays dialable under
//     a state that could not be read; the services and configs stay and the
//     next good pass restores the policies;
//   - a resource whose row does not scan, whose target is refused, or whose
//     convergence fails at any step is removed from the controller (service,
//     configs and policies) rather than left with what an earlier pass wrote.
func (rec *ZitiReconciler) reconcileNetworkServices(ctx context.Context, zm *ZitiManager) {
	if err := refreshRouterHosts(ctx, zm); err != nil {
		rec.logger.Warn("network services: router hosts not refreshed; keeping the last good list", zap.Error(err))
	}
	// The guard is complete only while both discovered halves (router hosts,
	// host interfaces) are fresh. When it is not, nothing new is written and
	// nothing judged under an older denylist stays dialable.
	if g := targetGuard(); g.incomplete != "" {
		rec.logger.Warn("network services: denylist incomplete; revoking every network Dial policy and writing nothing", zap.String("why", g.incomplete))
		rec.revokeNetworkDials(ctx, zm, "denylist incomplete: "+g.incomplete)
		return
	}
	load := rec.loadNetwork
	if load == nil {
		load = rec.loadDesiredNetworkServices
	}
	desired, err := load(ctx)
	if err != nil {
		rec.logger.Warn("reconcile: load network resources failed; removing every network service's Dial policies", zap.Error(err))
		rec.revokeNetworkDials(ctx, zm, "network resources could not be loaded")
		return
	}
	rec.applyNetworkServices(ctx, zm, desired)
}

// revokeNetworkDials removes the Dial policies of every network service on
// the controller, leaving the services and configs for the next good pass.
func (rec *ZitiReconciler) revokeNetworkDials(ctx context.Context, zm *ZitiManager, why string) {
	services, err := zm.ListServices(ctx)
	if err != nil {
		rec.logger.Warn("network services: list for dial revoke failed", zap.Error(err))
		return
	}
	for _, s := range services {
		if !strings.HasPrefix(s.Name, networkServicePrefix) {
			continue
		}
		for _, p := range []string{"openidx-dial-" + s.Name, "openidx-orgdial-" + s.Name} {
			if err := zm.deleteEdgeEntityByName(ctx, "service-policies", p); err != nil {
				rec.logger.Warn("network services: dial revoke failed", zap.String("policy", p), zap.Error(err))
			}
		}
		rec.setStatus(s.Name, "error: "+why+"; dial revoked")
	}
}

// applyNetworkServices converges the desired network services and removes
// every other one, including any whose convergence failed this pass.
func (rec *ZitiReconciler) applyNetworkServices(ctx context.Context, zm *ZitiManager, desired []DesiredNetworkService) {
	if len(desired) > 0 {
		// Device identities need an edge-router policy, or every dial fails
		// with NO_EDGE_ROUTERS_AVAILABLE.
		if err := zm.EnsureEdgeRouterPolicy(ctx, "openidx-agent-all-routers",
			[]string{"#all"}, []string{"#openidx-agent"}); err != nil {
			rec.logger.Warn("network services: agent edge-router policy failed", zap.Error(err))
		}
	}
	kept := make([]DesiredNetworkService, 0, len(desired))
	failed := map[string]string{}
	for _, d := range desired {
		if err := rec.ensureNetworkService(ctx, zm, d); err != nil {
			failed[d.ServiceName] = "error: " + err.Error() + " (removed from the overlay until it converges)"
			rec.logger.Warn("reconcile network service failed; removing it", zap.String("svc", d.ServiceName), zap.Error(err))
			continue
		}
		kept = append(kept, d)
		rec.setStatus(d.ServiceName, "synced")
	}
	// A service whose convergence failed is not left with what an earlier
	// pass wrote. Its Dial policies go first, by name, which needs no
	// service listing; then prune removes it with everything else not kept.
	for name := range failed {
		for _, p := range []string{"openidx-dial-" + name, "openidx-orgdial-" + name} {
			if err := zm.deleteEdgeEntityByName(ctx, "service-policies", p); err != nil {
				rec.logger.Warn("network services: dial revoke failed", zap.String("policy", p), zap.Error(err))
			}
		}
	}
	rec.pruneNetworkServices(ctx, zm, kept)
	for name, st := range failed {
		rec.setStatus(name, st)
	}
}

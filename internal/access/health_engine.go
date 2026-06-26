package access

import (
	"context"
	"errors"

	"go.uber.org/zap"
)

// Finding is one relation/integrity observation across the OpenIDX domains.
type Finding struct {
	CheckID  string `json:"check_id"`
	Domain   string `json:"domain"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail"`
	Safe     bool   `json:"safe"`
	Action   string `json:"action"`
}

// Report is the aggregate result of a scan.
type Report struct {
	Findings  []Finding `json:"findings"`
	Healed    []Finding `json:"healed,omitempty"`
	Remaining []Finding `json:"remaining,omitempty"`
}

// Check is one relation/integrity rule.
type Check interface {
	ID() string
	Domain() string
	Detect(ctx context.Context) ([]Finding, error)
	Fix(ctx context.Context, f Finding) error
}

var errCheckNotFound = errors.New("unknown check id")

// HealthEngine runs the registered checks.
type HealthEngine struct {
	svc    *Service
	logger *zap.Logger
	checks []Check
}

// NewHealthEngine builds the engine and registers all checks.
func NewHealthEngine(svc *Service) *HealthEngine {
	e := &HealthEngine{svc: svc, logger: svc.logger.With(zap.String("component", "health"))}
	e.checks = registerChecks(svc)
	return e
}

// Scan runs every check's Detect and aggregates findings.
func (e *HealthEngine) Scan(ctx context.Context) Report {
	var rep Report
	for _, c := range e.checks {
		fs, err := c.Detect(ctx)
		if err != nil {
			e.logger.Warn("check detect failed", zap.String("check", c.ID()), zap.Error(err))
			continue
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep
}

// ScanAndHeal scans, then (if applySafe) fixes every Safe drift/orphan finding.
func (e *HealthEngine) ScanAndHeal(ctx context.Context, applySafe bool) Report {
	rep := e.Scan(ctx)
	byID := map[string]Check{}
	for _, c := range e.checks {
		byID[c.ID()] = c
	}
	for _, f := range rep.Findings {
		if f.Status == "ok" {
			continue
		}
		if applySafe && f.Safe {
			if c := byID[f.CheckID]; c != nil {
				if err := c.Fix(ctx, f); err != nil {
					e.logger.Warn("safe heal failed", zap.String("check", f.CheckID), zap.String("subject", f.Subject), zap.Error(err))
					rep.Remaining = append(rep.Remaining, f)
					continue
				}
				rep.Healed = append(rep.Healed, f)
				continue
			}
			// A Safe finding whose CheckID matches no registered check is a
			// registry bug (don't silently drop it into Remaining).
			e.logger.Warn("safe finding references unknown check id", zap.String("check", f.CheckID), zap.String("subject", f.Subject))
		}
		rep.Remaining = append(rep.Remaining, f)
	}
	return rep
}

// HealRoute applies the cheap, safe post-mutation heals for a single route:
// re-sync its launcher tile and enqueue a Ziti reconcile. The mutation flows
// (publish/consolidate/feature-toggle) already RegenerateConfigs, so this
// deliberately does NOT — it's a safety net guaranteeing the tile + reconcile
// happen even if a caller path forgets. Safe to call on a nil engine.
func (e *HealthEngine) HealRoute(ctx context.Context, routeID string) {
	if e == nil {
		return
	}
	if err := e.svc.healRouteTile(ctx, routeID); err != nil {
		e.logger.Debug("post-mutation tile heal", zap.String("route", routeID), zap.Error(err))
	}
	e.svc.enqueueReconcile()
}

// FixOne runs a specific check's Fix for a subject after re-detecting it.
func (e *HealthEngine) FixOne(ctx context.Context, checkID, subject string) error {
	for _, c := range e.checks {
		if c.ID() != checkID {
			continue
		}
		fs, err := c.Detect(ctx)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if f.Subject == subject && f.Status != "ok" {
				return c.Fix(ctx, f)
			}
		}
		return nil
	}
	return errCheckNotFound
}

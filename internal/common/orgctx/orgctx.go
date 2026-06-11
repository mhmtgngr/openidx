// Package orgctx carries the resolved organization (tenant) on a
// request's context.Context.
//
// The v2.0 multi-tenancy design (docs/v2-multitenancy-design.md) makes
// every request belong to exactly one organization. The
// tenant-resolution middleware reads the subdomain, JWT claim, or
// X-Org-ID header (in that order), looks up the organization, and
// attaches it here. Downstream service code reads it from context and
// uses it to scope queries.
//
// Platform-admin actors may carry an additional marker that lets
// service code skip its scope check. Code that consumes that marker
// is required to record an audit entry recording the cross-tenant
// access. This package itself does not enforce that — it is a carrier,
// not a policy.
//
// This package ships as part of v1.6.0 (Foundation milestone). It is
// pure plumbing: no migration, no enforcement, no behavioral change.
// Later milestones build query scoping and RLS on top of it.
package orgctx

import (
	"context"
	"errors"
)

// Org is the resolved organization the request belongs to.
type Org struct {
	// ID is the organization's UUID (organizations.id).
	ID string
	// Slug is the organization's slug (organizations.slug). Stable,
	// URL-safe, suitable for subdomain or path use.
	Slug string
}

// ErrNoOrgContext means the request reached a code path that expected
// a resolved organization but none had been attached. Either the
// resolver middleware did not run, or it ran and rejected the
// request before delegating.
var ErrNoOrgContext = errors.New("orgctx: no organization context on request")

type orgKey struct{}
type platformAdminKey struct{}

// With returns a derived context carrying org. Use from the
// tenant-resolution middleware after looking up the org by slug or
// claim. The returned context propagates the org to every downstream
// service call that takes ctx.
func With(parent context.Context, org Org) context.Context {
	return context.WithValue(parent, orgKey{}, org)
}

// From returns the org carried by ctx, or ErrNoOrgContext if none is
// attached. Service code that scopes queries by org id should call
// this and return ErrNoOrgContext (or its own wrapping error) when it
// fires — that means the resolver middleware was skipped, which is a
// programmer error, not a 4xx.
func From(ctx context.Context) (Org, error) {
	org, ok := ctx.Value(orgKey{}).(Org)
	if !ok {
		return Org{}, ErrNoOrgContext
	}
	return org, nil
}

// MustFrom returns the org carried by ctx, panicking if absent. Reserve
// for paths where the resolver middleware is known to have run
// successfully — e.g., handler bodies behind the middleware. Never
// call from package-level constructors or background jobs that may
// run without a resolver upstream.
func MustFrom(ctx context.Context) Org {
	org, err := From(ctx)
	if err != nil {
		panic("orgctx.MustFrom: " + err.Error())
	}
	return org
}

// WithPlatformAdmin marks ctx as carrying a platform-admin actor.
// Service code that respects this marker may skip its org scope check
// and read across organizations. Every code path that does so MUST
// record an audit entry that includes the platform_admin flag and the
// actor's user id — see the v2.0 design's Role Model decision.
//
// This marker is independent of With: a platform admin acting inside
// org A still carries org A on ctx, the marker just lets them read
// out of it.
func WithPlatformAdmin(parent context.Context) context.Context {
	return context.WithValue(parent, platformAdminKey{}, true)
}

// IsPlatformAdmin reports whether ctx carries the platform-admin
// marker set by WithPlatformAdmin.
func IsPlatformAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(platformAdminKey{}).(bool)
	return v
}

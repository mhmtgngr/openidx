package organization

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// orgFetcher is the minimal slice of *Service the OrgLookup adapter
// needs. Defined here so the adapter can be unit-tested against a fake
// without spinning up a real database. *Service satisfies it.
type orgFetcher interface {
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
}

// OrgLookup adapts the organization service so the tenant-resolver
// middleware can consume it without dragging in the full
// organization-service dependency tree. Construction:
//
//	orgSvc := organization.NewService(...)
//	lookup := organization.NewOrgLookup(orgSvc)
//	router.Use(middleware.TenantResolver(lookup, cfg))
//
// The adapter's only job is the protocol translation: it converts the
// service's *Organization into the orgctx.Org struct the middleware
// works with, and maps pgx.ErrNoRows to middleware.ErrOrgNotFound so
// the resolver can report a 400 instead of a 500.
type OrgLookup struct {
	fetcher orgFetcher
}

// NewOrgLookup builds the adapter. The fetcher is any type with the
// two read methods the resolver uses; in production it is *Service.
func NewOrgLookup(f orgFetcher) *OrgLookup {
	return &OrgLookup{fetcher: f}
}

// ByID returns the org with the given UUID. Maps pgx.ErrNoRows to
// middleware.ErrOrgNotFound so the resolver can distinguish a
// genuine not-found (400) from a transport failure (500).
func (l *OrgLookup) ByID(ctx context.Context, id string) (orgctx.Org, error) {
	org, err := l.fetcher.GetOrganization(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return orgctx.Org{}, middleware.ErrOrgNotFound
		}
		return orgctx.Org{}, err
	}
	return orgctx.Org{ID: org.ID, Slug: org.Slug}, nil
}

// BySlug returns the org with the given slug. Same not-found semantics
// as ByID.
func (l *OrgLookup) BySlug(ctx context.Context, slug string) (orgctx.Org, error) {
	org, err := l.fetcher.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return orgctx.Org{}, middleware.ErrOrgNotFound
		}
		return orgctx.Org{}, err
	}
	return orgctx.Org{ID: org.ID, Slug: org.Slug}, nil
}

// Compile-time check that *OrgLookup satisfies middleware.OrgLookup.
// If the middleware ever evolves its interface, this fails the build
// here rather than at every consumer's call site.
var _ middleware.OrgLookup = (*OrgLookup)(nil)

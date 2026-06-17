package organization

import (
	"context"
	"errors"
	"sync"
	"time"

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

// orgCacheTTL bounds how stale a cached org may be. Orgs change
// rarely (rename, slug change), so a short TTL keeps the resolver off
// the database on the per-request hot path while bounding how long a
// rename takes to propagate.
const orgCacheTTL = 30 * time.Second

// OrgLookup adapts the organization service so the tenant-resolver
// middleware can consume it without dragging in the full
// organization-service dependency tree. Construction:
//
//	orgSvc := organization.NewService(...)
//	lookup := organization.NewOrgLookup(orgSvc)
//	router.Use(middleware.TenantResolver(lookup, cfg))
//
// The adapter does two jobs. Protocol translation: it converts the
// service's *Organization into the orgctx.Org struct the middleware
// works with, and maps pgx.ErrNoRows to middleware.ErrOrgNotFound so
// the resolver can report a 400 instead of a 500. Caching: the
// resolver consults the lookup on every request (the default-org
// fallback in particular), so successful lookups are cached for
// orgCacheTTL. Only successes are cached — the entry count is bounded
// by the number of real orgs, and transient failures retry
// immediately.
type OrgLookup struct {
	fetcher orgFetcher

	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedOrg
}

type cachedOrg struct {
	org     orgctx.Org
	expires time.Time
}

// NewOrgLookup builds the adapter. The fetcher is any type with the
// two read methods the resolver uses; in production it is *Service.
func NewOrgLookup(f orgFetcher) *OrgLookup {
	return &OrgLookup{
		fetcher: f,
		ttl:     orgCacheTTL,
		now:     time.Now,
		cache:   make(map[string]cachedOrg),
	}
}

// ByID returns the org with the given UUID. Maps pgx.ErrNoRows to
// middleware.ErrOrgNotFound so the resolver can distinguish a
// genuine not-found (400) from a transport failure (500).
func (l *OrgLookup) ByID(ctx context.Context, id string) (orgctx.Org, error) {
	return l.cached("id\x00"+id, func() (*Organization, error) {
		return l.fetcher.GetOrganization(ctx, id)
	})
}

// BySlug returns the org with the given slug. Same not-found semantics
// as ByID.
func (l *OrgLookup) BySlug(ctx context.Context, slug string) (orgctx.Org, error) {
	return l.cached("slug\x00"+slug, func() (*Organization, error) {
		return l.fetcher.GetOrganizationBySlug(ctx, slug)
	})
}

// cached serves key from the cache when fresh, otherwise fetches,
// translates, and (on success) stores. The NUL byte in keys separates
// the namespace from the value so an id can never collide with a slug.
func (l *OrgLookup) cached(key string, fetch func() (*Organization, error)) (orgctx.Org, error) {
	l.mu.Lock()
	if entry, ok := l.cache[key]; ok && l.now().Before(entry.expires) {
		l.mu.Unlock()
		return entry.org, nil
	}
	l.mu.Unlock()

	org, err := fetch()
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return orgctx.Org{}, middleware.ErrOrgNotFound
		}
		return orgctx.Org{}, err
	}

	resolved := orgctx.Org{ID: org.ID, Slug: org.Slug}
	l.mu.Lock()
	l.cache[key] = cachedOrg{org: resolved, expires: l.now().Add(l.ttl)}
	l.mu.Unlock()
	return resolved, nil
}

// Compile-time check that *OrgLookup satisfies middleware.OrgLookup.
// If the middleware ever evolves its interface, this fails the build
// here rather than at every consumer's call site.
var _ middleware.OrgLookup = (*OrgLookup)(nil)

package organization

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// fakeFetcher is a hand-rolled orgFetcher used by the OrgLookup unit
// tests. It lets us stage every code path the adapter cares about —
// success, generic transport error, pgx.ErrNoRows — without spinning
// up a real database. Routes calls to user-provided functions so each
// test can configure the behavior it needs.
type fakeFetcher struct {
	byID   func(ctx context.Context, id string) (*Organization, error)
	bySlug func(ctx context.Context, slug string) (*Organization, error)
}

func (f *fakeFetcher) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return f.byID(ctx, id)
}

func (f *fakeFetcher) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return f.bySlug(ctx, slug)
}

func TestOrgLookup_ByID_success(t *testing.T) {
	want := &Organization{ID: "id-1", Slug: "acme", Name: "Acme"}
	f := &fakeFetcher{
		byID: func(_ context.Context, id string) (*Organization, error) {
			if id != "id-1" {
				t.Errorf("inner fetcher called with id %q, want id-1", id)
			}
			return want, nil
		},
	}
	got, err := NewOrgLookup(f).ByID(context.Background(), "id-1")
	if err != nil {
		t.Fatalf("ByID: unexpected error: %v", err)
	}
	if got.ID != "id-1" || got.Slug != "acme" {
		t.Fatalf("ByID: got %+v, want id=id-1 slug=acme", got)
	}
}

func TestOrgLookup_ByID_pgxNoRows_returnsSentinel(t *testing.T) {
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			return nil, fmt.Errorf("wrapped: %w", pgx.ErrNoRows)
		},
	}
	_, err := NewOrgLookup(f).ByID(context.Background(), "missing-id")
	if !errors.Is(err, middleware.ErrOrgNotFound) {
		t.Fatalf("ByID: got %v, want middleware.ErrOrgNotFound", err)
	}
}

func TestOrgLookup_ByID_genericError_passedThrough(t *testing.T) {
	want := errors.New("connection refused")
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			return nil, want
		},
	}
	_, err := NewOrgLookup(f).ByID(context.Background(), "id-1")
	if !errors.Is(err, want) {
		t.Fatalf("ByID: got %v, want %v", err, want)
	}
	if errors.Is(err, middleware.ErrOrgNotFound) {
		t.Fatal("generic error must not be classified as ErrOrgNotFound")
	}
}

func TestOrgLookup_BySlug_success(t *testing.T) {
	want := &Organization{ID: "id-2", Slug: "bigcorp"}
	f := &fakeFetcher{
		bySlug: func(_ context.Context, slug string) (*Organization, error) {
			if slug != "bigcorp" {
				t.Errorf("inner fetcher called with slug %q, want bigcorp", slug)
			}
			return want, nil
		},
	}
	got, err := NewOrgLookup(f).BySlug(context.Background(), "bigcorp")
	if err != nil {
		t.Fatalf("BySlug: unexpected error: %v", err)
	}
	if got.ID != "id-2" || got.Slug != "bigcorp" {
		t.Fatalf("BySlug: got %+v, want id=id-2 slug=bigcorp", got)
	}
}

func TestOrgLookup_BySlug_pgxNoRows_returnsSentinel(t *testing.T) {
	f := &fakeFetcher{
		bySlug: func(_ context.Context, _ string) (*Organization, error) {
			return nil, fmt.Errorf("wrapped slug not found: %w", pgx.ErrNoRows)
		},
	}
	_, err := NewOrgLookup(f).BySlug(context.Background(), "ghost-corp")
	if !errors.Is(err, middleware.ErrOrgNotFound) {
		t.Fatalf("BySlug: got %v, want middleware.ErrOrgNotFound", err)
	}
}

func TestOrgLookup_BySlug_genericError_passedThrough(t *testing.T) {
	want := errors.New("server gone")
	f := &fakeFetcher{
		bySlug: func(_ context.Context, _ string) (*Organization, error) {
			return nil, want
		},
	}
	_, err := NewOrgLookup(f).BySlug(context.Background(), "bigcorp")
	if !errors.Is(err, want) {
		t.Fatalf("BySlug: got %v, want %v", err, want)
	}
}

// Compile-time guarantee: *OrgLookup must satisfy
// middleware.OrgLookup. Caught by the var declaration in
// orglookup.go too, but having it in the test file makes the
// contract explicit to readers.
func TestOrgLookup_implementsMiddlewareInterface(t *testing.T) {
	var _ middleware.OrgLookup = NewOrgLookup(&fakeFetcher{})
}

// Sanity: orgctx.Org is the right shape — the adapter must return
// the two-field struct, not the full *Organization.
func TestOrgLookup_returnsOrgctxOrg_notFullOrganization(t *testing.T) {
	got := orgctx.Org{}
	_ = got.ID
	_ = got.Slug
	// If the orgctx.Org struct grows a field, this test won't catch
	// it — but the adapter signature does (orgctx.Org return type).
}

// The tenant resolver consults the lookup on every request (the
// default-org fallback path in particular), so the adapter caches
// successful lookups for a short TTL to avoid a database round-trip
// per request platform-wide.

func TestOrgLookup_ByID_secondCallWithinTTL_servedFromCache(t *testing.T) {
	calls := 0
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			calls++
			return &Organization{ID: "id-1", Slug: "acme"}, nil
		},
	}
	l := NewOrgLookup(f)

	for i := 0; i < 3; i++ {
		got, err := l.ByID(context.Background(), "id-1")
		if err != nil {
			t.Fatalf("ByID call %d: unexpected error: %v", i, err)
		}
		if got.ID != "id-1" || got.Slug != "acme" {
			t.Fatalf("ByID call %d: got %+v, want id-1/acme", i, got)
		}
	}
	if calls != 1 {
		t.Fatalf("inner fetcher called %d times, want 1 (cache must absorb repeats)", calls)
	}
}

func TestOrgLookup_ByID_afterTTL_refetches(t *testing.T) {
	calls := 0
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			calls++
			return &Organization{ID: "id-1", Slug: "acme"}, nil
		},
	}
	l := NewOrgLookup(f)

	clock := time.Unix(1000, 0)
	l.now = func() time.Time { return clock }

	if _, err := l.ByID(context.Background(), "id-1"); err != nil {
		t.Fatalf("first ByID: %v", err)
	}
	clock = clock.Add(l.ttl + time.Second)
	if _, err := l.ByID(context.Background(), "id-1"); err != nil {
		t.Fatalf("second ByID: %v", err)
	}
	if calls != 2 {
		t.Fatalf("inner fetcher called %d times, want 2 (entry past TTL must refetch)", calls)
	}
}

func TestOrgLookup_ByID_errorNotCached(t *testing.T) {
	calls := 0
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("transient connection error")
			}
			return &Organization{ID: "id-1", Slug: "acme"}, nil
		},
	}
	l := NewOrgLookup(f)

	if _, err := l.ByID(context.Background(), "id-1"); err == nil {
		t.Fatal("first ByID: expected the transient error")
	}
	got, err := l.ByID(context.Background(), "id-1")
	if err != nil {
		t.Fatalf("second ByID: unexpected error: %v (errors must not be cached)", err)
	}
	if got.ID != "id-1" {
		t.Fatalf("second ByID: got %+v, want id-1", got)
	}
}

func TestOrgLookup_BySlug_cachedIndependentlyFromByID(t *testing.T) {
	idCalls, slugCalls := 0, 0
	f := &fakeFetcher{
		byID: func(_ context.Context, _ string) (*Organization, error) {
			idCalls++
			return &Organization{ID: "id-1", Slug: "acme"}, nil
		},
		bySlug: func(_ context.Context, _ string) (*Organization, error) {
			slugCalls++
			return &Organization{ID: "id-1", Slug: "acme"}, nil
		},
	}
	l := NewOrgLookup(f)

	if _, err := l.ByID(context.Background(), "id-1"); err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if _, err := l.BySlug(context.Background(), "acme"); err != nil {
		t.Fatalf("BySlug: %v", err)
	}
	if _, err := l.BySlug(context.Background(), "acme"); err != nil {
		t.Fatalf("BySlug repeat: %v", err)
	}
	if idCalls != 1 || slugCalls != 1 {
		t.Fatalf("fetcher calls = (byID=%d, bySlug=%d), want (1, 1)", idCalls, slugCalls)
	}
}

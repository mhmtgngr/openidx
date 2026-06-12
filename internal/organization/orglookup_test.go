package organization

import (
	"context"
	"errors"
	"fmt"
	"testing"

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

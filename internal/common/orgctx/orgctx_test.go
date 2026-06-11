package orgctx

import (
	"context"
	"errors"
	"testing"
)

func TestFrom_emptyContext_returnsErrNoOrgContext(t *testing.T) {
	_, err := From(context.Background())
	if !errors.Is(err, ErrNoOrgContext) {
		t.Fatalf("expected ErrNoOrgContext, got %v", err)
	}
}

func TestWith_thenFrom_roundtrips(t *testing.T) {
	want := Org{ID: "11111111-2222-3333-4444-555555555555", Slug: "acme"}
	ctx := With(context.Background(), want)
	got, err := From(ctx)
	if err != nil {
		t.Fatalf("From: unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("From: got %+v, want %+v", got, want)
	}
}

func TestWith_overwritesPreviousOrg(t *testing.T) {
	first := Org{ID: "aaaaaaaa-1111-1111-1111-111111111111", Slug: "first"}
	second := Org{ID: "bbbbbbbb-2222-2222-2222-222222222222", Slug: "second"}
	ctx := With(With(context.Background(), first), second)
	got, err := From(ctx)
	if err != nil {
		t.Fatalf("From: unexpected error: %v", err)
	}
	if got != second {
		t.Fatalf("From: got %+v, want %+v (later With must win)", got, second)
	}
}

func TestMustFrom_present_returnsOrg(t *testing.T) {
	want := Org{ID: "id", Slug: "slug"}
	ctx := With(context.Background(), want)
	got := MustFrom(ctx)
	if got != want {
		t.Fatalf("MustFrom: got %+v, want %+v", got, want)
	}
}

func TestMustFrom_absent_panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("MustFrom on empty ctx did not panic")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("MustFrom panic value was %T, want string", r)
		}
		if msg == "" {
			t.Fatal("MustFrom panic message empty")
		}
	}()
	MustFrom(context.Background())
}

func TestIsPlatformAdmin_default_false(t *testing.T) {
	if IsPlatformAdmin(context.Background()) {
		t.Fatal("IsPlatformAdmin returned true on empty ctx; want false")
	}
}

func TestWithPlatformAdmin_marksContext(t *testing.T) {
	ctx := WithPlatformAdmin(context.Background())
	if !IsPlatformAdmin(ctx) {
		t.Fatal("IsPlatformAdmin returned false after WithPlatformAdmin")
	}
}

func TestPlatformAdmin_independentOfOrg(t *testing.T) {
	// A platform admin acting inside org A still has org A on the
	// context; the marker just lets them cross boundaries.
	orgA := Org{ID: "orgA-id", Slug: "orgA"}
	ctx := WithPlatformAdmin(With(context.Background(), orgA))

	got, err := From(ctx)
	if err != nil {
		t.Fatalf("From: unexpected error: %v", err)
	}
	if got != orgA {
		t.Fatalf("From: got %+v, want %+v (org should survive marker)", got, orgA)
	}
	if !IsPlatformAdmin(ctx) {
		t.Fatal("IsPlatformAdmin false after marker + org composition")
	}
}

func TestPlatformAdminMarker_doesNotLeakAcrossDerivedContexts(t *testing.T) {
	// Cancelling a ctx must not strip the marker — context wrapping
	// preserves values.
	ctx := WithPlatformAdmin(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !IsPlatformAdmin(ctx) {
		t.Fatal("IsPlatformAdmin false after context.WithCancel; marker should survive derivation")
	}
}

func TestErrNoOrgContext_isSentinel(t *testing.T) {
	// errors.Is must work for callers that wrap.
	wrapped := errOrgContextWrapper{ErrNoOrgContext}
	if !errors.Is(wrapped, ErrNoOrgContext) {
		t.Fatal("ErrNoOrgContext does not behave as a sentinel under errors.Is")
	}
}

type errOrgContextWrapper struct{ err error }

func (e errOrgContextWrapper) Error() string { return "wrapped: " + e.err.Error() }
func (e errOrgContextWrapper) Unwrap() error { return e.err }

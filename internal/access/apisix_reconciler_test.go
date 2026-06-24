package access

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

type fakeAPISIX struct {
	put      map[string][]byte
	deleted  []string
	existing []string
}

func (f *fakeAPISIX) PutRoute(_ context.Context, name string, body []byte) error {
	if f.put == nil {
		f.put = map[string][]byte{}
	}
	f.put[name] = body
	return nil
}
func (f *fakeAPISIX) DeleteRoute(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}
func (f *fakeAPISIX) ListRouteNames(_ context.Context) ([]string, error) { return f.existing, nil }

type putFailAPISIX struct{ deleted []string }

func (p *putFailAPISIX) PutRoute(_ context.Context, name string, _ []byte) error {
	return fmt.Errorf("put failed: %s", name)
}
func (p *putFailAPISIX) DeleteRoute(_ context.Context, name string) error {
	p.deleted = append(p.deleted, name)
	return nil
}

// The desired routes are ALREADY present in APISIX from a prior pass.
func (p *putFailAPISIX) ListRouteNames(_ context.Context) ([]string, error) {
	return []string{"browzer-psm-tdv-org", "browzer-psm-tdv-org-oidc"}, nil
}

func TestAPISIXReconcilerKeepsDesiredRoutesWhenPutFails(t *testing.T) {
	p := &putFailAPISIX{}
	rec := &APISIXReconciler{
		logger: zap.NewNop(),
		client: p,
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095, oidcCallbacks: []string{"signin-oidc"}},
	}
	desired := []browzerRouteInfo{{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"}}
	if err := rec.applyRoutes(context.Background(), desired); err != nil {
		t.Fatalf("applyRoutes: %v", err)
	}
	// Both routes are still desired (the DB says so) even though their PUTs failed,
	// so neither may be pruned — pruning them would blackout a live app.
	if len(p.deleted) != 0 {
		t.Fatalf("must NOT prune still-desired routes when PUT fails; deleted=%v", p.deleted)
	}
}

func TestAPISIXReconcilerPrunesAllWhenNoneDesired(t *testing.T) {
	// Reuse fakeAPISIX: no put failures, existing has one browzer-* and one non-browzer.
	f := &fakeAPISIX{existing: []string{"browzer-gone", "identity-service"}}
	rec := &APISIXReconciler{
		logger: zap.NewNop(),
		client: f,
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095},
	}
	if err := rec.applyRoutes(context.Background(), nil); err != nil {
		t.Fatalf("applyRoutes: %v", err)
	}
	// No apps desired -> every browzer-* route pruned; non-browzer left alone.
	if len(f.deleted) != 1 || f.deleted[0] != "browzer-gone" {
		t.Fatalf("expected only browzer-gone pruned, got %v", f.deleted)
	}
}

func TestAPISIXReconcilerApplyAndPrune(t *testing.T) {
	f := &fakeAPISIX{existing: []string{"browzer-old", "identity-service"}}
	rec := &APISIXReconciler{
		logger: zap.NewNop(),
		client: f,
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095, oidcCallbacks: []string{"signin-oidc"}},
	}
	desired := []browzerRouteInfo{{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"}}
	if err := rec.applyRoutes(context.Background(), desired); err != nil {
		t.Fatalf("applyRoutes: %v", err)
	}
	if _, ok := f.put["browzer-psm-tdv-org"]; !ok {
		t.Fatalf("overlay route not PUT: %v keys", f.put)
	}
	if _, ok := f.put["browzer-psm-tdv-org-oidc"]; !ok {
		t.Fatal("oidc route not PUT")
	}
	// browzer-old is gone from desired -> deleted; identity-service is left alone.
	if len(f.deleted) != 1 || f.deleted[0] != "browzer-old" {
		t.Fatalf("prune wrong: %v", f.deleted)
	}
}

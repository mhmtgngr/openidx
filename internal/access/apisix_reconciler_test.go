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
func (p *putFailAPISIX) ListRouteNames(_ context.Context) ([]string, error) {
	return []string{"browzer-stale-a", "browzer-stale-b"}, nil
}

func TestAPISIXReconcilerAllPutsFailSkipsPrune(t *testing.T) {
	p := &putFailAPISIX{}
	rec := &APISIXReconciler{
		logger: zap.NewNop(),
		client: p,
		opts:   apisixRouteOpts{bootstrapperNode: "127.0.0.1:8445", hopBasePort: 8095, oidcCallbacks: []string{"signin-oidc"}},
	}
	desired := []browzerRouteInfo{{hostname: "psm.tdv.org", serviceName: "psm-zt", hostingMode: "hop"}}
	err := rec.applyRoutes(context.Background(), desired)
	if err == nil {
		t.Fatal("expected error when all PUTs fail")
	}
	if len(p.deleted) != 0 {
		t.Fatalf("must NOT prune when all PUTs failed; deleted=%v", p.deleted)
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

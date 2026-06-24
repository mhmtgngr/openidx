package access

import (
	"context"
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

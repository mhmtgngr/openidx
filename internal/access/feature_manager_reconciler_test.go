package access

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// When the Ziti reconciler owns controller-side mutations, the feature-manager
// (the admin-console one-click toggle) must NOT imperatively provision Ziti.
// Doing so double-hosts the service (SDK edge terminator + router tunnel
// terminator) and produces the 502 we chased on psm.tdv.org. The reconciler
// path must instead return only the proxy_routes marker and never touch the
// controller — proven here by leaving zitiProvider nil (the imperative path
// would nil-deref on fm.ziti()).
func TestProvisionBrowZerDefersToReconciler(t *testing.T) {
	fm := &FeatureManager{logger: zap.NewNop()}
	fm.SetReconcilerEnabled(true)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: "11111111-1111-1111-1111-111111111111"})
	ids, err := fm.provisionFeature(ctx, "route-1", FeatureBrowZer, &FeatureConfig{})
	if err != nil {
		t.Fatalf("reconciler-aware BrowZer provision must succeed without a Ziti manager, got: %v", err)
	}
	if ids["browzer_enabled"] != "true" {
		t.Fatalf("expected browzer_enabled marker, got %v", ids)
	}
}

// Disabling under the reconciler must also skip imperative teardown: the
// reconciler owns deletion off the proxy_routes flags. With a nil zitiProvider
// the imperative DeleteService path would nil-deref, so a clean return proves
// the defer.
func TestDeprovisionDefersToReconciler(t *testing.T) {
	fm := &FeatureManager{logger: zap.NewNop()}
	fm.SetReconcilerEnabled(true)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: "11111111-1111-1111-1111-111111111111"})
	if err := fm.deprovisionFeature(ctx, "route-1", FeatureZiti, map[string]string{"ziti_service_id": "svc-1"}); err != nil {
		t.Fatalf("reconciler-aware Ziti deprovision must succeed without a Ziti manager, got: %v", err)
	}
	if err := fm.deprovisionFeature(ctx, "route-1", FeatureBrowZer, map[string]string{"ziti_service_id": "svc-1"}); err != nil {
		t.Fatalf("reconciler-aware BrowZer deprovision must succeed without a Ziti manager, got: %v", err)
	}
}

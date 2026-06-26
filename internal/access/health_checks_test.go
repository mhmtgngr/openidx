package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func TestListEdgeEntitiesReturnsAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") == "" {
			t.Errorf("expected an explicit limit on %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"a","name":"openidx-A"},{"id":"b","name":"openidx-B"}]}`))
	}))
	defer srv.Close()
	zm := &ZitiManager{logger: zap.NewNop(), mgmtToken: "fake", mgmtClient: srv.Client(),
		cfg: &config.Config{ZitiCtrlURL: srv.URL}, initialized: true}
	got, err := zm.listEdgeEntities(context.Background(), "services")
	if err != nil {
		t.Fatalf("listEdgeEntities: %v", err)
	}
	if len(got) != 2 || got[0].Name != "openidx-A" {
		t.Fatalf("expected 2 entities, got %+v", got)
	}
}

func TestBaseCheckImplementsInterface(t *testing.T) {
	var _ Check = &fnCheck{}
}

func TestDedupBrowzerConfigDetectFlagsExtraRows(t *testing.T) {
	if f := dedupBrowzerConfigFinding(56); f.Status != "drift" || !f.Safe {
		t.Fatalf("56 rows should be safe drift, got %+v", f)
	}
	if f := dedupBrowzerConfigFinding(1); f.Status != "ok" {
		t.Fatalf("1 row should be ok, got %+v", f)
	}
}

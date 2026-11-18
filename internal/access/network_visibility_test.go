package access

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// The network stage of a reconcile pass must say when it leaves a resource
// out and when the set it wants changes. It used to say nothing on either, so
// a stored network resource that never reached the overlay left no trace.

func observedReconciler(t *testing.T) (*ZitiReconciler, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	return &ZitiReconciler{logger: zap.New(core), status: map[string]string{}}, logs
}

func messages(logs *observer.ObservedLogs, level zapcore.Level, contains string) []observer.LoggedEntry {
	var out []observer.LoggedEntry
	for _, e := range logs.All() {
		if e.Level == level && strings.Contains(e.Message, contains) {
			out = append(out, e)
		}
	}
	return out
}

func rowFor(app string) DesiredNetworkService {
	return DesiredNetworkService{ApplicationID: app, OrgID: "org-1"}
}

const visApp = "44444444-4444-4444-4444-444444444444"

func TestAResourceWithUnreadablePortsIsLoggedOnce(t *testing.T) {
	pinTargetGuard(t)
	rec, logs := observedReconciler(t)
	target := NetworkTarget{DNSNames: []string{"app.corp.example"}}

	if _, ok := rec.desiredFromRow(rowFor(visApp), target, []byte(`{not json`)); ok {
		t.Fatal("a resource whose port ranges do not parse was kept")
	}
	if _, ok := rec.desiredFromRow(rowFor(visApp), target, []byte(`{not json`)); ok {
		t.Fatal("the second pass kept it")
	}
	warns := messages(logs, zapcore.WarnLevel, "not on the overlay")
	if len(warns) != 1 {
		t.Fatalf("%d warnings over two passes, want exactly 1", len(warns))
	}
	got := warns[0].ContextMap()
	if got["application_id"] != visApp || got["org_id"] != "org-1" || !strings.Contains(got["status"].(string), "port_ranges does not parse") {
		t.Errorf("the warning does not name the resource and the reason: %v", got)
	}
	if st := rec.StatusSnapshot()[networkServiceName(visApp)]; !strings.HasPrefix(st, "error:") {
		t.Errorf("status %q, want the error", st)
	}
}

func TestARefusedTargetIsLoggedWithTheReason(t *testing.T) {
	pinTargetGuard(t)
	rec, logs := observedReconciler(t)

	if _, ok := rec.desiredFromRow(rowFor(visApp), NetworkTarget{Hosts: []string{"127.0.0.1"}}, nil); ok {
		t.Fatal("a loopback target was kept")
	}
	warns := messages(logs, zapcore.WarnLevel, "not on the overlay")
	if len(warns) != 1 || !strings.Contains(warns[0].ContextMap()["status"].(string), "127.0.0.1") {
		t.Fatalf("want one warning naming the refused address, got %v", warns)
	}
}

func TestAGoodResourceIsKeptAndNotWarnedAbout(t *testing.T) {
	pinTargetGuard(t)
	rec, logs := observedReconciler(t)

	d, ok := rec.desiredFromRow(rowFor(visApp), NetworkTarget{DNSNames: []string{"app.corp.example"}},
		[]byte(`[{"low":443,"high":443}]`))
	if !ok || d.ServiceName != networkServiceName(visApp) {
		t.Fatalf("a valid resource was dropped: ok=%v svc=%q", ok, d.ServiceName)
	}
	if n := len(messages(logs, zapcore.WarnLevel, "")); n != 0 {
		t.Errorf("%d warnings for a valid resource", n)
	}
}

func TestARepairedResourceIsAnnouncedOnce(t *testing.T) {
	pinTargetGuard(t)
	rec, logs := observedReconciler(t)
	target := NetworkTarget{DNSNames: []string{"app.corp.example"}}

	rec.desiredFromRow(rowFor(visApp), target, []byte(`{not json`))
	d, ok := rec.desiredFromRow(rowFor(visApp), target, []byte(`[{"low":443,"high":443}]`))
	if !ok {
		t.Fatal("the repaired resource was dropped")
	}
	if !rec.noteNetworkStatus(d, "synced") {
		t.Error("error to synced was not reported as a change")
	}
	if rec.noteNetworkStatus(d, "synced") {
		t.Error("synced to synced was reported as a change")
	}
	if n := len(messages(logs, zapcore.InfoLevel, "status changed")); n != 1 {
		t.Errorf("%d announcements of the repair, want 1", n)
	}
}

func TestThePassLogsTheDesiredSetWhenItChanges(t *testing.T) {
	f, zm, rec, d := failClosedFixture(t)
	_ = f
	resetRouterHosts(t, false)
	core, logs := observer.New(zapcore.DebugLevel)
	rec.logger = zap.New(core)

	desired := []DesiredNetworkService{d}
	rec.loadNetwork = func(context.Context) ([]DesiredNetworkService, error) { return desired, nil }

	rec.reconcileNetworkServices(context.Background(), zm)
	changed := messages(logs, zapcore.InfoLevel, "desired set changed")
	if len(changed) != 1 || changed[0].ContextMap()["desired"] != int64(1) {
		t.Fatalf("first pass: want one line with desired=1, got %v", changed)
	}
	if got := changed[0].ContextMap()["services"].([]interface{}); len(got) != 1 || got[0] != d.ServiceName {
		t.Errorf("the line does not name the service: %v", got)
	}

	rec.reconcileNetworkServices(context.Background(), zm)
	if n := len(messages(logs, zapcore.InfoLevel, "desired set changed")); n != 1 {
		t.Errorf("an unchanged set was logged again (%d lines)", n)
	}
	if n := len(messages(logs, zapcore.DebugLevel, "network services: pass")); n != 2 {
		t.Errorf("%d per-pass debug lines over two passes, want 2", n)
	}

	desired = nil
	rec.reconcileNetworkServices(context.Background(), zm)
	changed = messages(logs, zapcore.InfoLevel, "desired set changed")
	if len(changed) != 2 || changed[1].ContextMap()["desired"] != int64(0) {
		t.Fatalf("emptying the set: want a second line with desired=0, got %v", changed)
	}
}

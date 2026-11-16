package control

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"testing"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
	"github.com/openidx/openidx/agent/internal/ipc"
)

// unenrolledDeps diagnoses a device with no agent.json: no server is known,
// so no probe leaves the test.
func unenrolledDeps(t *testing.T) {
	t.Helper()
	old := doctorDeps
	doctorDeps = func() collect.Deps {
		return collect.Deps{
			LoadConfig: func(string) (*agent.AgentConfig, error) { return nil, fs.ErrNotExist },
			QueryIPC:   func() (*ipc.Status, error) { return nil, errors.New("no pipe") },
			Probes:     doctor.NewProbes(),
			Actions:    doctor.NewActions(),
		}
	}
	t.Cleanup(func() { doctorDeps = old })
}

func TestDoctorRoute(t *testing.T) {
	unenrolledDeps(t)
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/doctor?lang=tr")
	if code != http.StatusOK {
		t.Fatalf("status code = %d, body=%s", code, body)
	}
	var r doctor.Report
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("unmarshal report: %v (%s)", err, body)
	}
	if r.Healthy || r.SupportCode == "" || len(r.Items) != len(doctor.CheckOrder) {
		t.Fatalf("report = %+v", r)
	}
	if r.Items[0].Code != doctor.CodeNotEnrolled || r.Items[0].Title != "Bu cihaz henüz OpenIDX'e kaydedilmemiş." {
		t.Errorf("first item = %+v", r.Items[0])
	}

	if code, body := get(t, c, base, "/doctor?lang=de"); code != http.StatusBadRequest {
		t.Errorf("unknown language: code = %d, body=%s", code, body)
	}
}

func TestDoctorWithFixOnAnUnrepairableDeviceChangesNothing(t *testing.T) {
	unenrolledDeps(t)
	out, err := newTestEngine(t, &fakeBackend{}).Doctor("en", true)
	if err != nil {
		t.Fatal(err)
	}
	var r doctor.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Repairs) != 0 || r.Healthy {
		t.Errorf("not being enrolled has no local repair: %+v", r)
	}
}

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
)

// doctorBudget bounds one diagnosis, repairs and the second look included.
const doctorBudget = 90 * time.Second

// doctorDeps is the seam the tests replace.
var doctorDeps = collect.DefaultDeps

// Doctor diagnoses why this device cannot connect and returns the report as
// JSON, worded in lang ("en", "tr", or "" for the user's own). With fix it
// first applies the repairs that are safe to repeat.
func (e *Engine) Doctor(lang string, fix bool) (string, error) {
	l, err := doctor.ParseLang(lang)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), doctorBudget)
	defer cancel()
	b := collect.Run(ctx, doctorDeps(), e.configDir, checks.AgentVersion, fix)
	out, err := json.Marshal(doctor.NewReport(b, l))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	s.writeDoctor(w, r, false)
}

func (s *Server) handleDoctorRepair(w http.ResponseWriter, r *http.Request) {
	s.writeDoctor(w, r, true)
}

func (s *Server) writeDoctor(w http.ResponseWriter, r *http.Request, fix bool) {
	out, err := s.engine.Doctor(r.URL.Query().Get("lang"), fix)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(out))
}

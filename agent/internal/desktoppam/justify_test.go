package desktoppam

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestRequireJustificationIsClassified(t *testing.T) {
	for _, body := range []string{
		`{"error":"this entry asks why","require_justification":true}`,
		`{"error":"open it in a browser","code":"justification_required"}`,
	} {
		err := classify(refusalFrom(http.StatusForbidden, strings.NewReader(body)))
		if !errors.Is(err, ErrJustificationRequired) {
			t.Errorf("%s classified as %v", body, err)
		}
	}
	if err := classify(refusalFrom(http.StatusForbidden, strings.NewReader(`{"approval_required":true}`))); errors.Is(err, ErrJustificationRequired) {
		t.Error("a plain approval refusal asked for a justification")
	}
}

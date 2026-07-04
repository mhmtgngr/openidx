package credentials

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type fakeVault struct {
	candidate int
	promoted  int
	gotValue  []byte // value passed to AddCandidateVersion
}

func (f *fakeVault) AddCandidateVersion(ctx context.Context, secretID string, v []byte, by string) (int, error) {
	f.candidate = 2
	f.gotValue = append([]byte(nil), v...)
	return 2, nil
}
func (f *fakeVault) PromoteVersion(ctx context.Context, secretID string, version int) error {
	f.promoted = version
	return nil
}

type fakeRotator struct{ applyErr, verifyErr error }

func (f fakeRotator) Type() string { return "fake" }
func (f fakeRotator) Apply(ctx context.Context, cfg map[string]any, v []byte) error {
	return f.applyErr
}
func (f fakeRotator) Verify(ctx context.Context, cfg map[string]any, v []byte) error {
	return f.verifyErr
}

// genRotator is a fakeRotator that ALSO implements ValueGenerator, producing a
// fixed sentinel value. It records the values seen by Apply and Verify (copied,
// since runRotation zeroes the buffer on return).
type genRotator struct {
	sentinel   []byte
	seenApply  []byte
	seenVerify []byte
}

func (g *genRotator) Type() string { return "gen" }
func (g *genRotator) Generate(gp GenerationPolicy) ([]byte, error) {
	return append([]byte(nil), g.sentinel...), nil
}
func (g *genRotator) Apply(ctx context.Context, cfg map[string]any, v []byte) error {
	g.seenApply = append([]byte(nil), v...)
	return nil
}
func (g *genRotator) Verify(ctx context.Context, cfg map[string]any, v []byte) error {
	g.seenVerify = append([]byte(nil), v...)
	return nil
}

func TestRunRotation_ValueGenerator(t *testing.T) {
	sentinel := []byte("SENTINEL-KEY")

	// A rotator implementing ValueGenerator: the sentinel must flow through
	// AddCandidateVersion, Apply, and Verify.
	t.Run("value-generator", func(t *testing.T) {
		fv := &fakeVault{}
		gr := &genRotator{sentinel: sentinel}
		status, promoted, _ := runRotation(context.Background(), "dummy-secret-id",
			gr, fv, GenerationPolicy{Length: 12}, map[string]any{})
		if status != "succeeded" || !promoted {
			t.Fatalf("status=%q promoted=%v want succeeded/true", status, promoted)
		}
		if !bytes.Equal(fv.gotValue, sentinel) {
			t.Fatalf("AddCandidateVersion got %q want %q", fv.gotValue, sentinel)
		}
		if !bytes.Equal(gr.seenApply, sentinel) {
			t.Fatalf("Apply got %q want %q", gr.seenApply, sentinel)
		}
		if !bytes.Equal(gr.seenVerify, sentinel) {
			t.Fatalf("Verify got %q want %q", gr.seenVerify, sentinel)
		}
	})

	// A plain rotator (no ValueGenerator) still gets a generateSecret value:
	// non-empty and NOT the sentinel.
	t.Run("plain-rotator-uses-generateSecret", func(t *testing.T) {
		fv := &fakeVault{}
		status, promoted, _ := runRotation(context.Background(), "dummy-secret-id",
			fakeRotator{}, fv, GenerationPolicy{Length: 12}, map[string]any{})
		if status != "succeeded" || !promoted {
			t.Fatalf("status=%q promoted=%v want succeeded/true", status, promoted)
		}
		if len(fv.gotValue) == 0 {
			t.Fatalf("AddCandidateVersion got empty value, want generateSecret output")
		}
		if bytes.Equal(fv.gotValue, sentinel) {
			t.Fatalf("AddCandidateVersion got sentinel, want generateSecret output")
		}
	})
}

func TestRotateOutcome(t *testing.T) {
	cases := []struct {
		name          string
		apply, verify error
		wantPromoted  bool
		wantStatus    string
	}{
		{"ok", nil, nil, true, "succeeded"},
		{"apply-fail", errors.New("x"), nil, false, "failed"},
		{"verify-fail", nil, errors.New("x"), false, "failed"},
		{"verify-unsupported", nil, ErrVerifyUnsupported, true, "succeeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := &fakeVault{}
			status, promoted, _ := runRotation(context.Background(), "dummy-secret-id",
				fakeRotator{applyErr: tc.apply, verifyErr: tc.verify},
				fv, GenerationPolicy{Length: 12}, map[string]any{})
			if promoted != tc.wantPromoted {
				t.Fatalf("promoted=%v want %v", promoted, tc.wantPromoted)
			}
			if status != tc.wantStatus {
				t.Fatalf("status=%q want %q", status, tc.wantStatus)
			}
		})
	}
}

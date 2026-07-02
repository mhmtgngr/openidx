package credentials

import (
	"context"
	"errors"
	"testing"
)

type fakeVault struct {
	candidate int
	promoted  int
}

func (f *fakeVault) AddCandidateVersion(ctx context.Context, secretID string, v []byte, by string) (int, error) {
	f.candidate = 2
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
			status, promoted := runRotation(context.Background(), "dummy-secret-id",
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

package credentials

import (
	"context"
	"errors"
	"testing"
)

// minterFakeVault is an in-memory candidateVault for minter tests.
// (fakeVault is already declared in engine_test.go; this is a separate type.)
type minterFakeVault struct {
	candidateVal []byte
	added        int
	promoted     int
}

func (f *minterFakeVault) AddCandidateVersion(_ context.Context, _ string, value []byte, _ string) (int, error) {
	f.added++
	f.candidateVal = append([]byte(nil), value...)
	return 7, nil
}
func (f *minterFakeVault) PromoteVersion(_ context.Context, _ string, version int) error {
	f.promoted = version
	return nil
}

// fakeMinter implements Rotator + Minter + PostRotateCleaner.
type fakeMinter struct {
	minted     []byte
	applyCalls int
	verifyErr  error
	cleaned    bool
}

func (m *fakeMinter) Type() string { return "fake_minter" }
func (m *fakeMinter) Apply(context.Context, map[string]any, []byte) error {
	m.applyCalls++
	return nil
}
func (m *fakeMinter) Verify(context.Context, map[string]any, []byte) error { return m.verifyErr }
func (m *fakeMinter) Mint(context.Context, map[string]any) ([]byte, error) {
	return append([]byte(nil), m.minted...), nil
}
func (m *fakeMinter) Cleanup(context.Context, map[string]any) error { m.cleaned = true; return nil }

func TestRunRotation_MinterPath(t *testing.T) {
	v := &minterFakeVault{}
	m := &fakeMinter{minted: []byte(`{"access_key_id":"AKIA","secret_access_key":"s3cr3t"}`)}

	status, promoted, ver := runRotation(context.Background(), "sec-1", m, v, GenerationPolicy{}, map[string]any{})

	if status != "succeeded" || !promoted || ver != 7 {
		t.Fatalf("got (%s, %v, %d), want (succeeded, true, 7)", status, promoted, ver)
	}
	if m.applyCalls != 0 {
		t.Errorf("Apply was called %d times on the minter path; want 0", m.applyCalls)
	}
	if string(v.candidateVal) != string(m.minted) {
		t.Errorf("candidate value = %q, want the minted value %q", v.candidateVal, m.minted)
	}
	if v.promoted != 7 {
		t.Errorf("promoted version = %d, want 7", v.promoted)
	}
}

func TestRunRotation_MinterVerifyFailureBlocksPromote(t *testing.T) {
	v := &minterFakeVault{}
	m := &fakeMinter{minted: []byte("x"), verifyErr: errors.New("sts denied")}

	status, promoted, ver := runRotation(context.Background(), "sec-1", m, v, GenerationPolicy{}, map[string]any{})

	if status != "failed" || promoted || ver != 7 {
		t.Fatalf("got (%s, %v, %d), want (failed, false, 7 candidate-exists)", status, promoted, ver)
	}
	if v.promoted != 0 {
		t.Errorf("promoted despite verify failure (version=%d)", v.promoted)
	}
}

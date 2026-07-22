package admin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// fakeSettingsRepository is an in-memory SettingsRepository for unit tests. Its
// existence is the payoff of the Repository extraction: the settings business
// logic in the admin service (defaulting, marshalling, security policy) can now
// be exercised with zero infrastructure — no Postgres, no migrations.
type fakeSettingsRepository struct {
	store map[string][]byte
	// getErr, when set, is returned by GetRaw to simulate a DB outage.
	getErr error
	// putErr, when set, is returned by PutRaw to simulate a write failure.
	putErr error
	// call counters for behavior assertions.
	getCalls int
	putCalls int
}

func newFakeSettingsRepository() *fakeSettingsRepository {
	return &fakeSettingsRepository{store: map[string][]byte{}}
}

func (f *fakeSettingsRepository) GetRaw(_ context.Context, key string) ([]byte, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.store[key]
	if !ok {
		return nil, ErrSettingNotFound
	}
	return v, nil
}

func (f *fakeSettingsRepository) PutRaw(_ context.Context, key string, value []byte) error {
	f.putCalls++
	if f.putErr != nil {
		return f.putErr
	}
	// Copy to mimic storage semantics (caller may reuse the buffer).
	cp := make([]byte, len(value))
	copy(cp, value)
	f.store[key] = cp
	return nil
}

func newTestService(repo SettingsRepository) *Service {
	return &Service{logger: zap.NewNop(), settings: repo}
}

// GetSettings must fall back to safe defaults when the row is absent, and those
// defaults must be security-sane (this is what an unconfigured deployment runs
// with).
func TestGetSettingsFallsBackToDefaults(t *testing.T) {
	repo := newFakeSettingsRepository()
	s := newTestService(repo)

	got, err := s.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got == nil {
		t.Fatal("expected default settings, got nil")
	}
	if repo.getCalls != 1 {
		t.Errorf("GetSettings should hit the repo once, got %d", repo.getCalls)
	}
	// Spot-check a couple of security-relevant defaults.
	if got.Security.PasswordPolicy.MinLength < 8 {
		t.Errorf("default MinLength = %d, want >= 8 (security floor)", got.Security.PasswordPolicy.MinLength)
	}
	if got.General.OrganizationName == "" {
		t.Error("default OrganizationName must not be empty")
	}
}

// A stored blob round-trips through GetSettings.
func TestGetSettingsReturnsStored(t *testing.T) {
	repo := newFakeSettingsRepository()
	stored := &Settings{}
	stored.General.OrganizationName = "Acme"
	stored.Security.PasswordPolicy.MinLength = 20
	b, _ := json.Marshal(stored)
	repo.store["system"] = b

	s := newTestService(repo)
	got, err := s.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.General.OrganizationName != "Acme" {
		t.Errorf("OrganizationName = %q, want Acme", got.General.OrganizationName)
	}
	if got.Security.PasswordPolicy.MinLength != 20 {
		t.Errorf("MinLength = %d, want 20", got.Security.PasswordPolicy.MinLength)
	}
}

// Corrupt JSON in the row must not crash or leak — it degrades to defaults.
func TestGetSettingsCorruptRowFallsBackToDefaults(t *testing.T) {
	repo := newFakeSettingsRepository()
	repo.store["system"] = []byte("{not json")
	s := newTestService(repo)

	got, err := s.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got == nil || got.General.OrganizationName == "" {
		t.Error("corrupt row should fall back to non-empty defaults")
	}
}

// UpdateSettings marshals and delegates to PutRaw under the 'system' key.
func TestUpdateSettingsDelegatesToRepository(t *testing.T) {
	repo := newFakeSettingsRepository()
	s := newTestService(repo)

	in := &Settings{}
	in.General.OrganizationName = "Delegated"
	if err := s.UpdateSettings(context.Background(), in); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if repo.putCalls != 1 {
		t.Errorf("expected 1 PutRaw call, got %d", repo.putCalls)
	}
	raw, ok := repo.store["system"]
	if !ok {
		t.Fatal("UpdateSettings did not persist under the 'system' key")
	}
	var back Settings
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("stored value is not valid JSON: %v", err)
	}
	if back.General.OrganizationName != "Delegated" {
		t.Errorf("persisted OrganizationName = %q, want Delegated", back.General.OrganizationName)
	}
}

// A write failure surfaces as an error (not swallowed).
func TestUpdateSettingsPropagatesWriteError(t *testing.T) {
	repo := newFakeSettingsRepository()
	repo.putErr = errors.New("disk full")
	s := newTestService(repo)

	err := s.UpdateSettings(context.Background(), &Settings{})
	if err == nil {
		t.Fatal("expected UpdateSettings to propagate the write error")
	}
}

// The Postgres repo must guard a nil db instead of panicking (matches the
// nil-db guards added to the other aggregates).
func TestPostgresSettingsRepositoryNilDBGuards(t *testing.T) {
	repo := NewPostgresSettingsRepository(nil)
	if _, err := repo.GetRaw(context.Background(), "system"); err == nil {
		t.Error("GetRaw with nil db should return an error, not panic")
	}
	if err := repo.PutRaw(context.Background(), "system", []byte("{}")); err == nil {
		t.Error("PutRaw with nil db should return an error, not panic")
	}
}

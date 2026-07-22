package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeSessionRepository is an in-memory SessionRepository for unit tests.
type fakeSessionRepository struct {
	byID map[string]*Session
}

func newFakeSessionRepository() *fakeSessionRepository {
	return &fakeSessionRepository{byID: map[string]*Session{}}
}

func (f *fakeSessionRepository) ListByUser(_ context.Context, userID string) ([]Session, error) {
	var out []Session
	for _, s := range f.byID {
		if s.UserID == userID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeSessionRepository) CountActive(_ context.Context, userID string) (int, error) {
	n := 0
	for _, s := range f.byID {
		if s.UserID == userID && time.Now().Before(s.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (f *fakeSessionRepository) IsValid(_ context.Context, sessionID string) (bool, error) {
	s, ok := f.byID[sessionID]
	if !ok {
		return false, ErrSessionNotFound
	}
	return time.Now().Before(s.ExpiresAt), nil
}

func (f *fakeSessionRepository) Create(_ context.Context, s *Session) error {
	if s.ID == "" {
		s.ID = "generated-" + s.UserID
	}
	cp := *s
	f.byID[s.ID] = &cp
	return nil
}

func (f *fakeSessionRepository) UpdateActivity(_ context.Context, sessionID string) error {
	s, ok := f.byID[sessionID]
	if !ok || !time.Now().Before(s.ExpiresAt) {
		return ErrSessionNotFound
	}
	s.LastSeenAt = time.Now()
	return nil
}

func (f *fakeSessionRepository) Terminate(_ context.Context, sessionID string) error {
	delete(f.byID, sessionID)
	return nil
}

func serviceWithSessionRepo(repo SessionRepository) *Service {
	return &Service{sessions: repo, logger: zap.NewNop()}
}

func TestCreateSessionDelegates(t *testing.T) {
	repo := newFakeSessionRepository()
	svc := serviceWithSessionRepo(repo)

	sess, err := svc.CreateSession(context.Background(), "u-1", "client-a", "1.2.3.4", "agent", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected the repository to write back a generated id")
	}
	if _, ok := repo.byID[sess.ID]; !ok {
		t.Fatal("session not persisted through the repository")
	}
}

func TestIsSessionValid(t *testing.T) {
	repo := newFakeSessionRepository()
	repo.byID["live"] = &Session{ID: "live", ExpiresAt: time.Now().Add(time.Hour)}
	repo.byID["dead"] = &Session{ID: "dead", ExpiresAt: time.Now().Add(-time.Hour)}
	svc := serviceWithSessionRepo(repo)

	if ok, err := svc.IsSessionValid(context.Background(), "live"); err != nil || !ok {
		t.Fatalf("live session should be valid, got %v/%v", ok, err)
	}
	if ok, _ := svc.IsSessionValid(context.Background(), "dead"); ok {
		t.Fatal("expired session should be invalid")
	}
	if _, err := svc.IsSessionValid(context.Background(), "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing session should surface ErrSessionNotFound, got %v", err)
	}
}

func TestUpdateSessionActivityNotFound(t *testing.T) {
	svc := serviceWithSessionRepo(newFakeSessionRepository())
	err := svc.UpdateSessionActivity(context.Background(), "ghost")
	if err == nil || err.Error() != "session not found or is revoked/expired" {
		t.Fatalf("expected legacy not-found contract, got %v", err)
	}
}

func TestTerminateAndCountSessions(t *testing.T) {
	repo := newFakeSessionRepository()
	repo.byID["s1"] = &Session{ID: "s1", UserID: "u-1", ExpiresAt: time.Now().Add(time.Hour)}
	repo.byID["s2"] = &Session{ID: "s2", UserID: "u-1", ExpiresAt: time.Now().Add(time.Hour)}
	svc := serviceWithSessionRepo(repo)

	if n, _ := svc.CountActiveSessions(context.Background(), "u-1"); n != 2 {
		t.Fatalf("CountActiveSessions = %d, want 2", n)
	}
	if err := svc.TerminateSession(context.Background(), "s1"); err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if n, _ := svc.CountActiveSessions(context.Background(), "u-1"); n != 1 {
		t.Fatalf("after terminate, CountActiveSessions = %d, want 1", n)
	}
	sessions, _ := svc.GetUserSessions(context.Background(), "u-1")
	if len(sessions) != 1 {
		t.Fatalf("GetUserSessions len = %d, want 1", len(sessions))
	}
}

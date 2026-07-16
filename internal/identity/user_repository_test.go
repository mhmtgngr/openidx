package identity

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// fakeUserRepository is an in-memory UserRepository for unit tests. Its existence
// is the entire payoff of the Repository refactor: business logic that depends on
// UserRepository (instead of a *pgxpool.Pool) can now be tested with zero
// infrastructure — no Postgres, no gin, no migrations.
type fakeUserRepository struct {
	byID       map[string]*User
	byUsername map[string]*User
	// getByIDErr, when set, is returned by GetByID to simulate a DB outage.
	getByIDErr error
	// calls records how many times each method was invoked (behavior assertions).
	getByIDCalls int
}

func newFakeUserRepository() *fakeUserRepository {
	return &fakeUserRepository{
		byID:       map[string]*User{},
		byUsername: map[string]*User{},
	}
}

func (f *fakeUserRepository) add(u *User) {
	f.byID[u.ID] = u
	f.byUsername[u.UserName] = u
}

func (f *fakeUserRepository) GetByID(_ context.Context, id string) (*User, error) {
	f.getByIDCalls++
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	u, ok := f.byID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepository) GetByUsername(_ context.Context, username string) (*User, error) {
	u, ok := f.byUsername[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepository) Exists(_ context.Context, id string) (bool, error) {
	_, ok := f.byID[id]
	return ok, nil
}

// serviceWithRepo builds a Service wired to a fake repository — no DB, no config.
// This is only possible because the Service now depends on the UserRepository
// interface for user reads. A nop logger keeps it a pure unit test.
func serviceWithRepo(repo UserRepository) *Service {
	return &Service{users: repo, logger: zap.NewNop()}
}

// TestGetUserDelegatesToRepository proves the seam: Service.GetUser now returns
// exactly what the repository returns, with no database involved.
func TestGetUserDelegatesToRepository(t *testing.T) {
	repo := newFakeUserRepository()
	repo.add(&User{ID: "u-1", UserName: "alice", Enabled: true})
	svc := serviceWithRepo(repo)

	got, err := svc.GetUser(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserName != "alice" {
		t.Fatalf("UserName = %q, want alice", got.UserName)
	}
	if repo.getByIDCalls != 1 {
		t.Fatalf("expected exactly 1 repository call, got %d", repo.getByIDCalls)
	}
}

// TestGetUserNotFound proves the not-found contract surfaces as ErrUserNotFound.
func TestGetUserNotFound(t *testing.T) {
	repo := newFakeUserRepository()
	svc := serviceWithRepo(repo)

	_, err := svc.GetUser(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

// TestGetUserPropagatesDependencyError proves a repository/DB failure propagates
// (the handler/Tier-2 layer then maps it to a 503/500) rather than being masked.
func TestGetUserPropagatesDependencyError(t *testing.T) {
	repo := newFakeUserRepository()
	dbDown := errors.New("connection refused")
	repo.getByIDErr = dbDown
	svc := serviceWithRepo(repo)

	_, err := svc.GetUser(context.Background(), "u-1")
	if !errors.Is(err, dbDown) {
		t.Fatalf("expected the underlying dependency error to propagate, got %v", err)
	}
}

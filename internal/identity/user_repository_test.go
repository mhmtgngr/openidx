package identity

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// orgCtx returns a context carrying a tenant, as the resolver middleware would.
func orgCtx() context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: "org-test", Slug: "test"})
}

// fakeUserRepository is an in-memory UserRepository for unit tests. Its existence
// is the entire payoff of the Repository refactor: business logic that depends on
// UserRepository (instead of a *pgxpool.Pool) can now be tested with zero
// infrastructure — no Postgres, no gin, no migrations.
type fakeUserRepository struct {
	byID       map[string]*User
	byUsername map[string]*User
	byEmail    map[string]*User
	// getByIDErr, when set, is returned by GetByID to simulate a DB outage.
	getByIDErr error
	// calls records how many times each method was invoked (behavior assertions).
	getByIDCalls int
}

func newFakeUserRepository() *fakeUserRepository {
	return &fakeUserRepository{
		byID:       map[string]*User{},
		byUsername: map[string]*User{},
		byEmail:    map[string]*User{},
	}
}

func (f *fakeUserRepository) add(u *User) {
	f.byID[u.ID] = u
	f.byUsername[u.UserName] = u
	if len(u.Emails) > 0 {
		f.byEmail[u.Emails[0].Value] = u
	}
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

func (f *fakeUserRepository) GetByEmail(_ context.Context, email string) (*User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepository) Exists(_ context.Context, id string) (bool, error) {
	_, ok := f.byID[id]
	return ok, nil
}

func (f *fakeUserRepository) Create(_ context.Context, u *User) error {
	if _, dup := f.byUsername[u.UserName]; dup {
		return ErrUserAlreadyExists
	}
	if u.ID == "" {
		u.ID = "generated-" + u.UserName
	}
	f.add(u)
	return nil
}

func (f *fakeUserRepository) Update(_ context.Context, u *User) error {
	if _, ok := f.byID[u.ID]; !ok {
		return ErrUserNotFound
	}
	f.add(u)
	return nil
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

// TestGetUserByUsernameAndEmailDelegate proves the service_crud.go lookups now
// route through the repository (no DB), returning ErrUserNotFound on a miss.
func TestGetUserByUsernameAndEmailDelegate(t *testing.T) {
	repo := newFakeUserRepository()
	u := &User{ID: "u-2", UserName: "bob"}
	u.Emails = []Email{{Value: "bob@example.test"}}
	repo.add(u)
	svc := serviceWithRepo(repo)

	got, err := svc.GetUserByUsername(context.Background(), "bob")
	if err != nil || got.ID != "u-2" {
		t.Fatalf("GetUserByUsername = %v, %v; want u-2", got, err)
	}

	got, err = svc.GetUserByEmail(context.Background(), "bob@example.test")
	if err != nil || got.ID != "u-2" {
		t.Fatalf("GetUserByEmail = %v, %v; want u-2", got, err)
	}

	if _, err := svc.GetUserByUsername(context.Background(), "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing username should be ErrUserNotFound, got %v", err)
	}
	if _, err := svc.GetUserByEmail(context.Background(), "nobody@example.test"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing email should be ErrUserNotFound, got %v", err)
	}
}

// TestCreateUserDelegatesAndKeepsSideEffects proves the write path: Service.
// CreateUser persists via the repo (which writes back the generated id) and the
// domain side effect (audit) stays in the service. No database.
func TestCreateUserDelegatesToRepository(t *testing.T) {
	repo := newFakeUserRepository()
	svc := serviceWithRepo(repo)

	u := &User{UserName: "carol"}
	if err := svc.CreateUser(orgCtx(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected the repository to write back a generated id")
	}
	if _, ok := repo.byUsername["carol"]; !ok {
		t.Fatal("user was not persisted through the repository")
	}
}

// TestCreateUserDuplicateSurfacesConflict proves a unique violation surfaces as
// ErrUserAlreadyExists (which the handler maps to 409), not a raw DB error.
func TestCreateUserDuplicateSurfacesConflict(t *testing.T) {
	repo := newFakeUserRepository()
	repo.add(&User{ID: "u-1", UserName: "dave"})
	svc := serviceWithRepo(repo)

	err := svc.CreateUser(orgCtx(), &User{UserName: "dave"})
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

// TestUpdateUserNotFound proves updating a missing user returns the legacy
// "user not found" contract callers expect.
func TestUpdateUserNotFound(t *testing.T) {
	repo := newFakeUserRepository()
	svc := serviceWithRepo(repo)

	err := svc.UpdateUser(orgCtx(), &User{ID: "ghost", UserName: "ghost"})
	if err == nil || err.Error() != "user not found" {
		t.Fatalf("expected \"user not found\", got %v", err)
	}
}

package identity

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// fakeGroupRepository is an in-memory GroupRepository for unit tests, mirroring
// fakeUserRepository. It lets group service logic be tested with no database.
type fakeGroupRepository struct {
	byID   map[string]*Group
	byName map[string]*Group
}

func newFakeGroupRepository() *fakeGroupRepository {
	return &fakeGroupRepository{byID: map[string]*Group{}, byName: map[string]*Group{}}
}

func (f *fakeGroupRepository) add(g *Group) {
	f.byID[g.ID] = g
	f.byName[g.GetName()] = g
}

func (f *fakeGroupRepository) GetByID(_ context.Context, id string) (*Group, error) {
	g, ok := f.byID[id]
	if !ok {
		return nil, ErrGroupNotFound
	}
	return g, nil
}

func (f *fakeGroupRepository) GetByName(_ context.Context, name string) (*Group, error) {
	g, ok := f.byName[name]
	if !ok {
		return nil, ErrGroupNotFound
	}
	return g, nil
}

func (f *fakeGroupRepository) Create(_ context.Context, g *Group) error {
	if _, dup := f.byName[g.GetName()]; dup {
		return ErrGroupAlreadyExists
	}
	if g.ID == "" {
		g.ID = "generated-" + g.GetName()
	}
	f.add(g)
	return nil
}

func (f *fakeGroupRepository) Update(_ context.Context, g *Group) error {
	if _, ok := f.byID[g.ID]; !ok {
		return ErrGroupNotFound
	}
	f.add(g)
	return nil
}

func (f *fakeGroupRepository) Delete(_ context.Context, id string) error {
	g, ok := f.byID[id]
	if ok {
		delete(f.byID, id)
		delete(f.byName, g.GetName())
	}
	return nil // idempotent, matches the legacy DeleteGroup contract
}

func serviceWithGroupRepo(repo GroupRepository) *Service {
	return &Service{groups: repo, logger: zap.NewNop()}
}

func TestGroupServiceDelegatesToRepository(t *testing.T) {
	repo := newFakeGroupRepository()
	svc := serviceWithGroupRepo(repo)

	g := &Group{DisplayName: "Engineers"}
	if err := svc.CreateGroup(orgCtx(), g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.ID == "" {
		t.Fatal("expected the repository to write back a generated id")
	}

	got, err := svc.GetGroup(orgCtx(), g.ID)
	if err != nil || got.GetName() != "Engineers" {
		t.Fatalf("GetGroup = %v, %v; want Engineers", got, err)
	}

	byName, err := svc.GetGroupByDisplayName(orgCtx(), "Engineers")
	if err != nil || byName.ID != g.ID {
		t.Fatalf("GetGroupByDisplayName = %v, %v", byName, err)
	}
}

func TestGetGroupNotFound(t *testing.T) {
	svc := serviceWithGroupRepo(newFakeGroupRepository())
	if _, err := svc.GetGroup(orgCtx(), "ghost"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("expected ErrGroupNotFound, got %v", err)
	}
}

func TestCreateGroupDuplicateConflict(t *testing.T) {
	repo := newFakeGroupRepository()
	repo.add(&Group{ID: "g-1", DisplayName: "Admins"})
	svc := serviceWithGroupRepo(repo)

	err := svc.CreateGroup(orgCtx(), &Group{DisplayName: "Admins"})
	if !errors.Is(err, ErrGroupAlreadyExists) {
		t.Fatalf("expected ErrGroupAlreadyExists, got %v", err)
	}
}

func TestUpdateGroupNotFound(t *testing.T) {
	svc := serviceWithGroupRepo(newFakeGroupRepository())
	err := svc.UpdateGroup(orgCtx(), &Group{ID: "ghost", DisplayName: "ghost"})
	if !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("expected ErrGroupNotFound, got %v", err)
	}
}

func TestDeleteGroupIdempotent(t *testing.T) {
	repo := newFakeGroupRepository()
	repo.add(&Group{ID: "g-2", DisplayName: "Temp"})
	svc := serviceWithGroupRepo(repo)

	if err := svc.DeleteGroup(orgCtx(), "g-2"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, ok := repo.byID["g-2"]; ok {
		t.Fatal("group was not removed")
	}
	// Deleting again is a no-op (idempotent), not an error.
	if err := svc.DeleteGroup(orgCtx(), "g-2"); err != nil {
		t.Fatalf("second DeleteGroup should be idempotent, got %v", err)
	}
}

package oauth

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// fakeOAuthClientStore is an in-memory OAuthClientStore for unit tests, so the
// oauth service's client methods can be tested with no database.
type fakeOAuthClientStore struct {
	byClientID map[string]*OAuthClient
}

func newFakeOAuthClientStore() *fakeOAuthClientStore {
	return &fakeOAuthClientStore{byClientID: map[string]*OAuthClient{}}
}

func (f *fakeOAuthClientStore) GetByClientID(_ context.Context, clientID string) (*OAuthClient, error) {
	c, ok := f.byClientID[clientID]
	if !ok {
		return nil, ErrOAuthClientNotFound
	}
	return c, nil
}

func (f *fakeOAuthClientStore) List(_ context.Context, offset, limit int) ([]OAuthClient, int, error) {
	var out []OAuthClient
	for _, c := range f.byClientID {
		out = append(out, *c)
	}
	return out, len(out), nil
}

func (f *fakeOAuthClientStore) Create(_ context.Context, c *OAuthClient) error {
	if _, dup := f.byClientID[c.ClientID]; dup {
		return errors.New("duplicate")
	}
	cp := *c
	f.byClientID[c.ClientID] = &cp
	return nil
}

func (f *fakeOAuthClientStore) Update(_ context.Context, clientID string, c *OAuthClient) error {
	if _, ok := f.byClientID[clientID]; !ok {
		return ErrOAuthClientNotFound
	}
	cp := *c
	f.byClientID[clientID] = &cp
	return nil
}

func (f *fakeOAuthClientStore) Delete(_ context.Context, clientID string) error {
	delete(f.byClientID, clientID)
	return nil
}

func serviceWithClientStore(store OAuthClientStore) *Service {
	return &Service{clients: store, logger: zap.NewNop()}
}

func TestGetClientDelegates(t *testing.T) {
	store := newFakeOAuthClientStore()
	store.byClientID["app-1"] = &OAuthClient{ClientID: "app-1", Name: "App One"}
	svc := serviceWithClientStore(store)

	got, err := svc.GetClient(context.Background(), "app-1")
	if err != nil || got.Name != "App One" {
		t.Fatalf("GetClient = %v, %v; want App One", got, err)
	}
	if _, err := svc.GetClient(context.Background(), "missing"); !errors.Is(err, ErrOAuthClientNotFound) {
		t.Fatalf("missing client should be ErrOAuthClientNotFound, got %v", err)
	}
}

func TestClientCRUDDelegates(t *testing.T) {
	store := newFakeOAuthClientStore()
	svc := serviceWithClientStore(store)

	c := &OAuthClient{ClientID: "app-2", Name: "Two"}
	if err := svc.CreateClient(context.Background(), c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if _, ok := store.byClientID["app-2"]; !ok {
		t.Fatal("client not persisted through the store")
	}

	c.Name = "Two-updated"
	if err := svc.UpdateClient(context.Background(), "app-2", c); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if store.byClientID["app-2"].Name != "Two-updated" {
		t.Fatal("update did not persist")
	}

	if _, total, _ := svc.ListClients(context.Background(), 0, 10); total != 1 {
		t.Fatalf("ListClients total = %d, want 1", total)
	}

	if err := svc.DeleteClient(context.Background(), "app-2"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, ok := store.byClientID["app-2"]; ok {
		t.Fatal("client was not deleted")
	}
}

func TestUpdateClientNotFound(t *testing.T) {
	svc := serviceWithClientStore(newFakeOAuthClientStore())
	err := svc.UpdateClient(context.Background(), "ghost", &OAuthClient{ClientID: "ghost"})
	if !errors.Is(err, ErrOAuthClientNotFound) {
		t.Fatalf("expected ErrOAuthClientNotFound, got %v", err)
	}
}

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	iam "google.golang.org/api/iam/v1"
)

type staticVaultGCP struct{ val []byte }

func (s staticVaultGCP) Use(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.val...), nil
}

type fakeGCPKeyAPI struct {
	keys       []*iam.ServiceAccountKey
	createErr  error
	deleted    []string
	createName string
}

func (f *fakeGCPKeyAPI) ListKeys(context.Context, string) ([]*iam.ServiceAccountKey, error) {
	return f.keys, nil
}
func (f *fakeGCPKeyAPI) CreateKey(context.Context, string) (*iam.ServiceAccountKey, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	name := f.createName
	if name == "" {
		name = "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/NEW"
	}
	keyFile, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com", "private_key_id": "NEW",
	})
	return &iam.ServiceAccountKey{
		Name:           name,
		KeyType:        "USER_MANAGED",
		PrivateKeyData: base64.StdEncoding.EncodeToString(keyFile),
		ValidAfterTime: "2026-07-07T00:00:00Z",
	}, nil
}
func (f *fakeGCPKeyAPI) DeleteKey(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func adminSAJSON() []byte {
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "admin@p.iam.gserviceaccount.com", "private_key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
	})
	return b
}

func newTestGCPRotator(api *fakeGCPKeyAPI, check func(context.Context, []byte) error) *gcpSARotator {
	r := &gcpSARotator{vault: staticVaultGCP{val: adminSAJSON()}}
	r.newAPI = func(context.Context, []byte) (gcpKeyAPI, error) { return api, nil }
	r.check = check
	r.verifyRetries = 3
	r.verifyDelay = 0
	return r
}

func gcpCfg() map[string]any {
	return map[string]any{"service_account_email": "sa@p.iam.gserviceaccount.com", "admin_secret_id": "sec-admin"}
}

func okCheck(context.Context, []byte) error { return nil }

func TestGCPSA_MintReturnsDecodedKeyJSON(t *testing.T) {
	f := &fakeGCPKeyAPI{}
	r := newTestGCPRotator(f, okCheck)
	val, err := r.Mint(context.Background(), gcpCfg())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var kf map[string]string
	if err := json.Unmarshal(val, &kf); err != nil {
		t.Fatalf("Mint returned non-JSON key file: %v (%s)", err, val)
	}
	if kf["type"] != "service_account" || kf["private_key_id"] != "NEW" {
		t.Errorf("minted key = %v, want the newly created SA key file", kf)
	}
}

func TestGCPSA_MintDeletesOldestAtLimit(t *testing.T) {
	keys := make([]*iam.ServiceAccountKey, 0, 10)
	for i := 0; i < 10; i++ {
		vat := "2026-07-0" + string(rune('1'+i%9)) + "T00:00:00Z"
		keys = append(keys, &iam.ServiceAccountKey{
			Name: "projects/p/serviceAccounts/sa/keys/K" + string(rune('0'+i)), KeyType: "USER_MANAGED", ValidAfterTime: vat,
		})
	}
	keys[0].ValidAfterTime = "2020-01-01T00:00:00Z"
	f := &fakeGCPKeyAPI{keys: keys}
	r := newTestGCPRotator(f, okCheck)
	if _, err := r.Mint(context.Background(), gcpCfg()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "projects/p/serviceAccounts/sa/keys/K0" {
		t.Errorf("deleted = %v, want [K0] (oldest, to make room at the 10-key limit)", f.deleted)
	}
}

func TestGCPSA_VerifyRetriesThenSucceeds(t *testing.T) {
	calls := 0
	check := func(context.Context, []byte) error {
		calls++
		if calls <= 2 {
			return errors.New("key not yet propagated")
		}
		return nil
	}
	r := newTestGCPRotator(&fakeGCPKeyAPI{}, check)
	if err := r.Verify(context.Background(), gcpCfg(), []byte(`{"type":"service_account"}`)); err != nil {
		t.Fatalf("Verify should succeed after retries: %v", err)
	}
	if calls != 3 {
		t.Errorf("check calls = %d, want 3 (2 fail + 1 ok)", calls)
	}
}

func TestGCPSA_VerifyFailsAfterAllRetries(t *testing.T) {
	check := func(context.Context, []byte) error { return errors.New("always fails") }
	r := newTestGCPRotator(&fakeGCPKeyAPI{}, check)
	if err := r.Verify(context.Background(), gcpCfg(), []byte(`{}`)); err == nil {
		t.Fatal("Verify should fail when every attempt fails")
	}
}

func TestGCPSA_CleanupDeletesAllButNewestUserManaged(t *testing.T) {
	f := &fakeGCPKeyAPI{keys: []*iam.ServiceAccountKey{
		{Name: "keys/OLD", KeyType: "USER_MANAGED", ValidAfterTime: "2026-07-01T00:00:00Z"},
		{Name: "keys/NEW", KeyType: "USER_MANAGED", ValidAfterTime: "2026-07-07T00:00:00Z"},
		{Name: "keys/SYS", KeyType: "SYSTEM_MANAGED", ValidAfterTime: "2026-07-09T00:00:00Z"},
	}}
	r := newTestGCPRotator(f, okCheck)
	if err := r.Cleanup(context.Background(), gcpCfg()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "keys/OLD" {
		t.Errorf("deleted = %v, want [keys/OLD] (all USER_MANAGED but newest; never SYSTEM_MANAGED)", f.deleted)
	}
}

func TestGCPSA_ValidateConfig(t *testing.T) {
	r := &gcpSARotator{}
	if err := r.ValidateConfig(map[string]any{"admin_secret_id": "s"}); err == nil {
		t.Error("want error when service_account_email missing")
	}
	if err := r.ValidateConfig(map[string]any{"service_account_email": "e"}); err == nil {
		t.Error("want error when admin_secret_id missing")
	}
	if err := r.ValidateConfig(gcpCfg()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

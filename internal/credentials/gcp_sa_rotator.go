package credentials

// gcp_sa_rotator.go — GCP service-account key rotation connector.
//
// Manages a DEDICATED, rotation-managed service account's USER_MANAGED keys. Mirrors
// aws_iam_rotator.go: implements Minter (create a new SA key via the IAM API and return
// its JSON key file), Verify (obtain an access token from the new key, retried for
// propagation), PostRotateCleaner (delete all USER_MANAGED keys but the newest after
// promotion), and ConfigValidator. Apply is a no-op. The stored value is the new key
// FILE JSON (base64-decoded PrivateKeyData); the admin secret is an SA key file JSON.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2/google"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const gcpMaxKeys = 10

type gcpKeyAPI interface {
	ListKeys(ctx context.Context, saResource string) ([]*iam.ServiceAccountKey, error)
	CreateKey(ctx context.Context, saResource string) (*iam.ServiceAccountKey, error)
	DeleteKey(ctx context.Context, keyName string) error
}

type gcpSAConf struct {
	serviceAccountEmail string
	adminSecretID       string
}

func gcpSAConfigFromMap(cfg map[string]any) (gcpSAConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}
	email := str("service_account_email")
	adminSecretID := str("admin_secret_id")
	switch {
	case email == "":
		return gcpSAConf{}, fmt.Errorf("gcp_sa connector: missing required field %q", "service_account_email")
	case adminSecretID == "":
		return gcpSAConf{}, fmt.Errorf("gcp_sa connector: missing required field %q", "admin_secret_id")
	}
	return gcpSAConf{serviceAccountEmail: email, adminSecretID: adminSecretID}, nil
}

type gcpSARotator struct {
	vault         vaultUser
	newAPI        func(ctx context.Context, adminJSON []byte) (gcpKeyAPI, error)
	check         func(ctx context.Context, keyJSON []byte) error
	verifyRetries int
	verifyDelay   time.Duration
}

func NewGCPSARotator(v vaultUser) Rotator {
	return &gcpSARotator{
		vault:         v,
		newAPI:        realGCPKeyClient,
		check:         realGCPTokenCheck,
		verifyRetries: 6,
		verifyDelay:   3 * time.Second,
	}
}

func (r *gcpSARotator) Type() string { return "gcp_sa" }

func (r *gcpSARotator) Apply(_ context.Context, _ map[string]any, _ []byte) error { return nil }

func (r *gcpSARotator) ValidateConfig(cfg map[string]any) error {
	_, err := gcpSAConfigFromMap(cfg)
	return err
}

func saResource(email string) string { return "projects/-/serviceAccounts/" + email }

func (r *gcpSARotator) admin(ctx context.Context, conf gcpSAConf) ([]byte, error) {
	raw, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: fetch admin secret: %w", err)
	}
	var probe struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		zero(raw)
		return nil, fmt.Errorf("gcp_sa: admin secret is not valid JSON: %w", err)
	}
	if probe.ClientEmail == "" || probe.PrivateKey == "" {
		zero(raw)
		return nil, fmt.Errorf("gcp_sa: admin secret missing client_email or private_key")
	}
	return raw, nil
}

func (r *gcpSARotator) Mint(ctx context.Context, cfg map[string]any) ([]byte, error) {
	conf, err := gcpSAConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}
	adminRaw, err := r.admin(ctx, conf)
	if err != nil {
		return nil, err
	}
	defer zero(adminRaw)

	api, err := r.newAPI(ctx, adminRaw)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: build IAM client: %w", err)
	}
	res := saResource(conf.serviceAccountEmail)

	keys, err := api.ListKeys(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: list keys for %q: %w", conf.serviceAccountEmail, err)
	}
	userKeys := userManagedKeys(keys)
	if len(userKeys) >= gcpMaxKeys {
		if oldest := oldestGCPKey(userKeys); oldest != "" {
			if err := api.DeleteKey(ctx, oldest); err != nil {
				return nil, fmt.Errorf("gcp_sa: delete oldest key to make room: %w", err)
			}
		}
	}

	key, err := api.CreateKey(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: create key for %q: %w", conf.serviceAccountEmail, err)
	}
	dec, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("gcp_sa: decode new key data: %w", err)
	}
	return dec, nil
}

func (r *gcpSARotator) Verify(ctx context.Context, _ map[string]any, newValue []byte) error {
	var lastErr error
	for i := 0; i < r.verifyRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("gcp_sa: verify cancelled: %w", ctx.Err())
			case <-time.After(r.verifyDelay):
			}
		}
		if err := r.check(ctx, newValue); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("gcp_sa: verify: key not usable after %d attempts: %w", r.verifyRetries, lastErr)
}

func (r *gcpSARotator) Cleanup(ctx context.Context, cfg map[string]any) error {
	conf, err := gcpSAConfigFromMap(cfg)
	if err != nil {
		return err
	}
	adminRaw, err := r.admin(ctx, conf)
	if err != nil {
		return err
	}
	defer zero(adminRaw)

	api, err := r.newAPI(ctx, adminRaw)
	if err != nil {
		return fmt.Errorf("gcp_sa: build IAM client: %w", err)
	}
	keys, err := api.ListKeys(ctx, saResource(conf.serviceAccountEmail))
	if err != nil {
		return fmt.Errorf("gcp_sa: cleanup list keys: %w", err)
	}
	userKeys := userManagedKeys(keys)
	if len(userKeys) <= 1 {
		return nil
	}
	newest := newestGCPKey(userKeys)
	for _, k := range userKeys {
		if k.Name == newest {
			continue
		}
		if err := api.DeleteKey(ctx, k.Name); err != nil {
			return fmt.Errorf("gcp_sa: cleanup delete key %q: %w", k.Name, err)
		}
	}
	return nil
}

func userManagedKeys(keys []*iam.ServiceAccountKey) []*iam.ServiceAccountKey {
	out := make([]*iam.ServiceAccountKey, 0, len(keys))
	for _, k := range keys {
		if k != nil && k.KeyType != "SYSTEM_MANAGED" {
			out = append(out, k)
		}
	}
	return out
}

func gcpKeyTime(k *iam.ServiceAccountKey) time.Time {
	t, _ := time.Parse(time.RFC3339, k.ValidAfterTime)
	return t
}

func oldestGCPKey(keys []*iam.ServiceAccountKey) string {
	var name string
	var oldest time.Time
	for _, k := range keys {
		t := gcpKeyTime(k)
		if name == "" || t.Before(oldest) {
			name = k.Name
			oldest = t
		}
	}
	return name
}

func newestGCPKey(keys []*iam.ServiceAccountKey) string {
	var name string
	var newest time.Time
	for _, k := range keys {
		t := gcpKeyTime(k)
		if name == "" || t.After(newest) {
			name = k.Name
			newest = t
		}
	}
	return name
}

func realGCPKeyClient(ctx context.Context, adminJSON []byte) (gcpKeyAPI, error) {
	// nolint:staticcheck // SA1019: WithCredentialsJSON is deprecated over the risk of accepting
	// untrusted external-account credential *config*; here adminJSON is a service-account KEY
	// resolved from our own vault (a trusted, operator-controlled source), so that risk does not apply.
	svc, err := iam.NewService(ctx, option.WithCredentialsJSON(adminJSON)) //nolint:staticcheck
	if err != nil {
		return nil, err
	}
	return &realGCPKeyAPI{svc: svc}, nil
}

type realGCPKeyAPI struct{ svc *iam.Service }

func (a *realGCPKeyAPI) ListKeys(ctx context.Context, saRes string) ([]*iam.ServiceAccountKey, error) {
	resp, err := a.svc.Projects.ServiceAccounts.Keys.List(saRes).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

func (a *realGCPKeyAPI) CreateKey(ctx context.Context, saRes string) (*iam.ServiceAccountKey, error) {
	return a.svc.Projects.ServiceAccounts.Keys.Create(saRes, &iam.CreateServiceAccountKeyRequest{}).Context(ctx).Do()
}

func (a *realGCPKeyAPI) DeleteKey(ctx context.Context, keyName string) error {
	_, err := a.svc.Projects.ServiceAccounts.Keys.Delete(keyName).Context(ctx).Do()
	return err
}

func realGCPTokenCheck(ctx context.Context, keyJSON []byte) error {
	// nolint:staticcheck // SA1019: CredentialsFromJSON is deprecated over the risk of accepting
	// untrusted, unvalidated credential *config*; here keyJSON is the service-account KEY we just
	// minted via the IAM API (a trusted, self-produced source), so that risk does not apply.
	creds, err := google.CredentialsFromJSON(ctx, keyJSON, "https://www.googleapis.com/auth/cloud-platform") //nolint:staticcheck
	if err != nil {
		return fmt.Errorf("gcp_sa: parse new key: %w", err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("gcp_sa: obtain token from new key: %w", err)
	}
	if !tok.Valid() {
		return fmt.Errorf("gcp_sa: token from new key is not valid")
	}
	return nil
}

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// This file implements the persistence layer for OUTBOUND SCIM provisioning:
// OpenIDX acting as a SCIM 2.0 client that pushes users/groups to downstream
// SaaS apps. The wire protocol lives in internal/scimclient; here we manage the
// three tables from migration v95 (target apps, local<->remote records, and the
// outbox queue) plus enqueue helpers the identity layer calls on user changes.

// TargetApp is a configured downstream SCIM 2.0 service provider.
type TargetApp struct {
	ID                string          `json:"id"`
	OrgID             string          `json:"org_id,omitempty"`
	Name              string          `json:"name"`
	BaseURL           string          `json:"base_url"`
	AuthType          string          `json:"auth_type"` // bearer | oauth2
	ProvisionUsers    bool            `json:"provision_users"`
	ProvisionGroups   bool            `json:"provision_groups"`
	DeprovisionAction string          `json:"deprovision_action"` // deactivate | delete
	AttributeMapping  json.RawMessage `json:"attribute_mapping,omitempty"`
	Enabled           bool            `json:"enabled"`
	LastSyncAt        *time.Time      `json:"last_sync_at,omitempty"`
	LastSyncStatus    string          `json:"last_sync_status,omitempty"`
	LastSyncError     string          `json:"last_sync_error,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`

	// OAuth2 (auth_type=oauth2) non-secret fields.
	OAuthTokenURL string `json:"oauth_token_url,omitempty"`
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	OAuthScope    string `json:"oauth_scope,omitempty"`
}

// TargetAppInput is the create/update payload from the admin API. Secrets are
// plaintext here and encrypted before storage.
type TargetAppInput struct {
	Name              string          `json:"name"`
	BaseURL           string          `json:"base_url"`
	AuthType          string          `json:"auth_type"`
	BearerToken       string          `json:"bearer_token,omitempty"`
	OAuthTokenURL     string          `json:"oauth_token_url,omitempty"`
	OAuthClientID     string          `json:"oauth_client_id,omitempty"`
	OAuthClientSecret string          `json:"oauth_client_secret,omitempty"`
	OAuthScope        string          `json:"oauth_scope,omitempty"`
	ProvisionUsers    bool            `json:"provision_users"`
	ProvisionGroups   bool            `json:"provision_groups"`
	DeprovisionAction string          `json:"deprovision_action"`
	AttributeMapping  json.RawMessage `json:"attribute_mapping,omitempty"`
	Enabled           bool            `json:"enabled"`
}

// Provisioning outbox operations.
const (
	OpCreate     = "create"
	OpUpdate     = "update"
	OpDeactivate = "deactivate"
	OpActivate   = "activate"
	OpDelete     = "delete"
)

// Queue item delivery states.
const (
	QueuePending    = "pending"
	QueueProcessing = "processing"
	QueueDone       = "done"
	QueueFailed     = "failed"
	QueueDead       = "dead"
)

// Provisioning record lifecycle states.
const (
	RecordPending       = "pending"
	RecordActive        = "active"
	RecordDeprovisioned = "deprovisioned"
	RecordError         = "error"
)

// maxQueueAttempts caps retries before an item is dead-lettered.
const maxQueueAttempts = 8

// validAuthType reports whether t is a supported target auth type.
func validAuthType(t string) bool { return t == "bearer" || t == "oauth2" }

// validDeprovisionAction reports whether a is a supported deprovision policy.
func validDeprovisionAction(a string) bool { return a == "deactivate" || a == "delete" }

// CreateTargetApp validates and persists a new downstream SCIM target,
// encrypting any secrets at rest.
func (s *Service) CreateTargetApp(ctx context.Context, orgID string, in *TargetAppInput) (*TargetApp, error) {
	if in.Name == "" || in.BaseURL == "" {
		return nil, fmt.Errorf("name and base_url are required")
	}
	if in.AuthType == "" {
		in.AuthType = "bearer"
	}
	if !validAuthType(in.AuthType) {
		return nil, fmt.Errorf("unsupported auth_type %q (want bearer|oauth2)", in.AuthType)
	}
	if in.DeprovisionAction == "" {
		in.DeprovisionAction = "deactivate"
	}
	if !validDeprovisionAction(in.DeprovisionAction) {
		return nil, fmt.Errorf("unsupported deprovision_action %q (want deactivate|delete)", in.DeprovisionAction)
	}
	mapping := in.AttributeMapping
	if len(mapping) == 0 {
		mapping = json.RawMessage(`{}`)
	}

	tokenEnc, err := s.encryptSecret(in.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("encrypt bearer token: %w", err)
	}
	secretEnc, err := s.encryptSecret(in.OAuthClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt oauth secret: %w", err)
	}

	id := uuid.NewString()
	_, err = s.db.Pool.Exec(ctx, `
        INSERT INTO scim_target_apps
            (id, org_id, name, base_url, auth_type, auth_token_enc,
             oauth_token_url, oauth_client_id, oauth_client_secret_enc, oauth_scope,
             provision_users, provision_groups, deprovision_action,
             attribute_mapping, enabled)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		id, nullIfEmpty(orgID), in.Name, in.BaseURL, in.AuthType, tokenEnc,
		nullIfEmpty(in.OAuthTokenURL), nullIfEmpty(in.OAuthClientID), secretEnc, nullIfEmpty(in.OAuthScope),
		in.ProvisionUsers, in.ProvisionGroups, in.DeprovisionAction,
		string(mapping), in.Enabled)
	if err != nil {
		return nil, fmt.Errorf("insert target app: %w", err)
	}
	return s.GetTargetApp(ctx, orgID, id)
}

// GetTargetApp loads a target by id (org-scoped).
func (s *Service) GetTargetApp(ctx context.Context, orgID, id string) (*TargetApp, error) {
	row := s.db.Pool.QueryRow(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, base_url, auth_type,
               COALESCE(oauth_token_url,''), COALESCE(oauth_client_id,''), COALESCE(oauth_scope,''),
               provision_users, provision_groups, deprovision_action,
               COALESCE(attribute_mapping,'{}'::jsonb), enabled,
               last_sync_at, COALESCE(last_sync_status,''), COALESCE(last_sync_error,''),
               created_at, updated_at
          FROM scim_target_apps
         WHERE id = $1 AND (org_id::text = $2 OR $2 = '')`, id, orgID)
	return scanTargetApp(row)
}

// ListTargetApps returns all targets for an org.
func (s *Service) ListTargetApps(ctx context.Context, orgID string) ([]TargetApp, error) {
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id, COALESCE(org_id::text,''), name, base_url, auth_type,
               COALESCE(oauth_token_url,''), COALESCE(oauth_client_id,''), COALESCE(oauth_scope,''),
               provision_users, provision_groups, deprovision_action,
               COALESCE(attribute_mapping,'{}'::jsonb), enabled,
               last_sync_at, COALESCE(last_sync_status,''), COALESCE(last_sync_error,''),
               created_at, updated_at
          FROM scim_target_apps
         WHERE (org_id::text = $1 OR $1 = '')
         ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetApp
	for rows.Next() {
		t, err := scanTargetAppRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// UpdateTargetApp updates a target's mutable fields. Secret fields are only
// rewritten when a non-empty value is supplied (so the UI can omit them).
func (s *Service) UpdateTargetApp(ctx context.Context, orgID, id string, in *TargetAppInput) (*TargetApp, error) {
	existing, err := s.GetTargetApp(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if in.Name == "" {
		in.Name = existing.Name
	}
	if in.BaseURL == "" {
		in.BaseURL = existing.BaseURL
	}
	if in.AuthType == "" {
		in.AuthType = existing.AuthType
	}
	if !validAuthType(in.AuthType) {
		return nil, fmt.Errorf("unsupported auth_type %q", in.AuthType)
	}
	if in.DeprovisionAction == "" {
		in.DeprovisionAction = existing.DeprovisionAction
	}
	if !validDeprovisionAction(in.DeprovisionAction) {
		return nil, fmt.Errorf("unsupported deprovision_action %q", in.DeprovisionAction)
	}
	mapping := in.AttributeMapping
	if len(mapping) == 0 {
		mapping = existing.AttributeMapping
		if len(mapping) == 0 {
			mapping = json.RawMessage(`{}`)
		}
	}

	// Only re-encrypt secrets when provided.
	setToken := ""
	if in.BearerToken != "" {
		enc, err := s.encryptSecret(in.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("encrypt bearer token: %w", err)
		}
		setToken = enc
	}
	setSecret := ""
	if in.OAuthClientSecret != "" {
		enc, err := s.encryptSecret(in.OAuthClientSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypt oauth secret: %w", err)
		}
		setSecret = enc
	}

	_, err = s.db.Pool.Exec(ctx, `
        UPDATE scim_target_apps SET
            name=$3, base_url=$4, auth_type=$5,
            auth_token_enc = CASE WHEN $6 = '' THEN auth_token_enc ELSE $6 END,
            oauth_token_url=$7, oauth_client_id=$8,
            oauth_client_secret_enc = CASE WHEN $9 = '' THEN oauth_client_secret_enc ELSE $9 END,
            oauth_scope=$10, provision_users=$11, provision_groups=$12,
            deprovision_action=$13, attribute_mapping=$14, enabled=$15,
            updated_at=NOW()
         WHERE id=$1 AND (org_id::text=$2 OR $2='')`,
		id, orgID, in.Name, in.BaseURL, in.AuthType, setToken,
		nullIfEmpty(in.OAuthTokenURL), nullIfEmpty(in.OAuthClientID), setSecret, nullIfEmpty(in.OAuthScope),
		in.ProvisionUsers, in.ProvisionGroups, in.DeprovisionAction, string(mapping), in.Enabled)
	if err != nil {
		return nil, fmt.Errorf("update target app: %w", err)
	}
	return s.GetTargetApp(ctx, orgID, id)
}

// DeleteTargetApp removes a target and (via ON DELETE CASCADE) its records and
// queued items.
func (s *Service) DeleteTargetApp(ctx context.Context, orgID, id string) error {
	ct, err := s.db.Pool.Exec(ctx,
		`DELETE FROM scim_target_apps WHERE id=$1 AND (org_id::text=$2 OR $2='')`, id, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("target app not found")
	}
	return nil
}

// bearerTokenFor decrypts and returns the static bearer token for a target.
// For oauth2 targets it returns "" (the worker resolves a token separately).
func (s *Service) bearerTokenFor(ctx context.Context, id string) (string, error) {
	var enc *string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT auth_token_enc FROM scim_target_apps WHERE id=$1`, id).Scan(&enc); err != nil {
		return "", err
	}
	if enc == nil || *enc == "" {
		return "", nil
	}
	return s.decryptSecret(*enc)
}

// EnqueueUserOp writes one outbox row per enabled, user-provisioning target for
// the given local user. payload is the local user snapshot the worker maps to a
// SCIM resource. This is the fan-out called by identity on user create/update/
// deprovision. Safe to call within a caller's transaction context.
func (s *Service) EnqueueUserOp(ctx context.Context, orgID, userID, operation string, payload interface{}) (int, error) {
	return s.enqueueOp(ctx, orgID, "user", userID, operation, payload, true)
}

// EnqueueGroupOp is the group counterpart of EnqueueUserOp.
func (s *Service) EnqueueGroupOp(ctx context.Context, orgID, groupID, operation string, payload interface{}) (int, error) {
	return s.enqueueOp(ctx, orgID, "group", groupID, operation, payload, false)
}

func (s *Service) enqueueOp(ctx context.Context, orgID, resourceType, localID, operation string, payload interface{}, isUser bool) (int, error) {
	payloadJSON := json.RawMessage(`{}`)
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, fmt.Errorf("marshal payload: %w", err)
		}
		payloadJSON = b
	}
	flagCol := "provision_groups"
	if isUser {
		flagCol = "provision_users"
	}
	// INSERT ... SELECT fans out to every enabled target that provisions this
	// resource type. One statement, so it participates in the caller's tx.
	ct, err := s.db.Pool.Exec(ctx, fmt.Sprintf(`
        INSERT INTO scim_provisioning_queue
            (org_id, target_id, resource_type, local_id, operation, payload)
        SELECT $1, t.id, $2, $3, $4, $5::jsonb
          FROM scim_target_apps t
         WHERE t.enabled AND t.%s
           AND (t.org_id::text = $6 OR $6 = '')`, flagCol),
		nullIfEmpty(orgID), resourceType, localID, operation, string(payloadJSON), orgID)
	if err != nil {
		return 0, fmt.Errorf("enqueue %s op: %w", resourceType, err)
	}
	return int(ct.RowsAffected()), nil
}

// payloadHash returns a stable hash of a marshaled SCIM payload, used to skip
// no-op updates.
func payloadHash(v interface{}) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// EnqueueFullSync enqueues a create/update op for every local user (and, when
// the target provisions groups, every group) so a target is reconciled to the
// current directory. Returns the number of ops enqueued. Uses INSERT..SELECT so
// the whole reconcile is a couple of statements regardless of directory size.
func (s *Service) EnqueueFullSync(ctx context.Context, orgID string, target *TargetApp) (int, error) {
	total := 0
	if target.ProvisionUsers {
		ct, err := s.db.Pool.Exec(ctx, `
            INSERT INTO scim_provisioning_queue
                (org_id, target_id, resource_type, local_id, operation, payload)
            SELECT $1, $2, 'user', u.id, 'update',
                   jsonb_build_object(
                       'id', u.id::text,
                       'user_name', u.username,
                       'email', u.email,
                       'first_name', COALESCE(u.first_name,''),
                       'last_name', COALESCE(u.last_name,''),
                       'active', COALESCE(u.enabled, true)
                   )
              FROM users u
             WHERE (u.org_id::text = $3 OR $3 = '')`,
			nullIfEmpty(orgID), target.ID, orgID)
		if err != nil {
			return total, fmt.Errorf("enqueue user full sync: %w", err)
		}
		total += int(ct.RowsAffected())
	}
	if target.ProvisionGroups {
		ct, err := s.db.Pool.Exec(ctx, `
            INSERT INTO scim_provisioning_queue
                (org_id, target_id, resource_type, local_id, operation, payload)
            SELECT $1, $2, 'group', g.id, 'update',
                   jsonb_build_object('id', g.id::text, 'display_name', g.name)
              FROM groups g
             WHERE (g.org_id::text = $3 OR $3 = '')`,
			nullIfEmpty(orgID), target.ID, orgID)
		if err != nil {
			return total, fmt.Errorf("enqueue group full sync: %w", err)
		}
		total += int(ct.RowsAffected())
	}
	// Record the reconcile trigger for the admin UI.
	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE scim_target_apps SET last_sync_at=NOW(), last_sync_status='enqueued', last_sync_error=NULL WHERE id=$1`,
		target.ID)
	return total, nil
}

// TargetStatusReport summarizes a target's provisioning state.
type TargetStatusReport struct {
	TargetID        string         `json:"target_id"`
	RecordsByStatus map[string]int `json:"records_by_status"`
	QueueByState    map[string]int `json:"queue_by_state"`
}

// TargetStatus returns per-target record/queue counts for the admin UI.
func (s *Service) TargetStatus(ctx context.Context, targetID string) (*TargetStatusReport, error) {
	rep := &TargetStatusReport{
		TargetID:        targetID,
		RecordsByStatus: map[string]int{},
		QueueByState:    map[string]int{},
	}
	recRows, err := s.db.Pool.Query(ctx,
		`SELECT status, COUNT(*) FROM scim_provisioning_records WHERE target_id=$1 GROUP BY status`, targetID)
	if err != nil {
		return nil, err
	}
	for recRows.Next() {
		var st string
		var n int
		if err := recRows.Scan(&st, &n); err != nil {
			recRows.Close()
			return nil, err
		}
		rep.RecordsByStatus[st] = n
	}
	recRows.Close()

	qRows, err := s.db.Pool.Query(ctx,
		`SELECT state, COUNT(*) FROM scim_provisioning_queue WHERE target_id=$1 GROUP BY state`, targetID)
	if err != nil {
		return nil, err
	}
	defer qRows.Close()
	for qRows.Next() {
		var st string
		var n int
		if err := qRows.Scan(&st, &n); err != nil {
			return nil, err
		}
		rep.QueueByState[st] = n
	}
	return rep, qRows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanTargetApp(row rowScanner) (*TargetApp, error) {
	return scanTargetAppRows(row)
}

func scanTargetAppRows(row rowScanner) (*TargetApp, error) {
	var t TargetApp
	var mapping []byte
	if err := row.Scan(
		&t.ID, &t.OrgID, &t.Name, &t.BaseURL, &t.AuthType,
		&t.OAuthTokenURL, &t.OAuthClientID, &t.OAuthScope,
		&t.ProvisionUsers, &t.ProvisionGroups, &t.DeprovisionAction,
		&mapping, &t.Enabled,
		&t.LastSyncAt, &t.LastSyncStatus, &t.LastSyncError,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	t.AttributeMapping = json.RawMessage(mapping)
	return &t, nil
}

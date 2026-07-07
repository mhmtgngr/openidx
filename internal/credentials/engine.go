package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// vaultPort is the subset of *vault.Service the engine needs.
type vaultPort interface {
	AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)
	PromoteVersion(ctx context.Context, secretID string, version int) error
}

// Auditor records an audit event. Satisfied by *access.UnifiedAuditService.
type Auditor interface {
	RecordEvent(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error
}

// Service is the credential rotation engine.
type Service struct {
	db         *database.PostgresDB
	vault      vaultPort
	rotators   map[string]Rotator // keyed by Type()
	audit      Auditor
	logger     *zap.Logger
	defaultLen int
}

// NewService constructs the engine. rotators is the list of connectors to
// register; defaultLen is the fallback generation length when a policy's
// generation_policy.length is 0.
func NewService(db *database.PostgresDB, v vaultPort, rotators []Rotator, audit Auditor, defaultLen int, logger *zap.Logger) *Service {
	m := make(map[string]Rotator, len(rotators))
	for _, r := range rotators {
		m[r.Type()] = r
	}
	if defaultLen == 0 {
		defaultLen = 24
	}
	return &Service{
		db:         db,
		vault:      v,
		rotators:   m,
		audit:      audit,
		defaultLen: defaultLen,
		logger:     logger.With(zap.String("component", "credentials")),
	}
}

// zero wipes a byte slice in place. Always defer this on generated secrets.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// candidateVault is the minimal vault interface used by runRotation.
type candidateVault interface {
	AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error)
	PromoteVersion(ctx context.Context, secretID string, version int) error
}

// runRotation is the pure, DB-free decision core: generate → candidate →
// apply → verify → promote. Returns the terminal ledger status, whether
// the candidate was promoted, and the candidate version number (0 if the
// candidate was never created — i.e., generate or AddCandidateVersion failed).
//
// Semantics:
//   - generate/AddCandidate failure → ("failed", false, 0) — no candidate.
//   - Apply failure     → ("failed", false, candidateVersion) — candidate exists, no promote.
//   - Verify failure    → ("failed", false, candidateVersion) — candidate exists, no promote.
//   - ErrVerifyUnsupported → skip verify, proceed to promote → ("succeeded", true, candidateVersion).
//   - All steps pass    → ("succeeded", true, candidateVersion).
func runRotation(ctx context.Context, secretID string, r Rotator, v candidateVault, gp GenerationPolicy, cfg map[string]any) (status string, promoted bool, candidateVersion int) {
	var newValue []byte
	var err error
	minter, isMinter := r.(Minter)
	switch {
	case isMinter:
		newValue, err = minter.Mint(ctx, cfg)
	default:
		if g, ok := r.(ValueGenerator); ok {
			newValue, err = g.Generate(gp)
		} else {
			newValue, err = generateSecret(gp)
		}
	}
	if err != nil {
		return "failed", false, 0
	}
	defer zero(newValue)

	// created_by is empty: rotation is a system action with no acting user, and
	// vault_secret_versions.created_by is a UUID column (AddCandidateVersion casts
	// it NULLIF($,'')::uuid), so a non-UUID marker like "rotation" would fail the
	// cast. Empty string → created_by = NULL.
	candidate, err := v.AddCandidateVersion(ctx, secretID, newValue, "")
	if err != nil {
		return "failed", false, 0
	}

	// Minted credentials are already live on the provider — skip Apply.
	if !isMinter {
		if err := r.Apply(ctx, cfg, newValue); err != nil {
			return "failed", false, candidate
		}
	}

	if err := r.Verify(ctx, cfg, newValue); err != nil && !errors.Is(err, ErrVerifyUnsupported) {
		return "failed", false, candidate
	}

	if err := v.PromoteVersion(ctx, secretID, candidate); err != nil {
		return "failed", false, candidate
	}
	return "succeeded", true, candidate
}

// ---- Policy DTOs (no secret values) ----

// Policy is the DTO for a credential_rotation_policies row.
type Policy struct {
	ID               string           `json:"id"`
	OrgID            string           `json:"org_id"`
	SecretID         string           `json:"secret_id"`
	ConnectorType    string           `json:"connector_type"`
	ConnectorConfig  map[string]any   `json:"connector_config"`
	GenerationPolicy GenerationPolicy `json:"generation_policy"`
	IntervalSeconds  int              `json:"interval_seconds"`
	RotateOnCheckout bool             `json:"rotate_on_checkout"`
	Enabled          bool             `json:"enabled"`
	NextRunAt        *time.Time       `json:"next_run_at,omitempty"`
	LastRunAt        *time.Time       `json:"last_run_at,omitempty"`
	LastStatus       string           `json:"last_status,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// PolicyInput is used for create/update requests.
type PolicyInput struct {
	SecretID         string           `json:"secret_id"`
	ConnectorType    string           `json:"connector_type"`
	ConnectorConfig  map[string]any   `json:"connector_config"`
	GenerationPolicy GenerationPolicy `json:"generation_policy"`
	IntervalSeconds  int              `json:"interval_seconds"`
	RotateOnCheckout bool             `json:"rotate_on_checkout"`
	Enabled          *bool            `json:"enabled"`
}

// ErrPolicyNotFound is returned when a rotation policy is not found.
var ErrPolicyNotFound = errors.New("credentials: rotation policy not found")

// ErrInvalidPolicy is returned when policy validation fails.
var ErrInvalidPolicy = errors.New("credentials: invalid rotation policy")

// ErrSecretNotFound is returned when the target secret is not visible under
// the caller's org-scoped context (cross-tenant secret_id rejected).
var ErrSecretNotFound = errors.New("credentials: secret not found or not accessible")

// validatePolicyInput validates connector_type, connector_config, and interval_seconds.
// The connector_type must be a REGISTERED connector; its connector_config is validated by
// the connector itself (via the optional ConfigValidator interface) so any registered
// connector is creatable without the engine hardcoding per-connector field lists.
func (s *Service) validatePolicyInput(in PolicyInput) error {
	rot, ok := s.rotators[in.ConnectorType]
	if !ok {
		return fmt.Errorf("%w: unknown connector_type %q (no registered connector)", ErrInvalidPolicy, in.ConnectorType)
	}
	if cv, ok := rot.(ConfigValidator); ok {
		if err := cv.ValidateConfig(in.ConnectorConfig); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
		}
	}
	if in.IntervalSeconds < 0 {
		return fmt.Errorf("%w: interval_seconds must be >= 0", ErrInvalidPolicy)
	}
	return nil
}

// marshalJSON is a helper to marshal a value to a JSON string for pgx.
func marshalJSON(v any) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CreatePolicy inserts a new rotation policy for the requesting org.
func (s *Service) CreatePolicy(ctx context.Context, in PolicyInput) (*Policy, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.validatePolicyInput(in); err != nil {
		return nil, err
	}
	if in.GenerationPolicy.Length == 0 {
		in.GenerationPolicy.Length = s.defaultLen
	}

	cfgJSON, err := marshalJSON(in.ConnectorConfig)
	if err != nil {
		return nil, err
	}
	gpJSON, err := marshalJSON(in.GenerationPolicy)
	if err != nil {
		return nil, err
	}

	// Verify the target secret is visible under the CALLER's org-scoped context.
	// Running under the request ctx (RLS-scoped) means another org's secret
	// returns false → reject with ErrSecretNotFound.
	var secretExists bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM vault_secrets WHERE id=$1)`, in.SecretID,
	).Scan(&secretExists); err != nil {
		return nil, err
	}
	if !secretExists {
		return nil, ErrSecretNotFound
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	id := uuid.New().String()
	var p Policy
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO credential_rotation_policies
		   (id, org_id, secret_id, connector_type, connector_config, generation_policy,
		    interval_seconds, rotate_on_checkout, enabled)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9)
		 RETURNING id, org_id, secret_id::text, connector_type,
		           connector_config::text, generation_policy::text,
		           interval_seconds, rotate_on_checkout, enabled,
		           next_run_at, last_run_at, COALESCE(last_status,''),
		           created_at, updated_at`,
		id, org.ID, in.SecretID, in.ConnectorType, cfgJSON, gpJSON,
		in.IntervalSeconds, in.RotateOnCheckout, enabled,
	).Scan(
		&p.ID, &p.OrgID, &p.SecretID, &p.ConnectorType,
		new(string), new(string),
		&p.IntervalSeconds, &p.RotateOnCheckout, &p.Enabled,
		&p.NextRunAt, &p.LastRunAt, &p.LastStatus,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.ConnectorConfig = in.ConnectorConfig
	p.GenerationPolicy = in.GenerationPolicy
	return &p, nil
}

// ListPolicies returns all policies for the requesting org.
func (s *Service) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, org_id, secret_id::text, connector_type,
		        connector_config::text, generation_policy::text,
		        interval_seconds, rotate_on_checkout, enabled,
		        next_run_at, last_run_at, COALESCE(last_status,''),
		        created_at, updated_at
		 FROM credential_rotation_policies
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetPolicy returns a single policy by id (org-scoped via RLS).
func (s *Service) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	row := s.db.Pool.QueryRow(ctx,
		`SELECT id, org_id, secret_id::text, connector_type,
		        connector_config::text, generation_policy::text,
		        interval_seconds, rotate_on_checkout, enabled,
		        next_run_at, last_run_at, COALESCE(last_status,''),
		        created_at, updated_at
		 FROM credential_rotation_policies WHERE id = $1`, policyID)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}
	return p, nil
}

// errNoRows is a local sentinel checked after scanPolicy to map pgx.ErrNoRows
// without importing pgx in this file.
var errNoRows = errors.New("no rows")

// scanner abstracts pgx.Row and pgx.Rows for scanPolicy.
type scanner interface {
	Scan(dest ...any) error
}

func scanPolicy(row scanner) (*Policy, error) {
	var p Policy
	var cfgStr, gpStr string
	err := row.Scan(
		&p.ID, &p.OrgID, &p.SecretID, &p.ConnectorType,
		&cfgStr, &gpStr,
		&p.IntervalSeconds, &p.RotateOnCheckout, &p.Enabled,
		&p.NextRunAt, &p.LastRunAt, &p.LastStatus,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		// Translate pgx no-rows without importing pgx.
		if err.Error() == "no rows in result set" {
			return nil, errNoRows
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(cfgStr), &p.ConnectorConfig)
	_ = json.Unmarshal([]byte(gpStr), &p.GenerationPolicy)
	return &p, nil
}

// UpdatePolicy replaces mutable fields of an existing policy (org-scoped).
func (s *Service) UpdatePolicy(ctx context.Context, policyID string, in PolicyInput) (*Policy, error) {
	if _, err := orgctx.From(ctx); err != nil {
		return nil, err
	}
	if err := s.validatePolicyInput(in); err != nil {
		return nil, err
	}
	if in.GenerationPolicy.Length == 0 {
		in.GenerationPolicy.Length = s.defaultLen
	}

	cfgJSON, err := marshalJSON(in.ConnectorConfig)
	if err != nil {
		return nil, err
	}
	gpJSON, err := marshalJSON(in.GenerationPolicy)
	if err != nil {
		return nil, err
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	row := s.db.Pool.QueryRow(ctx,
		`UPDATE credential_rotation_policies
		 SET connector_type    = $2,
		     connector_config  = $3::jsonb,
		     generation_policy = $4::jsonb,
		     interval_seconds  = $5,
		     rotate_on_checkout = $6,
		     enabled           = $7,
		     updated_at        = NOW()
		 WHERE id = $1
		 RETURNING id, org_id, secret_id::text, connector_type,
		           connector_config::text, generation_policy::text,
		           interval_seconds, rotate_on_checkout, enabled,
		           next_run_at, last_run_at, COALESCE(last_status,''),
		           created_at, updated_at`,
		policyID, in.ConnectorType, cfgJSON, gpJSON,
		in.IntervalSeconds, in.RotateOnCheckout, enabled,
	)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}
	return p, nil
}

// DeletePolicy removes a rotation policy (org-scoped via RLS).
func (s *Service) DeletePolicy(ctx context.Context, policyID string) error {
	ct, err := s.db.Pool.Exec(ctx,
		`DELETE FROM credential_rotation_policies WHERE id = $1`, policyID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// policyRow holds what we need to execute a rotation.
type policyRow struct {
	OrgID            string
	SecretID         string
	ConnectorType    string
	ConnectorConfig  map[string]any
	GenerationPolicy GenerationPolicy
	IntervalSeconds  int
	Enabled          bool
	CurrentVersion   int
}

// loadPolicy loads the policy + current version under bypass (org from policy row).
func (s *Service) loadPolicy(ctx context.Context, policyID string) (*policyRow, error) {
	var p policyRow
	var cfgStr, gpStr string
	//orgscope:ignore rotation engine loads policy under bypass-RLS; org is read from the policy row and injected into ctx for all subsequent writes
	err := s.db.Pool.QueryRow(ctx,
		`SELECT p.org_id, p.secret_id::text, p.connector_type,
		        p.connector_config::text, p.generation_policy::text,
		        p.interval_seconds, p.enabled,
		        COALESCE(vs.current_version, 0)
		 FROM credential_rotation_policies p
		 LEFT JOIN vault_secrets vs ON vs.id = p.secret_id
		 WHERE p.id = $1`, policyID,
	).Scan(
		&p.OrgID, &p.SecretID, &p.ConnectorType,
		&cfgStr, &gpStr,
		&p.IntervalSeconds, &p.Enabled,
		&p.CurrentVersion,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(cfgStr), &p.ConnectorConfig)
	_ = json.Unmarshal([]byte(gpStr), &p.GenerationPolicy)
	return &p, nil
}

// RotateSecret runs one rotation for a policy, recording a credential_rotations
// ledger row through the state machine. trigger ∈ {scheduled, on_demand, checkout}.
func (s *Service) RotateSecret(ctx context.Context, policyID, trigger string) error {
	// 1. Load policy under a bypass context so we can read across orgs.
	bypassCtx := orgctx.WithBypassRLS(ctx)
	p, err := s.loadPolicy(bypassCtx, policyID)
	if err != nil {
		return fmt.Errorf("credentials: load policy %s: %w", policyID, err)
	}
	if !p.Enabled {
		return nil
	}

	// 2. Build a FRESH context with the policy's org so vault writes are
	// org-scoped and the bypass marker is NOT inherited.
	orgCtx := orgctx.With(context.Background(), orgctx.Org{ID: p.OrgID})

	// 3. Apply default generation length.
	gp := p.GenerationPolicy
	if gp.Length == 0 {
		gp.Length = s.defaultLen
	}

	// 3a. Check for an existing in-flight run; no-op if present.
	var inFlight bool
	if err := s.db.Pool.QueryRow(orgCtx, //orgscope:ignore in-flight guard scoped by policy_id (UUID); context is org-scoped via orgCtx so RLS on credential_rotations enforces org isolation
		`SELECT EXISTS(SELECT 1 FROM credential_rotations
		  WHERE policy_id=$1 AND status='rotating'
		    AND started_at > NOW() - INTERVAL '10 minutes')`, policyID,
	).Scan(&inFlight); err != nil {
		return fmt.Errorf("credentials: check in-flight: %w", err)
	}
	if inFlight {
		s.logger.Info("credentials: rotation already in flight, skipping", zap.String("policy_id", policyID))
		return nil
	}

	// 4. Insert ledger row at status='rotating'.
	runID := uuid.New().String()
	if _, err := s.db.Pool.Exec(orgCtx,
		`INSERT INTO credential_rotations
		   (id, org_id, policy_id, secret_id, connector_type, trigger, status, version_from, started_at)
		 VALUES ($1,$2,$3,$4,$5,$6,'rotating',$7,NOW())`,
		runID, p.OrgID, policyID, p.SecretID, p.ConnectorType, trigger, p.CurrentVersion,
	); err != nil {
		return fmt.Errorf("credentials: insert ledger: %w", err)
	}

	// 5. Resolve rotator.
	rot, ok := s.rotators[p.ConnectorType]
	if !ok {
		msg := fmt.Sprintf("unknown connector type: %s", p.ConnectorType)
		s.failRun(orgCtx, runID, policyID, 0, msg)
		return fmt.Errorf("credentials: %s", msg)
	}

	// 6. Execute the rotation state machine.
	status, promoted, candidateVer := runRotation(orgCtx, p.SecretID, rot, s.vault, gp, p.ConnectorConfig)

	// 6a. Best-effort retire of the superseded credential (minter connectors). Runs only
	// after a successful promote, so a failed verify/promote never deletes the live old key.
	if promoted {
		if c, ok := rot.(PostRotateCleaner); ok {
			if cerr := c.Cleanup(orgCtx, p.ConnectorConfig); cerr != nil {
				s.logger.Warn("credentials: post-rotate cleanup failed (new credential is live; old may linger)",
					zap.String("policy_id", policyID),
					zap.String("connector_type", p.ConnectorType),
					zap.Error(cerr))
			}
		}
	}

	// 7. Determine candidate version from vault (if promoted, it's current_version now).
	//    We capture candidate inside the rotation to update version_to.
	//    Re-read to get the new version_to (PromoteVersion updates current_version).
	var versionTo *int
	if promoted {
		var cv int
		//orgscope:ignore reading current_version to record version_to in the ledger; context already org-scoped via orgCtx
		if scanErr := s.db.Pool.QueryRow(orgCtx,
			`SELECT current_version FROM vault_secrets WHERE id = $1`, p.SecretID,
		).Scan(&cv); scanErr == nil {
			versionTo = &cv
		}
	}

	if status == "succeeded" {
		// Update ledger: succeeded.
		s.updateRunSucceeded(orgCtx, runID, policyID, versionTo, p.IntervalSeconds)
		s.recordRotationAudit(orgCtx, "credential.rotated", policyID, p.SecretID, p.CurrentVersion, versionTo, p.ConnectorType, trigger, "")
		// For generate_only: best-effort notification.
		if p.ConnectorType == "generate_only" {
			s.logger.Info("generate_only rotation complete: apply new value manually",
				zap.String("policy_id", policyID),
				zap.String("secret_id", p.SecretID))
		}
	} else {
		// Pass candidateVer so the ledger failure row records version_to when a
		// candidate was created before Apply/Verify failed (M-5). If the failure
		// was pre-candidate (generate / AddCandidate), candidateVer is 0 and
		// failRun leaves version_to NULL.
		s.failRun(orgCtx, runID, policyID, candidateVer, "rotation failed")
		s.recordRotationAudit(orgCtx, "credential.rotation_failed", policyID, p.SecretID, p.CurrentVersion, nil, p.ConnectorType, trigger, "rotation failed")
	}

	return nil
}

// failRun marks a ledger row as failed and updates the policy last_status.
func (s *Service) failRun(ctx context.Context, runID, policyID string, versionTo int, msg string) {
	var vTo *int
	if versionTo > 0 {
		vTo = &versionTo
	}
	if _, err := s.db.Pool.Exec(ctx, //orgscope:ignore failure-path update keyed by run UUID; row was inserted under org-scoped ctx
		`UPDATE credential_rotations
		 SET status='failed', error_message=$2, version_to=$3, completed_at=NOW()
		 WHERE id=$1`, runID, msg, vTo,
	); err != nil {
		s.logger.Warn("credentials: failed to update ledger on failure", zap.String("run_id", runID), zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx, //orgscope:ignore failure-path update keyed by policy UUID; RLS on credential_rotation_policies enforces org
		`UPDATE credential_rotation_policies SET last_status='failed', updated_at=NOW() WHERE id=$1`,
		policyID,
	); err != nil {
		s.logger.Warn("credentials: failed to update policy last_status on failure", zap.String("policy_id", policyID), zap.Error(err))
	}
}

// updateRunSucceeded marks the ledger row succeeded and advances the policy schedule.
func (s *Service) updateRunSucceeded(ctx context.Context, runID, policyID string, versionTo *int, intervalSeconds int) {
	if _, err := s.db.Pool.Exec(ctx, //orgscope:ignore success-path update keyed by run UUID; row was inserted under org-scoped ctx
		`UPDATE credential_rotations
		 SET status='succeeded', version_to=$2, completed_at=NOW()
		 WHERE id=$1`, runID, versionTo,
	); err != nil {
		s.logger.Warn("credentials: failed to update ledger on success", zap.String("run_id", runID), zap.Error(err))
	}
	if intervalSeconds > 0 {
		if _, err := s.db.Pool.Exec(ctx, //orgscope:ignore success-path update keyed by policy UUID; RLS on credential_rotation_policies enforces org
			`UPDATE credential_rotation_policies
			 SET last_run_at=NOW(), last_status='succeeded',
			     next_run_at=NOW() + $2 * interval '1 second',
			     updated_at=NOW()
			 WHERE id=$1`, policyID, intervalSeconds,
		); err != nil {
			s.logger.Warn("credentials: failed to advance policy schedule", zap.String("policy_id", policyID), zap.Error(err))
		}
	} else {
		if _, err := s.db.Pool.Exec(ctx, //orgscope:ignore success-path update keyed by policy UUID; RLS on credential_rotation_policies enforces org
			`UPDATE credential_rotation_policies
			 SET last_run_at=NOW(), last_status='succeeded', updated_at=NOW()
			 WHERE id=$1`, policyID,
		); err != nil {
			s.logger.Warn("credentials: failed to update policy last_run_at", zap.String("policy_id", policyID), zap.Error(err))
		}
	}
}

// RotationRun is the DTO for a single credential_rotations ledger row.
// Never includes the secret value.
type RotationRun struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	Trigger       string     `json:"trigger"`
	ConnectorType string     `json:"connector_type"`
	VersionFrom   *int       `json:"version_from,omitempty"`
	VersionTo     *int       `json:"version_to,omitempty"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// policyIDForSecret returns the rotation policy ID for a given secret, or
// ErrPolicyNotFound if no policy is configured for that secret (org-scoped
// via RLS / request context).
func (s *Service) policyIDForSecret(ctx context.Context, secretID string) (string, error) {
	var policyID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM credential_rotation_policies WHERE secret_id = $1 AND enabled = true LIMIT 1`, secretID,
	).Scan(&policyID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", ErrPolicyNotFound
		}
		return "", err
	}
	return policyID, nil
}

// LatestRotationRun returns the most recent ledger row for a secret, used to
// report status after an on-demand rotation.
func (s *Service) LatestRotationRun(ctx context.Context, secretID string) (*RotationRun, error) {
	row := s.db.Pool.QueryRow(ctx, //orgscope:ignore org enforced by FORCE RLS on credential_rotations; caller provides request context
		`SELECT id, COALESCE(status,''), COALESCE(trigger,''), COALESCE(connector_type,''),
		        version_from, version_to, COALESCE(error_message,''),
		        started_at, completed_at
		 FROM credential_rotations
		 WHERE secret_id = $1
		 ORDER BY started_at DESC
		 LIMIT 1`, secretID,
	)
	var r RotationRun
	if err := row.Scan(
		&r.ID, &r.Status, &r.Trigger, &r.ConnectorType,
		&r.VersionFrom, &r.VersionTo, &r.ErrorMessage,
		&r.StartedAt, &r.CompletedAt,
	); err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}
	return &r, nil
}

// RotationHistory returns up to 200 ledger rows for a secret, ordered
// newest-first (org-scoped via RLS). Never includes secret values.
func (s *Service) RotationHistory(ctx context.Context, secretID string) ([]RotationRun, error) {
	rows, err := s.db.Pool.Query(ctx, //orgscope:ignore org enforced by FORCE RLS on credential_rotations; caller provides request context
		`SELECT id, COALESCE(status,''), COALESCE(trigger,''), COALESCE(connector_type,''),
		        version_from, version_to, COALESCE(error_message,''),
		        started_at, completed_at
		 FROM credential_rotations
		 WHERE secret_id = $1
		 ORDER BY started_at DESC
		 LIMIT 200`, secretID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RotationRun
	for rows.Next() {
		var r RotationRun
		if err := rows.Scan(
			&r.ID, &r.Status, &r.Trigger, &r.ConnectorType,
			&r.VersionFrom, &r.VersionTo, &r.ErrorMessage,
			&r.StartedAt, &r.CompletedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// recordRotationAudit emits an audit event (never includes the secret value).
func (s *Service) recordRotationAudit(ctx context.Context, eventType, policyID, secretID string, versionFrom int, versionTo *int, connectorType, trigger, errMsg string) {
	if s.audit == nil {
		return
	}
	details := map[string]interface{}{
		"secret_id":    secretID,
		"policy_id":    policyID,
		"version_from": versionFrom,
		"connector":    connectorType,
		"trigger":      trigger,
	}
	if versionTo != nil {
		details["version_to"] = *versionTo
	}
	if errMsg != "" {
		details["error"] = errMsg
	}
	if err := s.audit.RecordEvent(ctx, "vault", eventType, "", "", "", details); err != nil {
		s.logger.Warn("credentials: audit event failed", zap.String("event", eventType), zap.Error(err))
	}
}

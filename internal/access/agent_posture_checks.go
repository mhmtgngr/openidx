package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access/posturevocab"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Device agent checks share posture_checks with the Ziti posture checks and
// share the console's /ziti/posture/checks endpoints, but nothing else: an
// agent check is never mirrored to the controller, carries no ziti_id, and
// can be written while no controller is connected at all. Which of the two a
// row is follows from its check_type (internal/access/posturevocab), so no
// column records it.

// errPostureCheckNotFound is a posture check id the caller's organization does
// not hold.
var errPostureCheckNotFound = errors.New("posture check not found")

// errNotAZitiCheck guards the controller: only a Ziti posture check type is
// ever written to /edge/management/v1/posture-checks.
var errNotAZitiCheck = errors.New("not a Ziti posture check type")

// defaultPostureOrgID is the organization a posture check falls back to when
// the request carries none, as the controller-mirroring path has always done.
const defaultPostureOrgID = "00000000-0000-0000-0000-000000000010"

func postureOrgID(ctx context.Context) string {
	if org, err := orgctx.From(ctx); err == nil {
		return org.ID
	}
	return defaultPostureOrgID
}

// postureRowKind is the vocabulary a stored row is handled by. A row whose
// type is in neither vocabulary was created through the controller path (it
// is the only path that ever accepted one), so it stays on that path.
func postureRowKind(checkType string) posturevocab.Kind {
	if posturevocab.KindOf(checkType) == posturevocab.KindAgent {
		return posturevocab.KindAgent
	}
	return posturevocab.KindZiti
}

// postureVocabError answers a refused posture check with its stable code and
// the field it concerns.
func postureVocabError(c *gin.Context, err *posturevocab.Error) {
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Message, "code": err.Code, "field": err.Field})
}

// unknownPostureCheckType is the refusal for a check_type in neither
// vocabulary. The controller would have refused it too, as a 500.
func unknownPostureCheckType(c *gin.Context, checkType string) {
	postureVocabError(c, &posturevocab.Error{
		Code:  posturevocab.CodeUnknownCheckType,
		Field: "check_type",
		Message: fmt.Sprintf("check_type %q is neither a device agent check nor a Ziti posture check; "+
			"GET /api/v1/access/ziti/posture/check-types lists both", checkType),
	})
}

// validateAgentPostureCheck checks a row against the agent vocabulary.
func validateAgentPostureCheck(check *PostureCheck) *posturevocab.Error {
	return posturevocab.ValidateAgentCheck(check.Name, check.CheckType, check.Parameters, check.Severity, check.Platforms)
}

// postureCheckTypeByID returns the stored check_type of the organization's
// posture check id.
func postureCheckTypeByID(ctx context.Context, db *database.PostgresDB, id string) (string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return "", errPostureCheckNotFound
	}
	var checkType string
	err := db.Pool.QueryRow(ctx,
		`SELECT check_type FROM posture_checks WHERE id = $1 AND org_id = $2`,
		id, postureOrgID(ctx)).Scan(&checkType)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errPostureCheckNotFound
	}
	if err != nil {
		return "", fmt.Errorf("look up posture check: %w", err)
	}
	return checkType, nil
}

// postureJSON marshals a row's parameters and platforms. Platforms is stored
// NULL when empty, which GET /agent/config reads as "every platform".
func postureJSON(check *PostureCheck) (params, platforms []byte, err error) {
	if check.Parameters == nil {
		check.Parameters = map[string]interface{}{}
	}
	if params, err = json.Marshal(check.Parameters); err != nil {
		return nil, nil, fmt.Errorf("marshal posture check parameters: %w", err)
	}
	if len(check.Platforms) > 0 {
		if platforms, err = json.Marshal(check.Platforms); err != nil {
			return nil, nil, fmt.Errorf("marshal posture check platforms: %w", err)
		}
	}
	return params, platforms, nil
}

// createAgentPostureCheck stores a validated agent check. The id is always
// minted here: a caller-chosen one could only collide with a row it cannot
// see.
func createAgentPostureCheck(ctx context.Context, db *database.PostgresDB, check *PostureCheck) error {
	paramsJSON, platformsJSON, err := postureJSON(check)
	if err != nil {
		return err
	}
	check.ID = uuid.New().String()
	check.ZitiID = ""
	check.Kind = string(posturevocab.KindAgent)
	now := time.Now().UTC()
	check.CreatedAt, check.UpdatedAt = now, now
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO posture_checks (id, ziti_id, name, check_type, parameters, enabled, severity,
		                             remediation_hint, platforms, created_at, updated_at, org_id)
		 VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		check.ID, check.Name, check.CheckType, paramsJSON, check.Enabled, check.Severity,
		check.RemediationHint, platformsJSON, now, now, postureOrgID(ctx))
	if err != nil {
		return fmt.Errorf("insert agent posture check: %w", err)
	}
	return nil
}

// updateAgentPostureCheck replaces a validated agent check. The row must
// still be an agent check: the handler has already refused a change of kind,
// and the predicate keeps a concurrent edit from turning that check into a
// write over a Ziti row whose controller object would be left behind.
func updateAgentPostureCheck(ctx context.Context, db *database.PostgresDB, id string, check *PostureCheck) error {
	paramsJSON, platformsJSON, err := postureJSON(check)
	if err != nil {
		return err
	}
	check.ID = id
	check.ZitiID = ""
	check.Kind = string(posturevocab.KindAgent)
	check.UpdatedAt = time.Now().UTC()
	err = db.Pool.QueryRow(ctx,
		`UPDATE posture_checks
		    SET name = $1, check_type = $2, parameters = $3, enabled = $4, severity = $5,
		        remediation_hint = $6, platforms = $7, updated_at = $8
		  WHERE id = $9 AND org_id = $10 AND ziti_id IS NULL AND check_type = ANY($11)
		 RETURNING created_at`,
		check.Name, check.CheckType, paramsJSON, check.Enabled, check.Severity,
		check.RemediationHint, platformsJSON, check.UpdatedAt, id, postureOrgID(ctx),
		agentCheckTypes()).Scan(&check.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return errPostureCheckNotFound
	}
	if err != nil {
		return fmt.Errorf("update agent posture check: %w", err)
	}
	return nil
}

// deleteAgentPostureCheck removes an agent check. There is no controller
// object to remove with it.
func deleteAgentPostureCheck(ctx context.Context, db *database.PostgresDB, id string) error {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM posture_checks
		  WHERE id = $1 AND org_id = $2 AND ziti_id IS NULL AND check_type = ANY($3)`,
		id, postureOrgID(ctx), agentCheckTypes())
	if err != nil {
		return fmt.Errorf("delete agent posture check: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errPostureCheckNotFound
	}
	return nil
}

func agentCheckTypes() []string {
	checks := posturevocab.AgentChecks()
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.Type
	}
	return out
}

// listPostureChecks returns the organization's posture checks of one kind,
// or of both when kind is empty, newest first. Each carries its kind.
func listPostureChecks(ctx context.Context, db *database.PostgresDB, logger *zap.Logger, kind posturevocab.Kind) ([]PostureCheck, error) {
	// ziti_id is NULL on every agent check and remediation_hint and severity
	// on rows written by anything but this service, and a NULL scanned into a
	// string fails the whole listing.
	rows, err := db.Pool.Query(ctx,
		`SELECT id, COALESCE(ziti_id, ''), name, check_type, parameters, enabled,
		        COALESCE(severity, ''), COALESCE(remediation_hint, ''), platforms, created_at, updated_at
		   FROM posture_checks WHERE org_id = $1 ORDER BY created_at DESC`, postureOrgID(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to query posture checks: %w", err)
	}
	defer rows.Close()

	checks := []PostureCheck{}
	for rows.Next() {
		var c PostureCheck
		var paramsJSON, platformsJSON []byte
		if err := rows.Scan(&c.ID, &c.ZitiID, &c.Name, &c.CheckType, &paramsJSON,
			&c.Enabled, &c.Severity, &c.RemediationHint, &platformsJSON, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan posture check row: %w", err)
		}
		rowKind := postureRowKind(c.CheckType)
		if kind != "" && rowKind != kind {
			continue
		}
		c.Kind = string(rowKind)
		if paramsJSON != nil {
			if err := json.Unmarshal(paramsJSON, &c.Parameters); err != nil {
				logger.Warn("Failed to unmarshal posture check parameters",
					logsafe.String("check_id", c.ID), zap.Error(err))
			}
		}
		if c.Parameters == nil {
			c.Parameters = make(map[string]interface{})
		}
		if platformsJSON != nil {
			if err := json.Unmarshal(platformsJSON, &c.Platforms); err != nil {
				logger.Warn("Failed to unmarshal posture check platforms",
					logsafe.String("check_id", c.ID), zap.Error(err))
			}
		}
		checks = append(checks, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read posture checks: %w", err)
	}
	return checks, nil
}

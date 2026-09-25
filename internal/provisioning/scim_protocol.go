package provisioning

// The parts of RFC 7644 every SCIM endpoint shares: the media type, the error
// envelope, where a created resource lives, and how a PATCH names what it
// changes. They live in one place so the handlers cannot drift apart on them,
// which is how the error bodies came to be half SCIM envelopes and half
// {"error": "..."} objects no SCIM client parses.

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// scimMediaType is the media type RFC 7644 §3.1 defines for SCIM messages.
const scimMediaType = "application/scim+json"

// SCIM error types (RFC 7644 §3.12) this server answers with.
const (
	scimTypeInvalidFilter = "invalidFilter"
	scimTypeInvalidPath   = "invalidPath"
	scimTypeInvalidValue  = "invalidValue"
	scimTypeInvalidSyntax = "invalidSyntax"
	scimTypeNoTarget      = "noTarget"
	scimTypeUniqueness    = "uniqueness"
)

// scimContentType answers every SCIM endpoint with application/scim+json.
// gin writes its own JSON Content-Type only when none is set, so setting it
// before the handler runs is enough.
func scimContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", scimMediaType+"; charset=utf-8")
		c.Next()
	}
}

// scimError writes the RFC 7644 §3.12 error envelope.
func scimError(c *gin.Context, status int, scimType, detail string) {
	c.JSON(status, SCIMError{
		Schemas:  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

// scimNoContent answers 204 with no body, as DELETE must (RFC 7644 §3.6).
func scimNoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
	c.Writer.WriteHeaderNow()
}

// scimResourceLocation is the URI of a resource, for the Location header of a
// create (RFC 7644 §3.3) and for meta.location (RFC 7643 §3.1).
func scimResourceLocation(c *gin.Context, endpoint, id string) string {
	scheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}
	return fmt.Sprintf("%s://%s/scim/v2/%s/%s", scheme, host, endpoint, id)
}

// isUniqueViolation reports a Postgres unique-constraint violation, which is
// SCIM's 409 uniqueness (RFC 7644 §3.3), not a server error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isNotFound reports a row that is not there.
func isNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// scimOp normalizes a PATCH op. Attribute names and keywords in SCIM are
// case-insensitive, and Microsoft Entra sends "Replace" and "Add".
func scimOp(op string) (string, error) {
	switch o := strings.ToLower(strings.TrimSpace(op)); o {
	case "add", "replace", "remove":
		return o, nil
	default:
		return "", fmt.Errorf("invalid SCIM patch operation: %s", op)
	}
}

// scimBool reads a boolean PATCH value. Entra sends active as the STRING
// "False"; a value that is neither is refused rather than ignored.
func scimBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// scimString reads a string PATCH value.
func scimString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// memberFilterPath matches the path Okta and others use to remove one member:
// members[value eq "<id>"].
var memberFilterPath = regexp.MustCompile(`(?i)^\s*members\s*\[\s*value\s+eq\s+"([^"]+)"\s*\]\s*$`)

// patchError is a PATCH that cannot be applied, with its SCIM error type.
type patchError struct {
	scimType string
	msg      string
}

func (e *patchError) Error() string { return e.msg }

func invalidPath(path string) error {
	return &patchError{scimType: scimTypeInvalidPath, msg: fmt.Sprintf("the path %q is not an attribute this server can modify", path)}
}

func invalidValue(format string, args ...interface{}) error {
	return &patchError{scimType: scimTypeInvalidValue, msg: fmt.Sprintf(format, args...)}
}

// writePatchError maps a PATCH failure to its SCIM error.
func writePatchError(c *gin.Context, err error) {
	var pe *patchError
	if errors.As(err, &pe) {
		scimError(c, http.StatusBadRequest, pe.scimType, pe.msg)
		return
	}
	scimError(c, http.StatusBadRequest, scimTypeInvalidSyntax, err.Error())
}
